//! This example demonstrates quic server for handling incoming transactions.
//!
//! Checkout the `README.md` for guidance.

use {
    pem::Pem,
    quinn::{Chunk, Endpoint, IdleTimeout, ServerConfig},
    server::{
        cli::{build_cli_parameters, ServerCliParameters},
        packet_accumulator::{PacketAccumulator, PacketChunk},
        QuicServerError, SkipClientVerification, QUIC_MAX_TIMEOUT,
        QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS, TIME_TO_HANDLE_ONE_TX,
    },
    //solana_logger,
    solana_sdk::{
        packet::{Meta, PACKET_DATA_SIZE},
        signature::Keypair,
    },
    solana_streamer::{
        nonblocking::quic::ALPN_TPU_PROTOCOL_ID, tls_certificates::new_self_signed_tls_certificate,
    },
    std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        process::exit,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tokio::{signal, time::sleep},
    tokio_util::sync::CancellationToken,
    tracing::{debug, error, info, info_span, trace, warn},
};

/// Returns default server configuration along with its PEM certificate chain.
#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
                                              // called configure_server in agave
fn create_server_config(
    identity_keypair: &Keypair,
) -> Result<(ServerConfig, String), QuicServerError> {
    let gossip_host = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let (cert, priv_key) = new_self_signed_tls_certificate(identity_keypair, gossip_host)
        .expect("Should be able to create certificate.");
    let cert_chain_pem_parts = vec![Pem {
        tag: "CERTIFICATE".to_string(),
        contents: cert.0.clone(),
    }];
    let cert_chain_pem = pem::encode_many(&cert_chain_pem_parts);

    let mut server_tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(SkipClientVerification::new())
        .with_single_cert(vec![cert], priv_key)?;
    server_tls_config.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(server_tls_config));
    // Looks like it was removed from quinn
    //server_config.use_retry(true);
    let config = Arc::get_mut(&mut server_config.transport).unwrap();

    // QUIC_MAX_CONCURRENT_STREAMS doubled, which was found to improve reliability
    const MAX_CONCURRENT_UNI_STREAMS: u32 =
        (QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS.saturating_mul(2)) as u32;
    config.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    config.stream_receive_window((PACKET_DATA_SIZE as u32).into());
    config.receive_window(
        (PACKET_DATA_SIZE as u32)
            .saturating_mul(MAX_CONCURRENT_UNI_STREAMS)
            .into(),
    );
    let timeout = IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap();
    config.max_idle_timeout(Some(timeout));

    // disable bidi & datagrams
    const MAX_CONCURRENT_BIDI_STREAMS: u32 = 0;
    config.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    config.datagram_receive_buffer_size(None);

    Ok((server_config, cert_chain_pem))
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
fn create_server_endpoint(
    bind_addr: SocketAddr,
    server_config: ServerConfig,
) -> Result<Endpoint, QuicServerError> {
    //TODO(klykov): this is done in spawn_server in streamer/src/nonblocking/quic.rs
    // we use new instead of server for no reason there
    Ok(Endpoint::server(server_config, bind_addr)?)
}

fn main() {
    //solana_logger::setup();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let parameters = build_cli_parameters();
    let code = {
        if let Err(e) = run(parameters) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[derive(Debug, Default)]
struct Stats {
    num_received_streams: AtomicU64,
    num_errored_streams: AtomicU64,
    num_accepted_connections: AtomicU64,
    num_refused_connections: AtomicU64,
    num_connection_errors: AtomicU64,
    num_finished_streams: AtomicU64,
}

#[tokio::main]
async fn run(options: ServerCliParameters) -> Result<(), QuicServerError> {
    let token = CancellationToken::new();
    let stats = Arc::new(Stats::default());
    // Spawn a task that listens for SIGINT (Ctrl+C)
    let handler = tokio::spawn({
        let token = token.clone();
        async move {
            if signal::ctrl_c().await.is_ok() {
                println!("Received Ctrl+C, shutting down...");
                token.cancel();
            }
        }
    });

    let identity = Keypair::new();
    let (server_config, _) = create_server_config(&identity)?;
    let endpoint = create_server_endpoint(options.listen, server_config)?;
    info!("listening on {}", endpoint.local_addr()?);

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                println!("{stats:?}");
                break;
            }
            conn = endpoint.accept() => {
                let Some(conn) = conn else {
                    continue;
                };
                if options
                    .connection_limit
                    .map_or(false, |n| endpoint.open_connections() >= n)
                {
                    warn!("refusing due to open connection limit");
                    stats
                        .num_refused_connections
                        .fetch_add(1, Ordering::Relaxed);
                    conn.refuse();
                } else if options.stateless_retry && !conn.remote_address_validated() {
                    warn!("requiring connection to validate its address");
                    conn.retry().unwrap(); // TODO(klykov): what does it mean?
                } else {
                    info!("accepting connection");
                    stats
                        .num_accepted_connections
                        .fetch_add(1, Ordering::Relaxed);
                    let fut = handle_connection(conn, stats.clone(), token.clone());
                    tokio::spawn(async move {
                        if let Err(e) = fut.await {
                            error!("connection failed: {reason}", reason = e.to_string())
                        }
                    });
                }
            }
        }
    }

    let _ = handler.await;
    Ok(())
}

async fn handle_connection(
    conn: quinn::Incoming,
    stats: Arc<Stats>,
    token: CancellationToken,
) -> Result<(), QuicServerError> {
    let connection = conn.await?;
    async {
        let span = info_span!(
            "connection",
            remote = %connection.remote_address(),
        );
        let _enter = span.enter();
        info!("Connection have been established.");

        // Each stream initiated by the client constitutes a new request.
        loop {
            if token.is_cancelled() {
                warn!("JJJJJJ");
                return Ok(());
            }
            let stream = connection.accept_uni().await;
            let mut stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    stats.num_connection_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
                Ok(s) => s,
            };
            // do the same as in the agave
            let mut packet_accum: Option<PacketAccumulator> = None;
            let stats = stats.clone();
            tokio::spawn({
                let token = token.clone();
                async move {
                    loop {
                        if token.is_cancelled() {
                            warn!("@@@");
                            break;
                        }
                        let Ok(chunk) = stream.read_chunk(PACKET_DATA_SIZE, true).await else {
                            debug!("Stream failed");
                            stats.num_finished_streams.fetch_add(1, Ordering::Relaxed);
                            break; // not sure if the right thing to do
                        };
                        let res = handle_stream_chunk_accumulation(chunk, &mut packet_accum).await;
                        if let Err(e) = res {
                            error!("failed: {reason}", reason = e.to_string());
                            stats.num_errored_streams.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        if res.unwrap() {
                            trace!("Finished stream.");
                            break;
                        }

                        stats.num_received_streams.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
        }
    }
    .await?;
    Ok(())
}

// returns if stream was closed
async fn handle_stream_chunk_accumulation(
    chunk: Option<Chunk>,
    packet_accum: &mut Option<PacketAccumulator>,
) -> Result<bool, QuicServerError> {
    let Some(chunk) = chunk else {
        //it means that the last chunk has been received, we put all the chunks accumulated to some channel
        if let Some(accum) = packet_accum.take() {
            handle_packet_bytes(accum).await;
        }
        return Ok(true);
    };
    let chunk_len = chunk.bytes.len() as u64;
    debug!("got chunk of len: {chunk_len}");
    // This code is copied from nonblocking/quic.rs. Interesting to know if these checks are sufficient.
    // shouldn't happen, but sanity check the size and offsets
    if chunk.offset > PACKET_DATA_SIZE as u64 || chunk_len > PACKET_DATA_SIZE as u64 {
        debug!("failed validation with chunk_len={chunk_len} > {PACKET_DATA_SIZE}");
        return Err(QuicServerError::FailedReadChunk);
    }
    let Some(end_of_chunk) = chunk.offset.checked_add(chunk_len) else {
        debug!("failed validation on offset overflow");
        return Err(QuicServerError::FailedReadChunk);
    };
    if end_of_chunk > PACKET_DATA_SIZE as u64 {
        debug!("failed validation on end_of_chunk={end_of_chunk} > {PACKET_DATA_SIZE}");
        return Err(QuicServerError::FailedReadChunk);
    }

    // chunk looks valid
    // accumulate chunks into packet but what's the reason
    // if we stick with tx to be limited by PACKET_DATA_SIZE
    if packet_accum.is_none() {
        let meta = Meta::default();
        //meta.set_socket_addr(remote_addr); don't care much in the context of this app
        *packet_accum = Some(PacketAccumulator {
            meta,
            chunks: Vec::new(),
            start_time: Instant::now(),
        });
    }
    if let Some(accum) = packet_accum.as_mut() {
        let offset = chunk.offset;
        let Some(end_of_chunk) = (chunk.offset as usize).checked_add(chunk.bytes.len()) else {
            debug!("failed validation on offset overflow when accumulating chunks");
            return Err(QuicServerError::FailedReadChunk);
        };
        accum.chunks.push(PacketChunk {
            bytes: chunk.bytes,
            offset: offset as usize,
            end_of_chunk,
        });

        accum.meta.size = std::cmp::max(accum.meta.size, end_of_chunk);
    }
    Ok(false)
}

async fn handle_packet_bytes(accum: PacketAccumulator) {
    debug!(
        "Received data size {}",
        accum.chunks.len() * PACKET_DATA_SIZE
    );
    tokio::time::sleep(TIME_TO_HANDLE_ONE_TX).await;
}
