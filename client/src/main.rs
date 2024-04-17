//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use {
    client::{
        cli::{build_cli_parameters, ClientCliParameters},
        transaction_generator::generate_dummy_data,
        QuicClientError, SkipServerVerification, QUIC_KEEP_ALIVE, QUIC_MAX_TIMEOUT,
    },
    futures::future::join_all,
    quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig},
    solana_sdk::signature::Keypair,
    solana_streamer::{
        nonblocking::quic::ALPN_TPU_PROTOCOL_ID,
        // on master, renamed to tls_certificates::new_dummy_x509_certificate,
        tls_certificates::new_self_signed_tls_certificate,
    },
    std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Instant,
    },
    tracing::{debug, info},
};

// copy-pasted from agave
pub struct QuicClientCertificate {
    pub certificate: rustls::Certificate,
    pub key: rustls::PrivateKey,
}

impl Default for QuicClientCertificate {
    fn default() -> Self {
        let (certificate, key) =
            new_self_signed_tls_certificate(&Keypair::new(), IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .expect("Creating TLS certificate should not fail.");
        Self { certificate, key }
    }
}

fn create_client_config(client_certificate: Arc<QuicClientCertificate>) -> ClientConfig {
    // taken from QuicLazyInitializedEndpoint::create_endpoint
    let mut crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_client_auth_cert(
            vec![client_certificate.certificate.clone()],
            client_certificate.key.clone(),
        )
        .expect("Failed to set QUIC client certificates");
    crypto.enable_early_data = true;
    crypto.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];

    let mut config = ClientConfig::new(Arc::new(crypto));
    let mut transport_config = TransportConfig::default();

    let timeout = IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap();
    transport_config.max_idle_timeout(Some(timeout));
    transport_config.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    config.transport_config(Arc::new(transport_config));

    config
}

fn create_client_endpoint(
    bind_addr: SocketAddr,
    client_config: ClientConfig,
) -> Result<Endpoint, QuicClientError> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// was called _send_buffer_using_conn
async fn send_data_over_stream(
    connection: &Connection,
    data: &[u8],
) -> Result<(), QuicClientError> {
    let mut send_stream = connection.open_uni().await?;

    send_stream.write_all(data).await?;
    send_stream.finish().await?;
    Ok(())
}

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = build_cli_parameters();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(parameters: ClientCliParameters) -> Result<(), QuicClientError> {
    let client_certificate = Arc::new(QuicClientCertificate::default());
    let client_config = create_client_config(client_certificate);
    let endpoint = create_client_endpoint(parameters.bind, client_config)
        .expect("Endpoint creation should not fail.");

    let start = Instant::now();

    info!("connecting to {}", parameters.target);
    let connection = endpoint.connect(parameters.target, "connect")?.await?;
    info!("connected at {:?}", start.elapsed());

    let num_tx_batches = 8;
    let num_streams_per_connection = 256;
    for _ in 0..num_tx_batches {
        let transactions = generate_dummy_data(num_streams_per_connection, false);
        // using join_all will run concurrently but not in parallel.
        let futures = transactions.into_iter().map(|data| {
            let conn = connection.clone();
            async move { send_data_over_stream(&conn, &data).await }
        });
        let results = join_all(futures).await;
        for result in results {
            debug!("{:?}", result);
        }
    }

    let connection_stats = connection.stats();
    info!("Connection stats: {:?}", connection_stats);
    connection.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
}
