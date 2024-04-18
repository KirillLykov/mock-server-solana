use {
    crate::error::QuicClientError,
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
        time::Duration,
    },
};

const QUIC_MAX_TIMEOUT: Duration = Duration::from_secs(2);
// TODO(klykov): it think the ratio between these consts should be higher
const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(1);

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
struct SkipServerVerification;

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
// copy-pasted from agave
pub struct QuicClientCertificate {
    pub certificate: rustls::Certificate,
    pub key: rustls::PrivateKey,
}

impl Default for QuicClientCertificate {
    fn default() -> Self {
        QuicClientCertificate::new(&Keypair::new())
    }
}

impl QuicClientCertificate {
    pub fn new(keypair: &Keypair) -> Self {
        let (certificate, key) =
            new_self_signed_tls_certificate(keypair, IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .expect("Creating TLS certificate should not fail.");
        Self { certificate, key }
    }
}

pub fn create_client_config(client_certificate: Arc<QuicClientCertificate>) -> ClientConfig {
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

pub fn create_client_endpoint(
    bind_addr: SocketAddr,
    client_config: ClientConfig,
) -> Result<Endpoint, QuicClientError> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// was called _send_buffer_using_conn
pub async fn send_data_over_stream(
    connection: &Connection,
    data: &[u8],
) -> Result<(), QuicClientError> {
    let mut send_stream = connection.open_uni().await?;

    send_stream.write_all(data).await?;
    send_stream.finish().await?;
    Ok(())
}
