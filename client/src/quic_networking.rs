use {
    crate::error::QuicClientError,
    quinn::{
        congestion, crypto::rustls::QuicClientConfig, AckFrequencyConfig, ClientConfig, Connection,
        Endpoint, IdleTimeout, TransportConfig, VarInt,
    },
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified},
        pki_types::{CertificateDer, ServerName, UnixTime},
        SignatureScheme,
    },
    solana_sdk::signature::Keypair,
    solana_streamer::{
        nonblocking::quic::ALPN_TPU_PROTOCOL_ID,
        // on master, renamed to tls_certificates::new_dummy_x509_certificate,
        tls_certificates::new_self_signed_tls_certificate,
    },
    std::{
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    },
};

const QUIC_MAX_TIMEOUT: Duration = Duration::from_secs(20);
// TODO(klykov): it think the ratio between these consts should be higher
const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(1);

// Implementation of `ServerCertVerifier` that verifies everything as
// trustworthy.
#[derive(Debug)]
pub struct SkipClientVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipClientVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipClientVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
// copy-pasted from agave

pub fn create_client_config() -> ClientConfig {
    // let mut roots = rustls::RootCertStore::empty();
    // roots
    //     .add(CertificateDer::from(fs::read("cert.der").unwrap()))
    //     .unwrap();
    // let mut crypto = rustls::ClientConfig::builder()
    //     .with_root_certificates(roots)
    //     .with_no_client_auth();

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    crypto.enable_early_data = true;
    // crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    //    crypto.alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID.to_vec()];

    let mut config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    let mut transport_config = TransportConfig::default();

    let timeout = IdleTimeout::try_from(QUIC_MAX_TIMEOUT).unwrap();
    transport_config.max_idle_timeout(Some(timeout));
    transport_config.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    transport_config.send_window(1024 * 1024 * 500);
    transport_config.enable_segmentation_offload(true);
    transport_config.time_threshold(500f32);
    // transport_config.packet_threshold(1000000);
    // transport_config.packet_threshold(1000000);
    transport_config.packet_threshold(u32::MAX);
    // transport_config.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
    transport_config.congestion_controller_factory(Arc::new(congestion::NewRenoConfig::default()));
    let mut ack = AckFrequencyConfig::default();
    ack.ack_eliciting_threshold(VarInt::from_u32(200));
    ack.reordering_threshold(VarInt::from_u32(199));
    // transport_config.ack_frequency_config(Some(ack));
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
    //never do this
    //send_stream.finish().await?;
    Ok(())
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
