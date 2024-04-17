pub mod cli;
pub mod transaction_generator;

use {
    quinn::{ConnectError, ConnectionError, WriteError},
    rustls,
    std::{io, sync::Arc, time::Duration},
    thiserror::Error,
};

pub const QUIC_MAX_TIMEOUT: Duration = Duration::from_secs(2);
// TODO(klykov): it think the ratio between these consts should be higher
pub const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(1);

// called QuicError in agave
#[derive(Error, Debug)]
pub enum QuicClientError {
    #[error(transparent)]
    WriteError(#[from] WriteError),
    #[error(transparent)]
    ConnectionError(#[from] ConnectionError),
    #[error(transparent)]
    ConnectError(#[from] ConnectError),

    #[error(transparent)]
    EndpointError(#[from] io::Error),
}

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
pub struct SkipServerVerification;

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
