pub mod cli;
pub mod packet_accumulator;

use {
    quinn::ConnectionError,
    rustls::DistinguishedName,
    std::{
        io,
        sync::Arc,
        time::{Duration, SystemTime},
    },
    thiserror::Error,
};
// this is local constant
pub const TIME_TO_HANDLE_ONE_TX: Duration = Duration::from_millis(10);

// Empirically found max number of concurrent streams
// that seems to maximize TPS on GCE (higher values don't seem to
// give significant improvement or seem to impact stability)
pub const QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS: usize = 128;

pub const QUIC_MAX_STAKED_CONCURRENT_STREAMS: usize = 512;
// the same is in the client crate
pub const QUIC_MAX_TIMEOUT: Duration = Duration::from_secs(20);

/*#[derive(Error, Debug)]
pub struct FailedReadChunk;

impl fmt::Display for FailedReadChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Failed to read chunk")
    }
}*/

#[derive(Error, Debug)]
pub enum QuicServerError {
    #[error("Endpoint creation failed: {0}")]
    EndpointFailed(io::Error),
    #[error("TLS error: {0}")]
    TlsError(#[from] rustls::Error),
    #[error(transparent)]
    ConnectionError(#[from] ConnectionError),
    #[error("Failed to read chunk")]
    FailedReadChunk,
    #[error(transparent)]
    EndpointError(#[from] io::Error),
}
