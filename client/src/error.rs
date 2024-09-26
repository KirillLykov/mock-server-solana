#[cfg(feature = "use_quinn_11")]
use quinn_11 as quinn;

#[cfg(feature = "use_quinn_master")]
use quinn_master as quinn;

#[cfg(any(feature = "use_quinn_11", feature = "use_quinn_master"))]
use quinn::{ConnectError, ConnectionError, WriteError};

use {std::io, thiserror::Error};

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

    #[error("Failed to read keypair file")]
    KeypairReadFailure,
}
