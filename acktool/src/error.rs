#[cfg(feature = "use_quinn_10")]
use quinn_10::{ConnectError, ConnectionError, WriteError};
#[cfg(feature = "use_quinn_master")]
use quinn_master::{ConnectError, ConnectionError, WriteError};
use {std::io, thiserror::Error};

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
