use {
    quinn::{ConnectError, ConnectionError, WriteError},
    std::io,
    thiserror::Error,
};

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
