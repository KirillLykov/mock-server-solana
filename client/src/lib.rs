pub mod cli;
pub mod transaction_generator;

use {
    quinn::{ConnectError, ConnectionError, WriteError},
    std::{io, time::Duration},
    thiserror::Error,
};

pub const QUIC_MAX_TIMEOUT: Duration = Duration::from_secs(2);
pub const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(1);

#[derive(Error, Debug)]
pub enum QuicError {
    #[error(transparent)]
    WriteError(#[from] WriteError),
    #[error(transparent)]
    ConnectionError(#[from] ConnectionError),
    #[error(transparent)]
    ConnectError(#[from] ConnectError),

    #[error(transparent)]
    EndpointError(#[from] io::Error),
}
