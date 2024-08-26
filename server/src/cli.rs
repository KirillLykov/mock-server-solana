use {clap::Parser, std::net::SocketAddr};

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct ServerCliParameters {
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    pub stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "127.0.0.1:4433")]
    pub listen: SocketAddr,
    /// Maximum number of concurrent connections to allow
    #[clap(long = "connection-limit")]
    pub connection_limit: Option<usize>,
    /// max concurrent streams
    /// QUIC_MAX_STAKED_CONCURRENT_STREAMS = 512
    #[clap(long = "max_concurrent_streams", default_value = "512")]
    pub max_concurrent_streams: u32,

    // PACKET_DATA_SIZE = 1232
    #[clap(long = "stream-receive-window-size", default_value = "1232")]
    pub stream_receive_window_size: u32,

    #[clap(long = "receive-window-size", default_value = "12320")]
    pub receive_window_size: u32,
}

pub fn build_cli_parameters() -> ServerCliParameters {
    ServerCliParameters::parse()
}
