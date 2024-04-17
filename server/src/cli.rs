use {clap::Parser, std::net::SocketAddr};

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct ServerCliParameters {
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    pub stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::1]:4433")]
    pub listen: SocketAddr,
    /// Maximum number of concurrent connections to allow
    #[clap(long = "connection-limit")]
    pub connection_limit: Option<usize>,
}

pub fn build_cli_parameters() -> ServerCliParameters {
    ServerCliParameters::parse()
}
