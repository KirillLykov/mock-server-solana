use {clap::Parser, std::net::SocketAddr};

#[derive(Parser, Debug)]
#[clap(name = "client")]
pub struct ClientCliParameters {
    #[clap(long, help = "target")]
    pub target: SocketAddr,

    /// Override hostname used for certificate verification
    #[clap(long, help = "host")]
    pub host: Option<String>,

    /// Address to bind on, default will listen on all available interfaces, 0 that
    ///  OS will choose the port.
    #[clap(long, help = "bind", default_value = "0.0.0.0:0")]
    pub bind: SocketAddr,
}

pub fn build_cli_parameters() -> ClientCliParameters {
    ClientCliParameters::parse()
}
