use {
    clap::{crate_description, crate_name, crate_version, Parser},
    std::net::SocketAddr,
};

#[derive(Parser, Debug)]
#[clap(name = crate_name!(),
    version = crate_version!(),
    about = crate_description!(),
    rename_all = "kebab-case"
)]
pub struct ClientCliParameters {
    #[clap(long, help = "target")]
    pub target: SocketAddr,

    /// Address to bind on, default will listen on all available interfaces, 0 that
    /// OS will choose the port.
    #[clap(long, help = "bind", default_value = "0.0.0.0:0")]
    pub bind: SocketAddr,
}

pub fn build_cli_parameters() -> ClientCliParameters {
    ClientCliParameters::parse()
}
