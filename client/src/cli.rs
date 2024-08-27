use {
    clap::{crate_description, crate_name, crate_version, Parser},
    std::{net::SocketAddr, path::PathBuf, time::Duration},
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

    // Cannot use value_parser to read keypair file because Keypair is not Clone.
    #[clap(long, help = "validator identity for staked connection")]
    pub staked_identity_file: Option<PathBuf>,

    /// Address to bind on, default will listen on all available interfaces, 0 that
    /// OS will choose the port.
    #[clap(long, help = "bind", default_value = "0.0.0.0:0")]
    pub bind: SocketAddr,

    #[clap(
        long,
        value_parser = parse_duration,
        help = "If specified, limits the benchmark execution to the specified duration."
    )]
    pub duration: Option<Duration>,

    #[clap(long, help = "Size of transaction in bytes.", default_value = "200")]
    pub tx_size: usize,
}

fn parse_duration(s: &str) -> Result<Duration, &'static str> {
    s.parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| "failed to parse duration")
}

pub fn build_cli_parameters() -> ClientCliParameters {
    ClientCliParameters::parse()
}
