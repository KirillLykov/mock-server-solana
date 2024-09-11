//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.
#[cfg(all(feature = "use_quinn_master", feature = "use_quinn_10"))]
compile_error!(
    "Features 'use_quinn_master' and 'use_quinn_10' are mutually exclusive.\
Try `cargo build --no-default-features --features ...` instead."
);

use {
    acktool::{
        cli::{build_cli_parameters, ClientCliParameters},
        error::QuicClientError,
        quic_networking::{
            create_client_config, create_client_endpoint, send_data_over_stream,
            QuicClientCertificate,
        },
    },
    rand::random,
    std::{sync::Arc, time::Instant},
    tracing::{debug, info},
};

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let opt = build_cli_parameters();
    let code = {
        if let Err(e) = run(opt) {
            eprintln!("ERROR: {e}");
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(parameters: ClientCliParameters) -> Result<(), QuicClientError> {
    let client_certificate = Arc::new(QuicClientCertificate::default());
    let client_config = create_client_config(client_certificate);
    let endpoint = create_client_endpoint(parameters.bind, client_config)
        .expect("Endpoint creation should not fail.");

    let start = Instant::now();

    info!("connecting to {}", parameters.target);
    let connection = endpoint.connect(parameters.target, "connect")?.await?;
    info!("connected at {:?}", start.elapsed());

    // try sending random data
    let data: Vec<u8> = (0..128).map(|_| random::<u8>()).collect();
    let result = send_data_over_stream(&connection, &data).await;
    debug!("Send result {:?}", result);

    let connection_stats = connection.stats();
    info!("Connection stats: {:?}", connection_stats);
    connection.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
}
