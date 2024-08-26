//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.

use {
    client::{
        cli::{build_cli_parameters, ClientCliParameters},
        error::QuicClientError,
        quic_networking::{
            create_client_config, create_client_endpoint, send_data_over_stream,
            QuicClientCertificate,
        },
        transaction_generator::generate_dummy_data,
    },
    solana_sdk::{signature::Keypair, signer::EncodableKey},
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
    let client_certificate = if let Some(staked_identity_file) = parameters.staked_identity_file {
        let staked_identity = Keypair::read_from_file(staked_identity_file)
            .map_err(|_err| QuicClientError::KeypairReadFailure)?;
        Arc::new(QuicClientCertificate::new(&staked_identity))
    } else {
        Arc::new(QuicClientCertificate::default())
    };
    let client_config = create_client_config(client_certificate);
    let endpoint = create_client_endpoint(parameters.bind, client_config)
        .expect("Endpoint creation should not fail.");

    let start = Instant::now();

    info!("connecting to {}", parameters.target);
    let connection = endpoint.connect(parameters.target, "connect")?.await?;
    info!("connected at {:?}", start.elapsed());

    let num_txs = 1024;
    for _ in 0..num_txs {
        let data = generate_dummy_data(false);
        // using join_all will run concurrently but not in parallel.
        // it was like below but it is wrong due to fragmentation
        /*let futures = transactions.into_iter().map(|data| {
            let conn = connection.clone();
            async move { send_data_over_stream(&conn, &data).await }
        });
        let results = join_all(futures).await;
        for result in results {
            debug!("{:?}", result);
        }*/
        let result = send_data_over_stream(&connection, &data).await;
        debug!("{:?}", result);
    }

    let connection_stats = connection.stats();
    info!("Connection stats: {:?}", connection_stats);
    connection.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;

    Ok(())
}
