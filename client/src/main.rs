//! This example demonstrates an HTTP client that requests files from a server.
//!
//! Checkout the `README.md` for guidance.
#[cfg(all(feature = "use_quinn_master", feature = "use_quinn_10"))]
compile_error!(
    "Features 'use_quinn_master' and 'use_quinn_10' are mutually exclusive.\
Try `cargo build --no-default-features --features ...` instead."
);

#[cfg(feature = "use_quinn_10")]
use quinn_10::ClientConfig;
#[cfg(feature = "use_quinn_master")]
use quinn_master::ClientConfig;
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
    tokio::task::JoinSet,
    tracing::{debug, error, info},
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
    let client_certificate =
        if let Some(staked_identity_file) = parameters.staked_identity_file.clone() {
            let staked_identity = Keypair::read_from_file(staked_identity_file)
                .map_err(|_err| QuicClientError::KeypairReadFailure)?;
            Arc::new(QuicClientCertificate::new(&staked_identity))
        } else {
            Arc::new(QuicClientCertificate::default())
        };
    let client_config = create_client_config(client_certificate);

    let mut tasks = JoinSet::new();

    for task_id in 0..parameters.num_connections {
        tasks.spawn(run_endpoint(
            client_config.clone(),
            parameters.clone(),
            task_id,
        ));
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(_) => info!("Task completed successfully"),
            Err(e) => error!("Task failed: {:?}", e),
        }
    }

    Ok(())
}

// quinn has one global per-endpoint lock, so multiple endpoints help get around that
async fn run_endpoint(
    client_config: ClientConfig,
    ClientCliParameters {
        target,
        bind,
        duration,
        tx_size,
        ..
    }: ClientCliParameters,
    task_id: usize,
) -> Result<(), QuicClientError> {
    let endpoint =
        create_client_endpoint(bind, client_config).expect("Endpoint creation should not fail.");

    let start = Instant::now();

    info!("connecting task `{task_id}` to {target}");
    let connection = endpoint.connect(target, "connect")?.await?;
    info!("connected task `{task_id}` at {:?}", start.elapsed());

    let start = Instant::now();
    loop {
        if let Some(duration) = duration {
            if start.elapsed() >= duration {
                info!("Transaction generator for task `{task_id}` is stopping...");
                break;
            }
        }

        let data = generate_dummy_data(tx_size);
        let result = send_data_over_stream(&connection, &data).await;
        debug!("{:?}", result);
    }

    let connection_stats = connection.stats();
    info!("Connection stats for task `{task_id}`: {connection_stats:?}");
    connection.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;
    Ok(())
}
