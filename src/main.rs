pub mod capture;
pub mod cli;
pub mod cmd;
pub mod config;
pub mod db;
pub mod dns;
pub mod endpoint;
pub mod interface;
pub mod log;
pub mod os;
pub mod output;
pub mod packet;
pub mod ping;
pub mod probe;
pub mod protocol;
pub mod scan;
pub mod service;
pub mod time;
pub mod util;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

use crate::db::DbInitializer;

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let cli = Cli::parse();
    // Initialize logger
    let _ = log::init_logger(&cli);
    // Start nscan
    let start_time = std::time::Instant::now();
    tracing::info!("nscan v{} started", env!("CARGO_PKG_VERSION"));

    if let Err(e) = run_command(cli).await {
        tracing::error!("{}", e);
    }
    tracing::info!(
        "nscan v{} completed in {:?}",
        env!("CARGO_PKG_VERSION"),
        start_time.elapsed()
    );
}

async fn run_command(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Port(args) => {
            DbInitializer::with_all().init().await;
            cmd::port::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Port scan failed: {}", e))
        }
        Command::Host(args) => {
            DbInitializer::new().with_os_db().with_oui_db().init().await;
            cmd::host::run(args, cli.no_stdout, cli.output)
                .await
                .map_err(|e| anyhow::anyhow!("Host scan failed: {}", e))
        }
        Command::Domain(args) => cmd::domain::run(args, cli.no_stdout, cli.output)
            .await
            .map_err(|e| anyhow::anyhow!("Domain scan failed: {}", e)),
        Command::Interface(args) => cmd::interface::show(&args)
            .map_err(|e| anyhow::anyhow!("Show interfaces failed: {}", e)),
    }
}
