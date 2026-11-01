pub mod capture;
pub mod cli;
pub mod cmd;
pub mod config;
pub mod db;
pub mod dns;
pub mod endpoint;
pub mod interface;
pub mod log;
pub mod nmap;
pub mod output;
pub mod ping;
pub mod probe;
pub mod protocol;
pub mod scan;
pub mod service;
pub mod time;
pub mod util;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Parse command line arguments
    let cli = Cli::parse();
    // Initialize logger
    if let Err(e) = log::init_logger(&cli) {
        eprintln!("Failed to initialize logging: {e:#}");
        return std::process::ExitCode::FAILURE;
    }
    // Start nscan
    let start_time = std::time::Instant::now();
    tracing::info!("nscan v{} started", env!("CARGO_PKG_VERSION"));

    if let Err(e) = run_command(cli).await {
        tracing::error!("{e:#}");
        return std::process::ExitCode::FAILURE;
    }
    tracing::info!(
        "nscan v{} completed in {:?}",
        env!("CARGO_PKG_VERSION"),
        start_time.elapsed()
    );
    std::process::ExitCode::SUCCESS
}

async fn run_command(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Port(args) => cmd::port::run(args, cli.no_stdout, cli.output)
            .await
            .context("Port scan failed"),
        Command::Host(args) => cmd::host::run(args, cli.no_stdout, cli.output)
            .await
            .context("Host scan failed"),
        Command::Domain(args) => cmd::domain::run(args, cli.no_stdout, cli.output)
            .await
            .context("Domain scan failed"),
        Command::Interface(args) => {
            cmd::interface::show(&args, cli.no_stdout, cli.output).context("Show interfaces failed")
        }
    }
}
