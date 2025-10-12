pub mod cli;
pub mod cmd;
pub mod config;
pub mod endpoint;
pub mod dns;
pub mod scan;
pub mod output;
pub mod capture;
pub mod interface;
pub mod packet;
pub mod time;
pub mod log;
pub mod service;
pub mod db;
pub mod os;
pub mod ping;
pub mod protocol;
pub mod probe;
pub mod util;

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

    match cli.command {
        Command::Port(args) => {
            DbInitializer::with_all().init().await;
            let r = cmd::port::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {},
                Err(e) => tracing::error!("Port scan failed: {}", e),
            }
        }
        Command::Host(args) => {
            let db_ini = DbInitializer::new();
            db_ini.with_os_db().with_oui_db().init().await;

            let r = cmd::host::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {},
                Err(e) => tracing::error!("Host scan failed: {}", e),
            }
        }
        Command::Domain(args) => {
            let r = cmd::domain::run(args, cli.no_stdout, cli.output).await;
            match r {
                Ok(_) => {},
                Err(e) => tracing::error!("Domain scan failed: {}", e),
            }
        }
        Command::Interface(args) => {
            let r = cmd::interface::show(&args);
            match r {
                Ok(_) => {},
                Err(e) => tracing::error!("Show interfaces failed: {}", e),
            }
        }
    }
    tracing::info!("nscan v{} completed in {:?}", env!("CARGO_PKG_VERSION"), start_time.elapsed());
}
