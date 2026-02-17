use anyhow::Result;
use std::fs::File;
use tracing::level_filters::LevelFilter;
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::{filter::Targets, fmt, prelude::*, registry};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::cli::Cli;
use crate::time::LocalTimeOnly;

/// Initialize the logger based on command-line arguments.
pub fn init_logger(cli_args: &Cli) -> Result<()> {
    let indicatif_layer = IndicatifLayer::new();

    // Format layer for console output (using a writer that coexists with the indicator)
    let console_fmt = fmt::layer()
        .with_target(false)
        .with_timer(LocalTimeOnly)
        .with_writer(indicatif_layer.get_stderr_writer());

    // Console log filter
    let console_filter = Targets::new()
        .with_default(LevelFilter::OFF)
        .with_target("nscan", cli_args.log_level.to_level_filter());

    if !cli_args.no_stdout {
        if cli_args.quiet {
            // Quiet mode: suppress all logs except errors
            let quiet_filter = LevelFilter::ERROR;

            registry()
                .with(indicatif_layer)
                .with(console_fmt.with_filter(quiet_filter))
                .init();
            return Ok(());
        }

        if !cli_args.log_file {
            // Registry-based layer stacking
            registry()
                .with(indicatif_layer)
                .with(console_fmt.with_filter(console_filter))
                .init();
            return Ok(());
        }
    }

    // Determine log file path
    let log_file_path = cli_args
        .log_file_path
        .clone()
        .unwrap_or_else(|| crate::config::get_user_file_path("nscan.log").unwrap());

    // Open log file in append mode
    let file = File::options()
        .create(true)
        .append(true)
        .open(&log_file_path)?;

    // File-specific fmt layer
    let file_fmt = fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_timer(LocalTimeOnly)
        .with_writer(file);

    #[cfg(debug_assertions)]
    {
        // debug: log_level for screen, ERROR only for file
        let file_filter = LevelFilter::ERROR;

        registry()
            .with(indicatif_layer)
            .with(console_fmt.with_filter(console_filter))
            .with(file_fmt.with_filter(file_filter))
            .init();
    }

    #[cfg(not(debug_assertions))]
    {
        // release: no output to screen, ERROR only for file
        let file_filter = LevelFilter::ERROR;

        registry().with(file_fmt.with_filter(file_filter)).init();
    }

    Ok(())
}
