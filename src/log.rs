use anyhow::{Context, Result};
use std::{fs::File, io::IsTerminal};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{filter::Targets, fmt, prelude::*, registry};

use crate::{cli::Cli, time::LocalTimeOnly};

/// Initialize stderr logging and optional file logging consistently in all builds.
pub fn init_logger(args: &Cli) -> Result<()> {
    let level = if args.quiet {
        tracing::Level::ERROR
    } else {
        args.log_level.to_level_filter()
    };
    let filter = || {
        Targets::new()
            .with_default(LevelFilter::OFF)
            .with_target("nscan", level)
    };
    let console = fmt::layer()
        .with_target(false)
        .with_ansi(std::io::stderr().is_terminal())
        .with_timer(LocalTimeOnly)
        .with_writer(std::io::stderr)
        .with_filter(filter());
    let file = if args.log_file || args.log_file_path.is_some() {
        let path = match &args.log_file_path {
            Some(path) => path.clone(),
            None => crate::config::get_user_file_path("nscan.log")
                .context("cannot determine or create the log directory")?,
        };
        Some(
            File::options()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("open log file {}", path.display()))?,
        )
    } else {
        None
    };
    let file_layer = file.map(|file| {
        fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .with_timer(LocalTimeOnly)
            .with_writer(file)
            .with_filter(filter())
    });
    registry().with(console).with(file_layer).try_init()?;
    Ok(())
}
