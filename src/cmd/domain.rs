use std::{path::PathBuf, time::Duration};

use crate::{
    cli::DomainScanArgs,
    util::json::{JsonStyle, save_json_output},
};
use anyhow::Result;

/// Run subdomain scan
pub async fn run(args: DomainScanArgs, no_stdout: bool, output: Option<PathBuf>) -> Result<()> {
    let resolve_timeout = Duration::from_millis(args.resolve_timeout_ms);
    let scan_timeout = Duration::from_millis(args.timeout_ms);
    let settings = crate::dns::probe::DomainScanSetting {
        base_domain: args.domain.clone(),
        word_list: if let Some(wl_path) = args.wordlist {
            let content = std::fs::read_to_string(wl_path)?;
            content
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            crate::db::domain::get_subdomain_wordlist()
        },
        timeout: scan_timeout,
        resolve_timeout,
        concurrent_limit: args.concurrency,
    };
    let scanner = crate::dns::probe::DomainScanner::new(settings);
    // Base-domain metadata must not add another lookup timeout before the scan.
    let (base, result) = tokio::join!(
        crate::dns::lookup_domain(&args.domain, resolve_timeout.min(scan_timeout)),
        scanner.run()
    );
    let result = result?;
    if !no_stdout {
        crate::output::domain::print_domain_tree(&base, &result);
    }
    if let Some(path) = &output {
        save_json_output(&result, path, JsonStyle::Pretty)?;
        tracing::info!("JSON output saved to {}", path.display());
    }
    Ok(())
}
