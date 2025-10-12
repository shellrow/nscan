use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use crate::{cli::DomainScanArgs, util::json::{save_json_output, JsonStyle}};

/// Run subdomain scan
pub async fn run(args: DomainScanArgs, no_stdout: bool, output: Option<PathBuf>) -> Result<()> {
    let resolve_timeout = Duration::from_millis(args.resolve_timeout_ms);
    let base = crate::dns::lookup_domain(&args.domain, resolve_timeout).await;
    let settings = crate::dns::probe::DomainScanSetting {
        base_domain: base.name.clone(),
        word_list: if let Some(wl_path) = args.wordlist {
            let content = std::fs::read_to_string(wl_path)?;
            content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        } else {
            crate::db::domain::get_subdomain_wordlist()
        },
        timeout: Duration::from_millis(args.timeout_ms),
        resolve_timeout: resolve_timeout,
        concurrent_limit: args.concurrency,
    };
    let scanner = crate::dns::probe::DomainScanner::new(settings);
    let result = scanner.run().await?;
    if !no_stdout {
        crate::output::domain::print_domain_tree(&base, &result);
    }
    if let Some(path) = &output {
        match save_json_output(&result, path, JsonStyle::Pretty) {
            Ok(_) => {
                if !no_stdout {
                    tracing::info!("JSON output saved to {}", path.display());
                }
            },
            Err(e) => tracing::error!("Failed to save JSON output: {}", e),
        }
    }
    Ok(())
}
