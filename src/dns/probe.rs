use anyhow::Result;
use futures::stream::{self, StreamExt};
use rand::{RngExt, distr::Alphanumeric};
use std::sync::Arc;
use std::time::Duration;
use std::{net::IpAddr, time::Instant};
use tokio::time::timeout;

use crate::dns::{Domain, DomainScanResult};

/// Settings for domain scanning
pub struct DomainScanSetting {
    /// Base Domain Name of scan target.  
    pub base_domain: String,
    /// Word-list of name
    pub word_list: Vec<String>,
    /// Timeout setting of domain scan.  
    pub timeout: Duration,
    /// Resolve timeout setting of domain scan.
    pub resolve_timeout: Duration,
    /// Concurrent limit of domain scan.
    pub concurrent_limit: usize,
}

impl DomainScanSetting {
    /// Create a new DomainScanSetting with default timeouts and concurrency.
    pub fn new(base_domain: String, word_list: Vec<String>) -> Self {
        Self {
            base_domain,
            word_list,
            timeout: Duration::from_secs(10),
            resolve_timeout: Duration::from_secs(2),
            concurrent_limit: 100,
        }
    }
}

/// Domain Scanner
pub struct DomainScanner {
    pub settings: DomainScanSetting,
}

impl DomainScanner {
    /// Create a new DomainScanner with the given settings.
    pub fn new(settings: DomainScanSetting) -> Self {
        Self { settings }
    }
    /// Run the domain scan and return the results.
    pub async fn run(&self) -> Result<DomainScanResult> {
        scan_subdomain(&self.settings).await
    }
}

/// Normalize a domain label by trimming trailing dots and converting to lowercase.
fn normalize_label(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Check if the base domain has wildcard DNS records.
async fn is_wildcard_domain(
    resolver: &hickory_resolver::TokioResolver,
    base: &str,
    rt: Duration,
) -> bool {
    let rand_label: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    let test = format!("{}.{}", rand_label, base);
    match timeout(rt, resolver.lookup_ip(test)).await {
        Ok(Ok(lip)) => !lip.as_lookup().answers().is_empty(),
        _ => false,
    }
}

/// Scan subdomains based on the provided settings.
pub async fn scan_subdomain(setting: &DomainScanSetting) -> Result<DomainScanResult> {
    anyhow::ensure!(
        setting.concurrent_limit > 0,
        "DNS concurrency must be positive"
    );
    anyhow::ensure!(
        !setting.timeout.is_zero() && !setting.resolve_timeout.is_zero(),
        "DNS timeouts must be positive"
    );
    let start_time = Instant::now();
    let base = normalize_label(&setting.base_domain);
    hickory_proto::rr::Name::from_ascii(format!("{base}."))?;

    let mut target_domains: Vec<String> = setting
        .word_list
        .iter()
        .map(|w| format!("{}.{}.", normalize_label(w), base))
        .collect();

    target_domains.sort();
    target_domains.dedup();
    let total = target_domains.len();
    let resolver = Arc::new(super::resolver::get_resolver()?);

    let wildcard = is_wildcard_domain(
        &resolver,
        &base,
        setting.resolve_timeout.min(setting.timeout),
    )
    .await;

    // Parallel resolution stream
    let results = stream::iter(target_domains)
        .map(|domain_name| {
            let resolver = resolver.clone();
            let rt = setting.resolve_timeout;
            async move {
                let mut d = Domain {
                    name: domain_name.trim_end_matches('.').to_string(),
                    ips: Vec::new(),
                };
                if let Ok(Ok(lip)) = timeout(rt, resolver.lookup_ip(domain_name)).await {
                    let mut uniq: Vec<IpAddr> = lip.iter().collect();
                    uniq.sort();
                    uniq.dedup();
                    d.ips = uniq;
                }
                d
            }
        })
        .buffer_unordered(setting.concurrent_limit);

    // Collect results with timeout handling
    tokio::pin!(results);
    let deadline = start_time + setting.timeout;
    let mut domains: Vec<Domain> = Vec::new();
    let mut attempted = 0;

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;

        tokio::select! {
            _ = tokio::time::sleep(remaining) => {
                // Deadline reached: return what has been collected so far
                break;
            }
            maybe = results.next() => {
                match maybe {
                    Some(d) => {
                        attempted += 1;
                        if !d.ips.is_empty() {
                            domains.push(d);
                        }
                    }
                    None => break, // All done
                }
            }
        }
    }

    if wildcard {
        tracing::warn!("Wildcard DNS detected; results may include wildcard responses");
    }
    if attempted < total {
        tracing::warn!("DNS scan timed out after {attempted}/{total} candidates");
    }

    domains.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(DomainScanResult {
        domains,
        wildcard_detected: wildcard,
        complete: attempted == total,
        attempted,
        total,
        scan_time: start_time.elapsed().min(setting.timeout),
    })
}
