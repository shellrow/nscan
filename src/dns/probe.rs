use futures::stream::{self, StreamExt};
use rand::{distributions::Alphanumeric, Rng};
use tokio::time::timeout;
use std::sync::Arc;
use std::{net::IpAddr, time::Instant};
use std::time::Duration;
use anyhow::Result;
use tracing_indicatif::span_ext::IndicatifSpanExt;

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
    s.trim_end_matches('.').to_ascii_lowercase()
}

/// Check if the base domain has wildcard DNS records.
async fn is_wildcard_domain(resolver: &hickory_resolver::TokioResolver, base: &str, rt: Duration) -> bool {
    let rand_label: String = rand::thread_rng()
        .sample_iter(&Alphanumeric).take(10).map(char::from).collect();
    let test = format!("{}.{}", rand_label, base);
    match timeout(rt, resolver.lookup_ip(test)).await {
        Ok(Ok(lip)) => !lip.as_lookup().is_empty(),
        _ => false,
    }
}

/// Scan subdomains based on the provided settings.
pub async fn scan_subdomain(setting: &DomainScanSetting) -> Result<DomainScanResult> {
    let base = normalize_label(&setting.base_domain);

    let target_domains: Vec<String> = setting.word_list
        .iter()
        .map(|w| format!("{}.{}", normalize_label(w), base))
        .collect();

    let resolver = Arc::new(super::resolver::get_resolver()?);

    let wildcard = is_wildcard_domain(&resolver, &base, setting.resolve_timeout).await;

    let header_span = tracing::info_span!("subdomain_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message(&format!("Subdomain Scan ({})", base));
    header_span.pb_set_length(target_domains.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    let start_time = Instant::now();

    // Parallel resolution stream
    let results = stream::iter(target_domains)
        .map(|domain_name| {
            let resolver = resolver.clone();
            let rt = setting.resolve_timeout;
            async move {
                let mut d = Domain { name: domain_name.clone(), ips: Vec::new() };
                match timeout(rt, resolver.lookup_ip(domain_name)).await {
                    Ok(Ok(lip)) => {
                        let mut uniq: Vec<IpAddr> = lip.iter().collect();
                        uniq.sort();
                        uniq.dedup();
                        d.ips = uniq;
                    }
                    _ => {}
                }
                d
            }
        })
        .buffer_unordered(setting.concurrent_limit);

    // Collect results with timeout handling
    tokio::pin!(results);
    let deadline = start_time + setting.timeout;
    let mut domains: Vec<Domain> = Vec::new();

    loop {
        let now = Instant::now();
        if now >= deadline { break; }
        let remaining = deadline - now;

        tokio::select! {
            _ = tokio::time::sleep(remaining) => {
                // Deadline reached: return what has been collected so far
                break;
            }
            maybe = results.next() => {
                match maybe {
                    Some(d) => {
                        if !d.ips.is_empty() {
                            domains.push(d);
                        }
                        header_span.pb_inc(1);
                    }
                    None => break, // All done
                }
            }
        }
    }

    drop(header_span);

    if wildcard {
        if let Some(first) = domains.first().map(|d| d.ips.clone()) {
            let all_same = domains.iter().all(|d| d.ips == first);
            if all_same { domains.clear(); }
        }
    }

    domains.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(DomainScanResult {
        domains,
        scan_time: start_time.elapsed().min(setting.timeout),
    })
}
