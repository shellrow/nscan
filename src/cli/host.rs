use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use ipnet::IpNet;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::endpoint::Host;

const TARGET_RESOLVE_CONCURRENCY: usize = 64;

#[derive(Debug)]
enum TargetSpec {
    Network(IpNet),
    Address(IpAddr),
    Hostname(String),
}

impl TargetSpec {
    fn parse(raw: &str) -> Self {
        if let Ok(net) = raw.parse::<IpNet>() {
            return Self::Network(net);
        }
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Self::Address(ip);
        }
        Self::Hostname(raw.to_string())
    }
}

fn canonicalize_for_seen(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn collect_target_tokens(
    inputs: &[String],
    seen_files: &mut HashSet<PathBuf>,
) -> Result<Vec<String>> {
    let mut tokens = Vec::new();

    for raw in inputs {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }

        let (is_file_hint, path_str) = if let Some(stripped) = s.strip_prefix('@') {
            (true, stripped)
        } else {
            (false, s)
        };

        let path = Path::new(path_str);
        if is_file_hint || path.is_file() {
            let canonical = canonicalize_for_seen(path);
            if !seen_files.insert(canonical.clone()) {
                continue;
            }

            let text = fs::read_to_string(path)
                .with_context(|| format!("read target list file {}", path.display()))?;

            let nested_inputs: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToString::to_string)
                .collect();

            if nested_inputs.is_empty() {
                continue;
            }

            let mut nested = collect_target_tokens(&nested_inputs, seen_files)?;
            tokens.append(&mut nested);
            continue;
        }

        tokens.push(s.to_string());
    }

    Ok(tokens)
}

/// Parse target specifications (CIDR / IP / hostname / @file / existing file path)
pub async fn parse_target_hosts(inputs: &[String]) -> Result<Vec<Host>> {
    let mut seen_files = HashSet::new();
    let tokens = collect_target_tokens(inputs, &mut seen_files)?;

    let mut net_targets = Vec::new();
    let mut ip_targets = Vec::new();
    let mut hostnames = Vec::new();

    for token in tokens {
        match TargetSpec::parse(&token) {
            TargetSpec::Network(net) => net_targets.push(net),
            TargetSpec::Address(ip) => ip_targets.push(ip),
            TargetSpec::Hostname(name) => hostnames.push(name),
        }
    }

    let resolver = crate::dns::resolver::get_resolver()?;

    let dns_resolved = stream::iter(hostnames.into_iter())
        .map(|name| {
            let resolver = resolver.clone();
            async move {
                let lookup = resolver
                    .lookup_ip(name.as_str())
                    .await
                    .with_context(|| format!("resolve {}", name))?;

                let mut hosts = Vec::new();
                for ip in lookup {
                    hosts.push(Host::with_hostname(ip, name.clone()));
                }
                Ok::<Vec<Host>, anyhow::Error>(hosts)
            }
        })
        .buffer_unordered(TARGET_RESOLVE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    let mut by_ip: BTreeMap<IpAddr, Host> = BTreeMap::new();

    for net in net_targets {
        for ip in net.hosts() {
            by_ip.entry(ip).or_insert_with(|| Host::new(ip));
        }
    }

    for ip in ip_targets {
        by_ip.entry(ip).or_insert_with(|| Host::new(ip));
    }

    for resolved in dns_resolved {
        let hosts = resolved?;
        for host in hosts {
            by_ip
                .entry(host.ip)
                .and_modify(|existing| {
                    if existing.hostname.is_none() {
                        existing.hostname = host.hostname.clone();
                    }
                })
                .or_insert(host);
        }
    }

    Ok(by_ip.into_values().collect())
}
