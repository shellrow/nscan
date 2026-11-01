use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use ipnet::IpNet;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::endpoint::Host;

const TARGET_RESOLVE_CONCURRENCY: usize = 64;
const MAX_TARGETS: usize = 65_536;
const MAX_FILE_DEPTH: usize = 32;

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
    depth: usize,
    base: &Path,
) -> Result<Vec<String>> {
    anyhow::ensure!(
        depth <= MAX_FILE_DEPTH,
        "target file nesting exceeds {MAX_FILE_DEPTH}"
    );
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

        let path = base.join(path_str);
        if is_file_hint || path.is_file() {
            let canonical = canonicalize_for_seen(&path);
            if !seen_files.insert(canonical.clone()) {
                continue;
            }

            let text = fs::read_to_string(&path)
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

            let mut nested = collect_target_tokens(
                &nested_inputs,
                seen_files,
                depth + 1,
                path.parent().unwrap_or(base),
            )?;
            tokens.append(&mut nested);
            anyhow::ensure!(
                tokens.len() <= MAX_TARGETS,
                "too many target specifications"
            );
            continue;
        }

        tokens.push(s.to_string());
        anyhow::ensure!(
            tokens.len() <= MAX_TARGETS,
            "too many target specifications"
        );
    }

    Ok(tokens)
}

/// Parse target specifications (CIDR / IP / hostname / @file / existing file path)
pub async fn parse_target_hosts(inputs: &[String]) -> Result<Vec<Host>> {
    let mut seen_files = HashSet::new();
    let tokens = collect_target_tokens(inputs, &mut seen_files, 0, Path::new("."))?;

    let mut net_targets = Vec::new();
    let mut ip_targets = Vec::new();
    let mut hostnames = Vec::new();

    for token in tokens {
        match TargetSpec::parse(&token) {
            TargetSpec::Network(net) => {
                let bits = if net.addr().is_ipv4() { 32 } else { 128 };
                let size = 1u128
                    .checked_shl(bits - u32::from(net.prefix_len()))
                    .unwrap_or(u128::MAX);
                anyhow::ensure!(
                    size <= MAX_TARGETS as u128,
                    "network {net} exceeds the {MAX_TARGETS} address limit; split the scan"
                );
                net_targets.push(net);
            }
            TargetSpec::Address(ip) => ip_targets.push(ip),
            TargetSpec::Hostname(name) => {
                anyhow::ensure!(!name.contains('/'), "invalid CIDR target: {name}");
                hostnames.push(name);
            }
        }
    }

    hostnames.sort();
    hostnames.dedup();
    net_targets.sort();
    net_targets.dedup();
    let resolver = if hostnames.is_empty() {
        None
    } else {
        Some(crate::dns::resolver::get_resolver()?)
    };

    let dns_resolved = stream::iter(hostnames)
        .map(|name| {
            let resolver = resolver.clone();
            async move {
                let resolver = resolver.context("DNS resolver unavailable")?;
                let lookup = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    resolver.lookup_ip(format!("{}.", name.trim_end_matches('.'))),
                )
                .await
                .context("target DNS lookup timed out")?
                .with_context(|| format!("resolve {}", name))?;

                let mut hosts = Vec::new();
                for ip in lookup {
                    hosts.push(Host::with_hostname(ip, name.clone()));
                }
                Ok::<Vec<Host>, anyhow::Error>(hosts)
            }
        })
        .buffered(TARGET_RESOLVE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    let mut by_ip: BTreeMap<IpAddr, Host> = BTreeMap::new();

    for net in net_targets {
        for ip in net.hosts() {
            by_ip.entry(ip).or_insert_with(|| Host::new(ip));
            anyhow::ensure!(
                by_ip.len() <= MAX_TARGETS,
                "target count exceeds {MAX_TARGETS}"
            );
        }
    }

    for ip in ip_targets {
        by_ip.entry(ip).or_insert_with(|| Host::new(ip));
        anyhow::ensure!(
            by_ip.len() <= MAX_TARGETS,
            "target count exceeds {MAX_TARGETS}"
        );
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
            anyhow::ensure!(
                by_ip.len() <= MAX_TARGETS,
                "target count exceeds {MAX_TARGETS}"
            );
        }
    }

    Ok(by_ip.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_unbounded_networks_before_expansion() {
        for target in ["::/0", "2001:db8::/64", "0.0.0.0/0", "192.0.2.1/33"] {
            assert!(parse_target_hosts(&[target.into()]).await.is_err());
        }
    }

    #[tokio::test]
    async fn merges_networks_and_addresses_without_dns() {
        let hosts =
            parse_target_hosts(&["192.0.2.0/30".into(), "192.0.2.1".into(), "::1/128".into()])
                .await
                .unwrap();
        assert_eq!(hosts.len(), 3);
        assert!(
            hosts
                .iter()
                .any(|h| h.ip == "::1".parse::<IpAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn nested_files_are_relative_and_cycles_terminate() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("first"), "@second\n192.0.2.1\n").unwrap();
        fs::write(dir.path().join("second"), "@first\n192.0.2.2\n").unwrap();
        let hosts = parse_target_hosts(&[format!("@{}", dir.path().join("first").display())])
            .await
            .unwrap();
        assert_eq!(hosts.len(), 2);
    }
}
