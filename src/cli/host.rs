use anyhow::{Result, Context};
use std::{net::IpAddr, path::Path};
use ipnet::IpNet;
use std::fs;
use crate::endpoint::Host;

/// Resolve one target specification line (CIDR / IP / hostname)
async fn expand_one_target(t: &str) -> Result<Vec<Host>> {
    let mut out = Vec::new();
    let resolver = crate::dns::resolver::get_resolver()?;

    // CIDR
    if let Ok(net) = t.parse::<IpNet>() {
        for ip in net.hosts() {
            out.push(Host::new(ip));
        }
        return Ok(out);
    }

    // IP
    if let Ok(ip) = t.parse::<IpAddr>() {
        out.push(Host::new(ip));
        return Ok(out);
    }

    // Hostname
    let ips = resolver.lookup_ip(t).await.with_context(|| format!("resolve {t}"))?;
    for ip in ips {
        out.push(Host::with_hostname(ip, t.to_string()));
    }
    Ok(out)
}

/// Expand targets from a file (each line: CIDR / IP / hostname / @file)
async fn expand_file(path: &Path) -> Result<Vec<Host>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read target list file {}", path.display()))?;

    // Normalize lines and prepare for recursive processing
    let mut hosts = Vec::new();
    let mut nested_inputs = Vec::new();

    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') { continue; } // Skip empty lines/comments
        nested_inputs.push(s.to_string());
    }

    // Recursively interpret each entry in the file
    for entry in nested_inputs {
        let nested = expand_one_target(&entry).await?;
        hosts.extend(nested);
    }

    Ok(hosts)
}

/// Parse target specifications (CIDR / IP / hostname / @file / existing file path)
pub async fn parse_target_hosts(inputs: &[String]) -> Result<Vec<Host>> {
    let mut out = Vec::new();

    for raw in inputs {
        let s = raw.trim();
        if s.is_empty() { continue; }

        // 1. Check if it's a file (with '@' hint or existing file path)
        let (is_file_hint, path_str) = if let Some(stripped) = s.strip_prefix('@') {
            (true, stripped)
        } else {
            (false, s)
        };

        let path = Path::new(path_str);
        if is_file_hint || path.is_file() {
            // Interpret as file
            let hosts = expand_file(path).await?;
            out.extend(hosts);
            continue;
        }

        // 2. Interpret as regular target
        let hosts = expand_one_target(s).await?;
        out.extend(hosts);
    }

    // Sort by IP & remove duplicates
    out.sort_by_key(|e| e.ip);
    out.dedup_by_key(|e| e.ip);
    Ok(out)
}
