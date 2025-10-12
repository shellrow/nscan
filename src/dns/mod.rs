use std::{net::IpAddr, time::Duration};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::endpoint::Host;

pub mod resolver;
pub mod probe;

/// Lookup a host by name or IP address string.
pub async fn lookup_host(host: &str, timeout: Duration) -> Result<Host> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        // Reverse lookup for IP address
        let hostname = reverse_lookup(ip, timeout).await.unwrap_or_else(|| ip.to_string());
        Ok(Host { hostname: Some(hostname), ip: ip })
    } else {
        // Resolve hostname to IP address
        let ips = lookup_ip(host, timeout).await.unwrap_or_default();
        match ips.first() {
            Some(ip) => Ok(Host { hostname: Some(host.to_string()), ip: *ip }),
            None => Err(anyhow::anyhow!("failed to resolve host")),
        }
    }
}

/// Lookup a domain and return its associated IP addresses.
pub async fn lookup_domain(hostname: &str, timeout: Duration) -> Domain {
    let ips = lookup_ip(hostname, timeout).await.unwrap_or_default();
    Domain { name: hostname.to_string(), ips }
}

/// Perform a DNS lookup for the given hostname with a timeout.
pub async fn lookup_ip(hostname: &str, timeout: Duration) -> Option<Vec<IpAddr>> {
    let resolver = resolver::get_resolver().ok()?;
    match tokio::time::timeout(
        timeout,
        async move { resolver.lookup_ip(hostname).await }
    ).await {
        Ok(Ok(ips)) => Some(ips.iter().collect()),
        _ => None,
    }
}

/// Perform a reverse DNS lookup for the given IP address with a timeout.
pub async fn reverse_lookup(ip: IpAddr, timeout: Duration) -> Option<String> {
    let resolver = resolver::get_resolver().ok()?;
    match tokio::time::timeout(
        timeout,
        async move { resolver.reverse_lookup(ip).await }
    ).await {
        Ok(Ok(names)) => names.iter().next().map(|n| n.to_string()),
        _ => None,
    }
}

/// A domain with its associated IP addresses
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Domain {
    pub name: String,
    pub ips: Vec<IpAddr>,
}

/// Result of domain scan  
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainScanResult {
    /// List of scanned domains
    pub domains: Vec<Domain>,
    /// Time from start to end of scan.  
    pub scan_time: Duration,
}
