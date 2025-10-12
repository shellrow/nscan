use std::net::IpAddr;

use anyhow::{Result, Context};
use crate::endpoint::Host;

/// Parse a single target host (IP or hostname)
pub async fn parse_target_host(host_str: &str) -> Result<Host> {
    let resolver = crate::dns::resolver::get_resolver()?;
    match host_str.parse::<IpAddr>() {
        Ok(ip) => Ok(Host::new(ip)),
        Err(_) => {
            let ips = resolver.lookup_ip(host_str).await
                .with_context(|| format!("resolve {host_str}"))?;
            // If multiple IPs are returned, use the first one (ips: LookupIp)
            for ip in ips {
                return Ok(Host::with_hostname(ip, host_str.to_string()));
            }
            Err(anyhow::anyhow!("no IPs found"))
        }
    }
}
