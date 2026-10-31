use std::time::Duration;

use anyhow::Result;
use netdev::Interface;

use crate::endpoint::{Endpoint, Host, Port};
use std::collections::{BTreeMap, HashSet};

/// Resolve the interface from CLI option. Falls back to default interface.
pub fn resolve_interface(interface_name: Option<&str>) -> Result<Interface> {
    if let Some(name) = interface_name {
        return crate::interface::get_interface_by_name(name.to_string())
            .ok_or_else(|| anyhow::anyhow!("interface not found: {}", name));
    }

    netdev::get_default_interface()
        .map_err(|e| anyhow::anyhow!("failed to get default interface: {}", e))
}

/// Build endpoints by applying the same port list to each host.
pub fn build_endpoints(hosts: Vec<Host>, ports: &[Port]) -> Result<Vec<Endpoint>> {
    anyhow::ensure!(
        hosts.len().saturating_mul(ports.len().max(1)) <= 1_000_000,
        "scan exceeds 1,000,000 host/port pairs; split the scan"
    );
    // Deduplicate once while preserving randomized or explicitly ordered scans.
    let mut seen = HashSet::new();
    let ports: Vec<Port> = ports
        .iter()
        .copied()
        .filter(|port| seen.insert(*port))
        .collect();
    Ok(hosts
        .into_iter()
        .map(|host| {
            let mut endpoint = Endpoint::new(host.ip);
            endpoint.hostname = host.hostname;
            endpoint.ports = ports.clone();
            endpoint
        })
        .collect())
}

/// Merge duplicate endpoints by IP and de-duplicate ports.
pub fn merge_endpoints(endpoints: Vec<Endpoint>) -> Vec<Endpoint> {
    let mut by_ip: BTreeMap<std::net::IpAddr, Endpoint> = BTreeMap::new();
    for endpoint in endpoints {
        by_ip
            .entry(endpoint.ip)
            .and_modify(|existing| existing.merge(endpoint.clone()))
            .or_insert(endpoint);
    }
    by_ip.into_values().collect()
}

/// Ensure concurrency is always at least 1.
pub fn normalize_concurrency(v: usize) -> usize {
    v.max(1)
}

/// Derive connect timeout from initial RTT unless explicitly configured.
pub fn derive_connect_timeout(initial_rtt: Duration, override_ms: Option<u64>) -> Duration {
    match override_ms {
        Some(ms) => Duration::from_millis(ms),
        None => {
            let adapted = (initial_rtt.as_millis() as f64 * 1.5) as u64;
            Duration::from_millis(adapted.clamp(50, 5000))
        }
    }
}

/// Derive wait time from initial RTT unless explicitly configured.
pub fn derive_wait_time(initial_rtt: Duration, override_ms: Option<u64>) -> Duration {
    match override_ms {
        Some(ms) => Duration::from_millis(ms),
        None => {
            let adapted = (initial_rtt.as_millis() as f64 * 2.0) as u64;
            Duration::from_millis(adapted.clamp(100, 5000))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::TransportProtocol;

    #[test]
    fn endpoint_construction_preserves_order_and_removes_duplicates() {
        let ports = [443, 22, 80, 22].map(|port| Port::new(port, TransportProtocol::Tcp));
        let hosts = vec![
            Host::new("127.0.0.1".parse().unwrap()),
            Host::new("::1".parse().unwrap()),
        ];
        let endpoints = build_endpoints(hosts, &ports).unwrap();
        for endpoint in endpoints {
            assert_eq!(endpoint.ports, ports[..3]);
        }
        let all_ports = (1..=65535)
            .map(|port| Port::new(port, TransportProtocol::Tcp))
            .collect::<Vec<_>>();
        let endpoints = build_endpoints(vec![Host::default()], &all_ports).unwrap();
        assert_eq!(endpoints[0].ports, all_ports);
    }
}
