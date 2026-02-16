use std::time::Duration;

use anyhow::Result;
use netdev::Interface;

use crate::endpoint::{Endpoint, Host, Port};

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
pub fn build_endpoints(hosts: Vec<Host>, ports: &[Port]) -> Vec<Endpoint> {
    hosts
        .into_iter()
        .map(|host| {
            let mut endpoint = Endpoint::new(host.ip);
            endpoint.hostname = host.hostname;
            for port in ports {
                endpoint.upsert_port(*port);
            }
            endpoint
        })
        .collect()
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
