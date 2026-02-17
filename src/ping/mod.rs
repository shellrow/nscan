pub mod pinger;
pub mod probe;
pub mod result;
pub mod setting;

use std::time::Duration;

use anyhow::Result;
use netdev::Interface;

use crate::{
    endpoint::Host,
    ping::{pinger::Pinger, setting::PingSetting},
};

// Check reachability of the target and measure latency before probing
pub async fn initial_ping(
    interface: &Interface,
    dst_host: &Host,
    port: Option<u16>,
) -> Result<Duration> {
    match dst_host.hostname {
        Some(ref name) => {
            tracing::info!("Performing initial ping to {} ({})", name, dst_host.ip);
        }
        None => {
            tracing::info!("Performing initial ping to {}", dst_host.ip);
        }
    }

    // 1. Try ICMP ping
    let icmp_setting: PingSetting = PingSetting::icmp_ping(&interface, dst_host.clone(), 1)?;
    let pinger = Pinger::new(icmp_setting);
    match pinger.run().await {
        Ok(r) => {
            if let Some(first) = r.first_response() {
                return Ok(first.rtt);
            }
        }
        Err(e) => {
            tracing::warn!("Initial ICMP ping failed: {}", e);
        }
    }

    // 2. Try UDP ping
    let udp_setting: PingSetting = PingSetting::udp_ping(&interface, dst_host.clone(), 1)?;
    let pinger = Pinger::new(udp_setting);
    match pinger.run().await {
        Ok(r) => {
            if let Some(first) = r.first_response() {
                return Ok(first.rtt);
            }
        }
        Err(e) => {
            tracing::warn!("Initial UDP ping failed: {}", e);
        }
    }

    // 3. Try TCP ping
    let target_port = port.unwrap_or(80);
    let tcp_setting: PingSetting =
        PingSetting::tcp_ping(&interface, dst_host.clone(), target_port, 1)?;
    let pinger = Pinger::new(tcp_setting);
    match pinger.run().await {
        Ok(r) => {
            if let Some(first) = r.first_response() {
                return Ok(first.rtt);
            }
        }
        Err(e) => {
            tracing::warn!("Initial TCP ping failed: {}", e);
        }
    }

    anyhow::bail!("All initial ping methods failed");
}
