use crate::{
    ping::{result::PingResult, setting::PingSetting},
    protocol::Protocol,
};
use anyhow::Result;

/// Pinger structure.
///
/// Supports ICMP Ping, TCP Ping, UDP Ping.
#[derive(Clone, Debug)]
pub struct Pinger {
    /// Probe Setting
    pub ping_setting: PingSetting,
}

impl Pinger {
    /// Create a new Pinger instance.
    pub fn new(ping_setting: PingSetting) -> Self {
        Self { ping_setting }
    }
    /// Run the ping based on the specified protocol and return the results.
    pub async fn run(&self) -> Result<PingResult> {
        match self.ping_setting.protocol {
            Protocol::Icmp => super::probe::icmp::run_icmp_ping(&self.ping_setting).await,
            Protocol::Udp => super::probe::udp::run_udp_ping(&self.ping_setting).await,
            Protocol::Tcp => super::probe::tcp::run_tcp_ping(&self.ping_setting).await,
            _ => Err(anyhow::anyhow!("Unsupported protocol")),
        }
    }
}
