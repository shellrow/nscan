use serde::{Deserialize, Serialize};
use clap::ValueEnum;

/// Supported protocols for probing
#[derive(Deserialize, Serialize, Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum Protocol { 
    Icmp, 
    Udp, 
    Tcp,
    Quic,
    Arp,
    Ndp
}

impl Protocol {
    /// Get the protocol as a string
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Icmp => "icmp",
            Protocol::Udp => "udp",
            Protocol::Tcp => "tcp",
            Protocol::Quic => "quic",
            Protocol::Arp => "arp",
            Protocol::Ndp => "ndp",
        }
    }
}
