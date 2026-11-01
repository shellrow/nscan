pub mod http;
pub mod null;
pub mod quic;
pub mod tls;

use crate::endpoint::{ServiceInfo, TransportProtocol};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};

/// Fixed built-in probes. Auto selects a small set of conventional ports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ProbeMode {
    #[default]
    Auto,
    Banner,
    Http,
    Https,
    Tls,
    Quic,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceProbe {
    TcpNull,
    TcpHTTPGet,
    TcpHTTPSGet,
    TcpTlsSession,
    UdpQuic,
}

impl ServiceProbe {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TcpNull => "tcp:banner",
            Self::TcpHTTPGet => "tcp:http",
            Self::TcpHTTPSGet => "tcp:https",
            Self::TcpTlsSession => "tcp:tls",
            Self::UdpQuic => "quic:handshake",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortProbe {
    pub probe_id: ServiceProbe,
    pub port: u16,
    pub transport: TransportProtocol,
}

#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub probe: PortProbe,
    pub timeout: Duration,
    pub max_read_size: usize,
    pub sni: bool,
    pub skip_cert_verify: bool,
}

impl ProbeContext {
    pub fn result(self, service_info: ServiceInfo) -> PortProbeResult {
        PortProbeResult {
            ip: self.ip,
            hostname: self.hostname,
            port: self.probe.port,
            transport: self.probe.transport,
            probe_id: self.probe.probe_id,
            service_info,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortProbeResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub port: u16,
    pub transport: TransportProtocol,
    pub probe_id: ServiceProbe,
    pub service_info: ServiceInfo,
}
