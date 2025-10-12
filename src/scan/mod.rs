use anyhow::Result;

use crate::{cli::{HostScanProto, PortScanMethod}, endpoint::TransportProtocol, output::ScanResult, probe::ProbeSetting};

pub mod probe;

/// A port scanner that can perform scans using different methods and transport protocols.
pub struct PortScanner {
    pub settings: ProbeSetting,
    pub scan_method: PortScanMethod,
    pub transport: TransportProtocol,
}

impl PortScanner {
    /// Create a new PortScanner instance.
    pub fn new(settings: ProbeSetting, transport: TransportProtocol, scan_method: PortScanMethod) -> Self {
        Self {
            settings,
            scan_method,
            transport,
        }
    }
    /// Run the port scan based on the specified transport protocol and method.
    pub async fn run(&self) -> Result<ScanResult> {
        match self.transport {
            TransportProtocol::Tcp => probe::tcp::run_port_scan(self.settings.clone(), self.scan_method).await,
            TransportProtocol::Quic => probe::quic::run_port_scan(self.settings.clone(), self.scan_method).await,
            _ => anyhow::bail!("Unsupported transport protocol: {:?}", self.transport),
        }
    }
}

/// A host scanner that can perform scans using different protocols.
pub struct HostScanner {
    pub settings: ProbeSetting,
    pub protocol: HostScanProto,
}

impl HostScanner {
    /// Create a new HostScanner instance.
    pub fn new(settings: ProbeSetting, protocol: HostScanProto) -> Self {
        Self { settings, protocol }
    }
    /// Run the host scan based on the specified protocol.
    pub async fn run(&self) -> Result<ScanResult> {
        match self.protocol {
            HostScanProto::Icmp => probe::icmp::run_host_scan(self.settings.clone()).await,
            HostScanProto::Udp => probe::udp::run_host_scan(self.settings.clone()).await,
            HostScanProto::Tcp => probe::tcp::run_host_scan(self.settings.clone()).await,
        }
    }
}
