use std::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{host::Host, scan::result::ScanStatus};

/// Result of portscan
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortScanResult {
    /// Scanned Host info and their respective ports
    pub host: Host,
    /// Time taken to scan
    pub port_scan_time: Duration,
    /// Service detection time
    pub service_detection_time: Duration,
    /// Total scan time
    pub total_scan_time: Duration,
    /// Status of the scan task
    pub scan_status: ScanStatus,
}

impl PortScanResult {
    /// Constructs a new PortScanResult
    pub fn new(ip_addr: IpAddr, hostname: String) -> PortScanResult {
        PortScanResult {
            host: Host::new(ip_addr, hostname),
            port_scan_time: Duration::new(0, 0),
            service_detection_time: Duration::new(0, 0),
            total_scan_time: Duration::new(0, 0),
            scan_status: ScanStatus::Error("Scan not started".to_string()),
        }
    }
}
