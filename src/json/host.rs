use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{host::Host, scan::result::{ScanResult, ScanStatus}};

/// Result of hostscan
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostScanResult {
    /// List of scanned Host info and their respective ports
    pub hosts: Vec<Host>,
    /// Time taken to scan
    pub scan_time: Duration,
    /// Status of the scan task
    pub scan_status: ScanStatus,
}

impl HostScanResult {
    /// Constructs a new PortScanResult
    pub fn new() -> HostScanResult {
        HostScanResult {
            hosts: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Error("Scan not started".to_string()),
        }
    }
    pub fn from_scan_result(scan_result: &ScanResult) -> HostScanResult {
        HostScanResult {
            hosts: scan_result.hosts.clone(),
            scan_time: scan_result.scan_time.clone(),
            scan_status: scan_result.scan_status.clone(),
        }
    }
}
