use crate::scan::result::ScanStatus;

use super::domain::Domain;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Result of domain scan  
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainScanResult {
    /// HashMap of domain.
    ///
    /// (Domain, IP Addresses)
    pub domains: Vec<Domain>,
    /// Time from start to end of scan.  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

impl DomainScanResult {
    pub fn new() -> DomainScanResult {
        DomainScanResult {
            domains: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Error(String::from("Scan not started")),
        }
    }
}
