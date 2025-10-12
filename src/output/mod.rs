use std::time::Duration;
use nex::packet::frame::Frame;
use serde::{Deserialize, Serialize};
use crate::endpoint::{Endpoint, EndpointResult};

pub mod port;
pub mod progress;
pub mod host;
pub mod ping;
pub mod domain;
pub mod interface;

/// Convert a string into a tree label.
fn tree_label<S: Into<String>>(s: S) -> String {
    s.into()
}

/// The overall scan result containing endpoints and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub endpoints: Vec<EndpointResult>,
    pub scan_time: Duration,
    pub fingerprints: Vec<Frame>,
}

impl ScanResult {
    /// Construct a new, empty ScanResult.
    pub fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            scan_time: Duration::new(0, 0),
            fingerprints: Vec::new(),
        }
    }

    /// Get a list of all endpoints from the scan result.
    pub fn get_endpoints(&self) -> Vec<Endpoint> {
        self.endpoints.iter().map(|e| e.to_endpoint()).collect()
    }

    /// Get a list of active endpoints (those with active results).
    pub fn get_active_endpoints(&self) -> Vec<Endpoint> {
        self.endpoints.iter().filter_map(|e| e.active_endpoint()).collect()
    }

    /// Sort the endpoints by their IP addresses.
    pub fn sort_endpoints(&mut self) {
        self.endpoints.sort_by_key(|e| e.ip);
    }
}
