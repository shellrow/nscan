use crate::endpoint::{Endpoint, EndpointResult};
use nex::packet::frame::Frame;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod domain;
pub mod host;
pub mod interface;
pub mod ping;
pub mod port;

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
        self.endpoints
            .iter()
            .filter_map(|e| e.active_endpoint())
            .collect()
    }

    /// Sort the endpoints by their IP addresses.
    pub fn sort_endpoints(&mut self) {
        self.endpoints.sort_by_key(|e| e.ip);
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape terminal controls in untrusted names and remote service banners.
pub fn terminal_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for ch in text.chars() {
        if (ch.is_control() && ch != '\n' && ch != '\t')
            || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            output.extend(ch.escape_default());
        } else {
            output.push(ch);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    #[test]
    fn terminal_output_escapes_remote_control_sequences() {
        let text = super::terminal_text("banner\x1b[2J\r\u{202e}\n");
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\r'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.ends_with('\n'));
    }
}
