use crate::endpoint::{Port, TransportProtocol};
use anyhow::{Result, bail};
use std::collections::BTreeSet;

/// Get top N ports from the default port list
fn top_ports(n: usize) -> Vec<u16> {
    let top_ports: Vec<u16> = crate::db::port::get_default_ports();
    top_ports.into_iter().take(n).collect()
}

/// Parse port specification string into a list of ports
pub fn parse_ports(spec: &str, tr: TransportProtocol) -> Result<Vec<Port>> {
    let mut set = BTreeSet::new();

    if let Some(nstr) = spec.strip_prefix("top-") {
        let n: usize = nstr.parse()?;
        for p in top_ports(n) {
            set.insert(Port::new(p, tr));
        }
    } else {
        for part in spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if let Some((a, b)) = part.split_once('-') {
                let start: u16 = a.parse()?;
                let end: u16 = b.parse()?;
                if start > end {
                    bail!("invalid range: {part}");
                }
                for p in start..=end {
                    set.insert(Port::new(p, tr));
                }
            } else {
                let p: u16 = part.parse()?;
                set.insert(Port::new(p, tr));
            }
        }
    }
    Ok(set.into_iter().collect())
}
