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

    let spec = spec.trim();
    if let Some(nstr) = spec.strip_prefix("top-") {
        let n: usize = nstr.parse()?;
        anyhow::ensure!(
            n > 0 && n <= 65535,
            "top port count must be between 1 and 65535"
        );
        for p in top_ports(n) {
            set.insert(Port::new(p, tr));
        }
    } else {
        for part in spec.split(',').map(str::trim) {
            if let Some((a, b)) = part.split_once('-') {
                let start: u16 = a.parse()?;
                let end: u16 = b.parse()?;
                anyhow::ensure!(start > 0, "port zero is not supported");
                if start > end {
                    bail!("invalid range: {part}");
                }
                for p in start..=end {
                    set.insert(Port::new(p, tr));
                }
            } else {
                let p: u16 = part.parse()?;
                anyhow::ensure!(p > 0, "port zero is not supported");
                set.insert(Port::new(p, tr));
            }
        }
    }
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_port_specs() {
        for invalid in ["", "0", "0-2", "80,", "80,,443", "top-0", "65536", "443-80"] {
            assert!(
                parse_ports(invalid, TransportProtocol::Tcp).is_err(),
                "{invalid}"
            );
        }
        let ports = parse_ports("443,80-81,80", TransportProtocol::Tcp).unwrap();
        assert_eq!(
            ports.iter().map(|p| p.number).collect::<Vec<_>>(),
            [80, 81, 443]
        );
    }
}
