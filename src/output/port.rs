use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{Duration, SystemTime},
};

use crate::{
    endpoint::{EndpointResult, Port, PortState},
    output::{ScanResult, tree_label},
    service::ServiceDetectionResult,
};
use serde::{Deserialize, Serialize};
use termtree::Tree;

/// Comprehensive scan report combining various scan results.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ScanReport {
    pub meta: ReportMeta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identification: Option<crate::nmap::Identification>,
    /// Keep IP as key for merging
    #[serde(default)]
    pub endpoints: BTreeMap<IpAddr, EndpointResult>,
    #[serde(default)]
    pub stats: ReportStats,
}

/// Metadata about the scan report
#[derive(Serialize, Deserialize, Debug)]
pub struct ReportMeta {
    pub tool: String,    // "nscan"
    pub version: String, // env!("CARGO_PKG_VERSION")
    pub started_at: SystemTime,
    pub finished_at: Option<SystemTime>,
}

impl Default for ReportMeta {
    fn default() -> Self {
        Self {
            tool: "nscan".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            started_at: SystemTime::now(),
            finished_at: None,
        }
    }
}

/// Statistics about the scan
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ReportStats {
    pub hosts_total: usize,
    pub ports_scanned: usize,
    pub open_ports: usize,
    pub duration_scan: Option<Duration>,    // PortScan
    pub duration_service: Option<Duration>, // ServiceDetect
}

impl ScanReport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply port scan results: merge endpoints, update stats
    pub fn apply_port_scan(&mut self, ps: ScanResult) {
        for ep in ps.endpoints {
            // Upsert
            self.endpoints
                .entry(ep.ip)
                .and_modify(|e| e.merge(ep.clone()))
                .or_insert_with(|| ep);
        }
        self.stats.duration_scan =
            Some(self.stats.duration_scan.unwrap_or_default() + ps.scan_time);
        self.recompute_stats();
    }

    /// Apply service detection results: merge service info, update stats
    pub fn apply_service_detection(&mut self, sd: ServiceDetectionResult) {
        for r in sd.results {
            let Some(ep) = self.endpoints.get_mut(&r.ip) else {
                continue;
            };
            // Upsert port result
            let port_key = Port {
                number: r.port,
                transport: r.transport,
            };
            if let Some(pr) = ep.ports.get_mut(&port_key) {
                pr.service = r.service_info;
            }
        }
        self.stats.duration_service = Some(sd.scan_time);
        self.recompute_stats();
    }

    /// Fill missing observations with identification data, keeping native results first.
    pub fn apply_identification(&mut self, mut details: crate::nmap::Identification) {
        for host in details.hosts.drain(..) {
            let Some(ep) = self.endpoints.get_mut(&host.ip) else {
                continue;
            };
            for port in host.ports {
                let Some(transport) = crate::endpoint::TransportProtocol::parse(&port.protocol)
                else {
                    continue;
                };
                let Some(pr) = ep.ports.get_mut(&Port::new(port.port, transport)) else {
                    continue;
                };
                if transport != crate::endpoint::TransportProtocol::Tcp
                    || pr.state != PortState::Open
                {
                    continue;
                }
                if let Some(service) = port.service {
                    let existing = &mut pr.service;
                    existing.name = existing.name.take().or(service.name);
                    existing.product = existing.product.take().or(service.product);
                    existing.version = existing.version.take().or(service.version);
                    for cpe in service.cpes {
                        if !existing.cpes.contains(&cpe) {
                            existing.cpes.push(cpe);
                        }
                    }
                }
            }
            if ep.os.family.is_none()
                && let Some(os) = host.os_matches.into_iter().max_by_key(|os| os.accuracy)
            {
                ep.os.family = Some(os.name);
                ep.os.confidence = Some(f32::from(os.accuracy) / 100.0);
                for class in os.classes {
                    for cpe in class.cpes {
                        if !ep.cpes.contains(&cpe) {
                            ep.cpes.push(cpe);
                        }
                    }
                }
            }
        }
        self.identification = Some(details);
    }

    pub fn finish(&mut self) {
        self.meta.finished_at = Some(SystemTime::now());
        for ep in self.endpoints.values_mut() {
            for (port, pr) in &mut ep.ports {
                pr.service.registered_name =
                    crate::db::service::registered_name(port.number, port.transport);
            }
        }
    }
    pub fn as_vec(&self) -> Vec<&EndpointResult> {
        self.endpoints.values().collect()
    }

    fn recompute_stats(&mut self) {
        self.stats.hosts_total = self.endpoints.len();
        let mut ports_scanned = 0usize;
        let mut open_ports = 0usize;
        for ep in self.endpoints.values() {
            ports_scanned += ep.ports.len();
            open_ports += ep
                .ports
                .values()
                .filter(|p| p.state == PortState::Open)
                .count();
        }
        self.stats.ports_scanned = ports_scanned;
        self.stats.open_ports = open_ports;
    }
}

/// Print the merged scan observations.
pub fn print_report_tree(rep: &ScanReport) {
    let mut root = Tree::new(tree_label("Scan report(s)"));
    for ep in rep.endpoints.values() {
        let title = if let Some(hn) = &ep.hostname {
            format!("{} ({})", ep.ip, hn)
        } else {
            format!("{}", ep.ip)
        };
        let mut ep_root = Tree::new(title);

        if let Some(ttl) = ep.os.ttl_observed {
            ep_root.push(Tree::new(format!("observed TTL: {ttl}")));
        }

        if let Some(os) = &ep.os.family {
            let confidence = ep
                .os
                .confidence
                .map(|value| format!(" ({:.0}%)", value * 100.0))
                .unwrap_or_default();
            ep_root.push(Tree::new(format!("OS: {os}{confidence}")));
        }

        // Ports
        for (port, pr) in &ep.ports {
            if pr.state != PortState::Open {
                continue;
            }
            let mut pnode = Tree::new(tree_label(format!(
                "{}/{}",
                port.number,
                port.transport.as_str().to_uppercase()
            )));
            pnode.push(Tree::new(tree_label(format!("state: {:?}", pr.state))));
            if let Some(name) = &pr.service.name {
                pnode.push(Tree::new(tree_label(format!("service: {}", name))));
            }
            if let Some(label) = &pr.service.registered_name
                && pr.service.name.as_ref() != Some(label)
            {
                pnode.push(Tree::new(format!("registered service: {label}")));
            }
            if let Some(server) = &pr.service.server_header {
                pnode.push(Tree::new(format!("HTTP Server header: {server}")));
            }
            if let Some(b) = &pr.service.banner {
                pnode.push(Tree::new(tree_label(format!("banner: {}", b))));
            }
            if let Some(p) = &pr.service.product {
                pnode.push(Tree::new(tree_label(format!("product: {}", p))));
            }
            if let Some(version) = &pr.service.version {
                pnode.push(Tree::new(format!("version: {version}")));
            }
            if !pr.service.cpes.is_empty() {
                let mut c = Tree::new(tree_label("cpes"));
                for cp in &pr.service.cpes {
                    c.push(Tree::new(cp.clone()));
                }
                pnode.push(c);
            }
            ep_root.push(pnode);
        }

        root.push(ep_root);
    }
    if let Some(details) = &rep.identification {
        for warning in &details.warnings {
            root.push(Tree::new(format!("warning: {warning}")));
        }
        if let Some(error) = &details.error {
            root.push(Tree::new(format!("warning: {error}")));
        }
    }
    println!("{}", crate::output::terminal_text(&root.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{PortResult, ServiceInfo, TransportProtocol};

    #[test]
    fn identification_fills_gaps_and_preserves_native_observations() {
        let ip = "127.0.0.1".parse().unwrap();
        let port = Port::new(22, TransportProtocol::Tcp);
        let mut ep = EndpointResult::new(ip);
        ep.os.ttl_observed = Some(64);
        ep.upsert_port(PortResult {
            port,
            state: PortState::Open,
            rtt_ms: Some(10),
            service: ServiceInfo {
                name: Some("native service".into()),
                product: Some("native product".into()),
                cpes: vec!["shared".into()],
                ..Default::default()
            },
        });
        let mut report = ScanReport::new();
        report.endpoints.insert(ip, ep);
        let details = || {
            serde_json::from_value(serde_json::json!({
                "source": "nmap", "version": "7.99", "complete": true, "error": null,
                "hosts": [{"ip": "127.0.0.1", "ports": [{
                    "port": 22, "protocol": "tcp", "state": {"state": "closed"},
                    "service": {"name": "external", "product": "external product",
                        "version": "9.9", "cpes": ["shared", "additional", "additional"]}
                }], "os_matches": [{"name": "Linux", "accuracy": 95}]}]
            }))
            .unwrap()
        };
        report.apply_identification(details());
        report.apply_identification(details());
        let ep = &report.endpoints[&ip];
        let pr = &ep.ports[&port];
        assert_eq!(pr.state, PortState::Open);
        assert_eq!(pr.rtt_ms, Some(10));
        assert_eq!(pr.service.name.as_deref(), Some("native service"));
        assert_eq!(pr.service.product.as_deref(), Some("native product"));
        assert_eq!(pr.service.version.as_deref(), Some("9.9"));
        assert_eq!(pr.service.cpes, ["shared", "additional"]);
        assert_eq!(ep.os.family.as_deref(), Some("Linux"));
        assert_eq!(ep.os.ttl_observed, Some(64));
        report.endpoints.get_mut(&ip).unwrap().os.family = Some("native OS".into());
        report.apply_identification(details());
        assert_eq!(
            report.endpoints[&ip].os.family.as_deref(),
            Some("native OS")
        );
        assert!(report.identification.unwrap().hosts.is_empty());
    }
}
