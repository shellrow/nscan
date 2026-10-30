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

/// Print observations and optional external identification separately.
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
            if let Some(label) = &pr.service.registered_name {
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
        let mut node = Tree::new(format!(
            "Nmap {} ({})",
            details.version,
            if details.complete {
                "complete"
            } else {
                "incomplete"
            }
        ));
        for host in &details.hosts {
            let mut host_node = Tree::new(host.ip.to_string());
            for port in &host.ports {
                if let Some(service) = &port.service {
                    host_node.push(Tree::new(format!(
                        "{}/{}: {} {} {}",
                        port.port,
                        port.protocol,
                        service.name.as_deref().unwrap_or("unknown"),
                        service.product.as_deref().unwrap_or(""),
                        service.version.as_deref().unwrap_or("")
                    )));
                }
            }
            for os in &host.os_matches {
                host_node.push(Tree::new(format!("OS: {} ({}%)", os.name, os.accuracy)));
            }
            node.push(host_node);
        }
        for warning in &details.warnings {
            node.push(Tree::new(format!("warning: {warning}")));
        }
        if let Some(error) = &details.error {
            node.push(Tree::new(error.clone()));
        }
        root.push(node);
    }
    println!("{}", crate::output::terminal_text(&root.to_string()));
}
