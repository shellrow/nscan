use std::{
    collections::BTreeMap,
    net::IpAddr,
    time::{Duration, SystemTime},
};

use crate::{
    endpoint::{EndpointResult, Port, PortResult, PortState, ServiceInfo, TransportProtocol},
    output::{ScanResult, tree_label},
    service::{ServiceDetectionResult, probe::ServiceProbe},
};
use nex::packet::frame::Frame;
use serde::{Deserialize, Serialize};
use termtree::Tree;

/// Results of OS probing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsProbeResult {
    pub endpoints: Vec<EndpointResult>,
    pub probe_time: Duration,
    pub fingerprints: Vec<Frame>,
}

impl OsProbeResult {
    /// Construct a new, empty OsProbeResult.
    pub fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            probe_time: Duration::new(0, 0),
            fingerprints: Vec::new(),
        }
    }
}

/// Comprehensive scan report combining various scan results.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ScanReport {
    pub meta: ReportMeta,
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
    pub duration_os: Option<Duration>,      // OS probe
}

/// An attempt to probe a service on a port
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortProbeAttempt {
    pub probe_id: ServiceProbe,
    pub result: Result<ServiceInfo, String>,
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
        self.stats.duration_scan = Some(ps.scan_time);
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
            let pr = ep.ports.entry(port_key).or_insert_with(|| PortResult {
                port: port_key,
                state: PortState::Open,
                service: r.service_info.clone(),
                rtt_ms: None,
            });

            pr.state = PortState::Open;
            pr.port = port_key;
            pr.service = select_better_service(pr.service.clone(), r.service_info);
        }
        self.stats.duration_service = Some(sd.scan_time);
        self.recompute_stats();
    }

    /// Apply OS probe results: replace with the more confident one
    pub fn apply_os_probe(&mut self, osr: OsProbeResult) {
        for ep2 in osr.endpoints {
            if let Some(ep) = self.endpoints.get_mut(&ep2.ip) {
                ep.merge(ep2);
            } else {
                self.endpoints.insert(ep2.ip, ep2);
            }
        }
        self.stats.duration_os = Some(osr.probe_time);
        self.recompute_stats();
    }

    pub fn finish(&mut self) {
        self.meta.finished_at = Some(SystemTime::now());
        let tcp_svc_db = crate::db::service::tcp_service_db();
        let udp_svc_db = crate::db::service::udp_service_db();
        // check service name. if service name is not in result, set it.
        for ep in self.endpoints.values_mut() {
            for (port, pr) in &mut ep.ports {
                if pr.service.name.is_none() {
                    match port.transport {
                        TransportProtocol::Tcp => {
                            pr.service.name =
                                tcp_svc_db.get_name(port.number).map(|s| s.to_string());
                        }
                        TransportProtocol::Udp | TransportProtocol::Quic => {
                            pr.service.name =
                                udp_svc_db.get_name(port.number).map(|s| s.to_string());
                        }
                    }
                }
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

/// Choose the better ServiceInfo based on a simple scoring system.
fn select_better_service(cur: ServiceInfo, newv: ServiceInfo) -> ServiceInfo {
    let old_score = score_service(&cur);
    let new_score = score_service(&newv);
    if new_score >= old_score { newv } else { cur }
}

/// Score a ServiceInfo based on the presence of certain fields.
fn score_service(s: &ServiceInfo) -> usize {
    let mut sc = 0;
    if s.name.is_some() {
        sc += 1;
    }
    if s.product.is_some() {
        sc += 1;
    }
    if let Some(b) = &s.banner {
        sc += 1;
        // Check for HTTP 200 OK for additional points
        if b.contains("HTTP") && b.contains("200 OK") {
            sc += 1;
        }
    }
    sc += s.cpes.len();
    sc
}

/// Match and print OS detection results in a tree structure.
pub fn print_report_tree(rep: &ScanReport) {
    let mut root = Tree::new(tree_label("Scan report(s)"));
    for ep in rep.endpoints.values() {
        let title = if let Some(hn) = &ep.hostname {
            format!("{} ({})", ep.ip, hn)
        } else {
            format!("{}", ep.ip)
        };
        let mut ep_root = Tree::new(title);

        // OS
        if ep.os.family.is_some() || !ep.cpes.is_empty() {
            let mut os_node = Tree::new(tree_label("os"));
            if let Some(f) = &ep.os.family {
                os_node.push(Tree::new(tree_label(format!("family: {}", f))));
            }
            if let Some(v) = &ep.os.ttl_observed {
                os_node.push(Tree::new(tree_label(format!("TTL: {}", v))));
            }
            if !ep.cpes.is_empty() {
                let mut cpe_node = Tree::new(tree_label("cpes"));
                for c in &ep.cpes {
                    cpe_node.push(Tree::new(c.clone()));
                }
                os_node.push(cpe_node);
            }
            ep_root.push(os_node);
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
    println!("{}", root);
}
