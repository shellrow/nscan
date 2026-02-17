pub mod probe;

use crate::{output::port::OsProbeResult, probe::ProbeSetting};
use anyhow::Result;
use nex::packet::{
    frame::Frame,
    tcp::{TcpHeader, TcpOptionKind},
};
use serde::{Deserialize, Serialize};

/// OS Detector using TCP SYN packets
pub struct OsDetector {
    pub settings: ProbeSetting,
}

impl OsDetector {
    /// Construct a new OsDetector instance
    pub fn new(settings: ProbeSetting) -> Self {
        Self { settings }
    }

    /// Run the OS detection probe and return the results.
    pub async fn run(&self) -> Result<OsProbeResult> {
        probe::tcp::run_os_probe(self.settings.clone()).await
    }
}

/// Metadata about the OS database
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Meta {
    pub name: String,
    pub version: String,
}

/// A record in the OS signature database
#[derive(Serialize, Deserialize, Debug)]
struct OsSigRecord {
    signature: SignatureKey,
    cpe: Vec<String>,
}

/// TCP/IP signature keys for matching
#[derive(Serialize, Deserialize, Debug, Default)]
struct SignatureKey {
    order_key: Option<String>,
    set_key: Option<String>,
    win_bucket: Option<Vec<u16>>,
}

/// The OS database structure
#[derive(Serialize, Deserialize)]
pub struct OsDb {
    meta: Meta,
    signatures: Vec<OsSigRecord>,
}

/// Signature features extracted from a packet frame
#[derive(Debug)]
pub struct SignatureFeatures {
    pub order_key: String,
    pub set_key: String,
    pub window: u16,
    pub ttl_class: Option<u8>,
}

/// Result of OS matching
pub struct OsMatchResult {
    pub family: String,
    pub confidence: u8,
    pub evidence: String,
    pub cpes: Vec<String>,
}

impl OsMatchResult {
    pub fn new() -> Self {
        OsMatchResult {
            family: String::new(),
            confidence: 0,
            evidence: String::new(),
            cpes: Vec::new(),
        }
    }
}

/// OS class with initial TTL and description
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsClassTtl {
    pub os_class: OsClass,
    pub os_description: String,
    pub initial_ttl: u8,
}

/// OS classes for classification
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OsClass {
    UnixLike,
    Windows,
}

impl OsClass {
    pub fn as_str(&self) -> &str {
        match self {
            OsClass::UnixLike => "UnixLike",
            OsClass::Windows => "Windows",
        }
    }
}

/// Extracts TCP options from a Frame and compresses NOP options.
fn tcp_option_tokens(tcp: &TcpHeader) -> Vec<&'static str> {
    let mut toks = Vec::with_capacity(tcp.options.len());

    for opt in &tcp.options {
        let t = match opt.kind() {
            TcpOptionKind::MSS => "MSS",
            TcpOptionKind::SACK_PERMITTED => "SACK",
            TcpOptionKind::TIMESTAMPS => "TS",
            TcpOptionKind::WSCALE => "WS",
            TcpOptionKind::NOP => "NOP",
            _ => continue,
        };
        toks.push(t);
    }
    toks
}

/// Compress consecutive NOP options in TCP header
fn tcp_option_token_set(tcp: &TcpHeader) -> Vec<&'static str> {
    let mut toks = Vec::with_capacity(tcp.options.len());

    for opt in &tcp.options {
        let t = match opt.kind() {
            TcpOptionKind::MSS => "MSS",
            TcpOptionKind::SACK_PERMITTED => "SACK",
            TcpOptionKind::TIMESTAMPS => "TS",
            TcpOptionKind::WSCALE => "WS",
            TcpOptionKind::NOP => "NOP",
            _ => continue,
        };
        toks.push(t);
    }

    // Compress consecutive NOPs
    let mut out = Vec::with_capacity(toks.len());
    let mut prev_nop = false;
    for t in toks {
        if t == "NOP" {
            if !prev_nop {
                out.push(t)
            }
            prev_nop = true;
        } else {
            prev_nop = false;
            out.push(t);
        }
    }
    out
}

/// Create an order key string from TCP option tokens
fn order_key(tokens: &[&str]) -> String {
    tokens.join(",")
}

/// Create a set key string from TCP option tokens
fn set_key(tokens: &[&str]) -> String {
    // Order options by priority, then alphabetically
    const PRI: [&str; 5] = ["MSS", "SACK", "TS", "WS", "NOP"];
    use std::collections::BTreeSet;

    let set: BTreeSet<&str> = tokens.iter().copied().collect();
    let mut head: Vec<&str> = PRI.iter().copied().filter(|t| set.contains(*t)).collect();
    let mut tail: Vec<&str> = set
        .difference(&PRI.iter().copied().collect())
        .copied()
        .collect();
    tail.sort_unstable();
    head.extend(tail);
    format!("{{{}}}", head.join(","))
}

/// Initial TTL class based on IPv4 or IPv6 header
fn ttl_class_from_packet(frame: &Frame) -> Option<u8> {
    // Extract TTL from IPv4 or Hop Limit from IPv6
    if let Some(ip) = &frame.ip {
        if let Some(ipv4) = &ip.ipv4 {
            let ttl = ipv4.ttl;
            return Some(match ttl {
                0..=64 => 64,
                65..=128 => 128,
                _ => 255,
            });
        }
        if let Some(ipv6) = &ip.ipv6 {
            let h = ipv6.hop_limit;
            return Some(match h {
                0..=64 => 64,
                65..=128 => 128,
                _ => 255,
            });
        }
    }
    None
}

/// Extract signature features from a Frame
pub fn extract_signature(frame: &Frame) -> Option<SignatureFeatures> {
    if let Some(transport) = &frame.transport {
        if let Some(tcp) = &transport.tcp {
            let tokens = tcp_option_tokens(tcp);
            let token_set = tcp_option_token_set(tcp);
            let sig = SignatureFeatures {
                order_key: order_key(&tokens),
                set_key: set_key(&token_set),
                window: tcp.window,
                ttl_class: ttl_class_from_packet(frame),
            };
            return Some(sig);
        }
    }
    None
}

/// Derive a human-readable OS family name from CPE strings
fn family_from_cpe(cpes: &[String]) -> String {
    // Extract vendor and product from a CPE string
    for c in cpes {
        if let Some(rest) = c.strip_prefix("cpe:/") {
            // /o:vendor:product:...
            let mut parts = rest.split(':');
            let _part_type = parts.next(); // 'o' or 'a' or 'h'
            if let (Some(vendor), Some(product)) = (parts.next(), parts.next()) {
                return format!("{} {}", vendor, product);
            }
        }
    }
    String::new()
}

fn score_signature(sig: &SignatureKey, feat: &SignatureFeatures) -> (u8, Vec<&'static str>) {
    let mut score: u8 = 0;
    let mut evid: Vec<&'static str> = Vec::new();

    if let Some(ok) = &sig.order_key {
        if ok == &feat.order_key {
            score = score.saturating_add(60);
            evid.push("order");
        }
    }
    if let Some(sk) = &sig.set_key {
        if sk == &feat.set_key {
            score = score.saturating_add(40);
            evid.push("set");
        }
    }
    if let Some(buckets) = &sig.win_bucket {
        if buckets.iter().any(|&w| w == feat.window) {
            score = score.saturating_add(20);
            evid.push("win");
        }
    }
    if let Some(_ttl) = feat.ttl_class {
        score = score.saturating_add(10);
        evid.push("ttl?");
    }

    (score, evid)
}

pub fn match_tcpip_signatures(frame: &Frame) -> Option<OsMatchResult> {
    let os_db: &'static OsDb = crate::db::os::os_db();
    let feat = extract_signature(frame)?;

    let mut best: Option<(u8, &OsSigRecord, Vec<&'static str>)> = None;

    for rec in &os_db.signatures {
        if rec.signature.order_key.is_none()
            && rec.signature.set_key.is_none()
            && rec.signature.win_bucket.is_none()
        {
            continue;
        }

        let (score, evid) = score_signature(&rec.signature, &feat);
        let replace = match &best {
            None => true,
            Some((best_score, _best_rec, best_evid)) => {
                score > *best_score || (score == *best_score && evid.len() > best_evid.len())
            }
        };
        if replace {
            best = Some((score, rec, evid));
        }
    }

    let (score, rec, evid) = best?;
    if score < 40 {
        return None;
    }

    // Build the result
    let mut out = OsMatchResult::new();
    out.cpes = rec.cpe.clone();
    out.family = family_from_cpe(&out.cpes);
    out.confidence = score.min(100);
    out.evidence = {
        let mut parts = Vec::new();
        if evid.contains(&"order") {
            parts.push(format!("order={}", feat.order_key));
        }
        if evid.contains(&"set") {
            parts.push(format!("set={}", feat.set_key));
        }
        if evid.contains(&"win") {
            parts.push(format!("win={}", feat.window));
        }
        if let Some(ttl) = feat.ttl_class {
            if evid.contains(&"ttl?") {
                parts.push(format!("ttl~{}", ttl));
            }
        }
        if parts.is_empty() {
            "heuristic".to_string()
        } else {
            parts.join(", ")
        }
    };

    Some(out)
}
