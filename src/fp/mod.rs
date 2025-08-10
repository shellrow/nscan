use std::{collections::HashMap, net::IpAddr};

use nex::packet::tcp::{TcpHeader, TcpOptionKind};
use serde::{Deserialize, Serialize};

use crate::{db::{self, model::{Entry, OsDbIndex}}, packet::frame::PacketFrame};

pub mod setting;

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

/// OS families for classification
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OsFamily { Windows, Linux, Bsd, Darwin, Solaris, NetworkOs, Embedded, Unknown }

impl OsFamily {
    pub fn as_str(&self) -> &str {
        match self {
            OsFamily::Windows => "Windows",
            OsFamily::Linux => "Linux",
            OsFamily::Bsd => "Bsd",
            OsFamily::Darwin => "Darwin",
            OsFamily::Solaris => "Solaris",
            OsFamily::NetworkOs => "NetworkOs",
            OsFamily::Embedded => "Embedded",
            OsFamily::Unknown => "Unknown",
        }
    }
}

/// Signature features extracted from a packet frame
#[derive(Debug)]
pub struct SignatureFeatures {
    pub order_key: String,
    pub set_key: String,
    pub has_ts: bool,
    pub has_sack: bool,
    pub has_ws: bool,
    pub win_bucket: String,
    pub ttl_class: Option<u8>,
}

/// Extracts TCP options from a PacketFrame and compresses NOP options.
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

    // Compress consecutive NOPs
    let mut out = Vec::with_capacity(toks.len());
    let mut prev_nop = false;
    for t in toks {
        if t == "NOP" {
            if !prev_nop { out.push(t) }
            prev_nop = true;
        } else {
            prev_nop = false;
            out.push(t);
        }
    }
    out
}

fn order_key(tokens: &[&str]) -> String {
    tokens.join(",")
}

fn set_key(tokens: &[&str]) -> String {
    // Order options by priority, then alphabetically
    const PRI: [&str; 5] = ["MSS","SACK","TS","WS","NOP"];
    use std::collections::BTreeSet;

    let set: BTreeSet<&str> = tokens.iter().copied().collect();
    let mut head: Vec<&str> = PRI.iter().copied().filter(|t| set.contains(*t)).collect();
    let mut tail: Vec<&str> = set.difference(&PRI.iter().copied().collect()).copied().collect();
    tail.sort_unstable();
    head.extend(tail);
    format!("{{{}}}", head.join(","))
}

fn win_bucket(tcp: &TcpHeader) -> String {
    let v = u16::from_be(tcp.window);
    // Map common window sizes to human-readable names
    match v {
        65535 | 5792 | 8192 | 16384 | 4096 | 32768 | 5840 | 4128 | 0 | 14480 => v.to_string(),
        _ => "other".to_string(),
    }
}

/// Initial TTL class based on IPv4 or IPv6 header
fn ttl_class_from_packet(frame: &PacketFrame) -> Option<u8> {
    // Extract TTL from IPv4 or Hop Limit from IPv6
    if let Some(ip) = &frame.ipv4_header {
        let ttl = ip.ttl;
        return Some(match ttl {
            0..=64   => 64,
            65..=128 => 128,
            _        => 255,
        });
    }
    if let Some(ip6) = &frame.ipv6_header {
        let h = ip6.hop_limit;
        return Some(match h {
            0..=64   => 64,
            65..=128 => 128,
            _        => 255,
        });
    }
    None
}

pub fn extract_signature(frame: &PacketFrame) -> Option<SignatureFeatures> {
    let tcp = frame.tcp_header.as_ref()?;
    let tokens = tcp_option_tokens(tcp);
    let sig = SignatureFeatures {
        order_key: order_key(&tokens),
        set_key: set_key(&tokens),
        has_ts: tokens.contains(&"TS"),
        has_sack: tokens.contains(&"SACK"),
        has_ws: tokens.contains(&"WS"),
        win_bucket: win_bucket(tcp),
        ttl_class: ttl_class_from_packet(frame),
    };
    Some(sig)
}

pub struct MatchResult {
    pub family: String,
    // 0..=100
    pub confidence: u8,
    pub evidence: String,
}

fn map_family(s: &str) -> OsFamily {
    match s {
        "Windows" => OsFamily::Windows,
        "Linux" => OsFamily::Linux,
        "Bsd" => OsFamily::Bsd,
        "Darwin" => OsFamily::Darwin,
        "Solaris" => OsFamily::Solaris,
        "NetworkOs" => OsFamily::NetworkOs,
        "Embedded" => OsFamily::Embedded,
        _ => OsFamily::Unknown,
    }
}

pub fn classify(frame: &PacketFrame, idx: &OsDbIndex, ttl_table: &HashMap<OsFamily, u8>) -> MatchResult {
    let Some(sig) = extract_signature(frame) else {
        // If no TCP options, we can't classify. So get family from TTL if available.
        let ttl_class_map = crate::db::get_ttl_class_map();
        if let Some(initial_ttl) = ttl_class_from_packet(frame) {
            if let Some(class) = ttl_class_map.get(&initial_ttl) {
                return MatchResult {
                    family: class.to_string(),
                    confidence: 100,
                    evidence: "TTL match".to_string(),
                };
            }
        }
        // No signature and no TTL match, we can't classify
        return MatchResult {
            family: OsFamily::Unknown.as_str().to_string(),
            confidence: 0,
            evidence: "no_signature".into(),
        };
    };

    // 1) order_key + win_bucket exact match
    // This is the most reliable match, as it uses the exact ordered TCP options and window size.
    if let Some(cands) = idx.by_order.get(&(sig.order_key.clone(), sig.win_bucket.clone())) {
        // Additional confidence based on flags and TTL class
        let mut best = None::<(&Entry, f32)>;
        for e in cands {
            let mut conf = e.confidence;
            // Add confidence based on flags
            if e.signature.has_ts == sig.has_ts { conf += 0.03; }
            if e.signature.has_sack == sig.has_sack { conf += 0.03; }
            if e.signature.has_ws == sig.has_ws { conf += 0.03; }

            // Adjust based on TTL class if available (Windows=128, Linux/BSD/Darwin=64, others=255)
            if let Some(ttl) = sig.ttl_class {
                let fam = map_family(&e.suggested_family);
                if let Some(exp) = ttl_table.get(&fam) {
                    if *exp == ttl { conf += 0.04; }
                }
            }

            if best.map_or(true, |b| conf > b.1) {
                best = Some((e, conf));
            }
        }
        // If we found a best match, return it
        if let Some((e, conf)) = best {
            let family = map_family(&e.suggested_family);
            let confidence = (conf * 100.0).clamp(0.0, 100.0) as u8;
            // Threshold: 75 or higher for assertion, below that for candidate display (adjust according to your policy)
            if confidence >= 75 {
                return MatchResult {
                    family: family.as_str().to_string(),
                    confidence,
                    evidence: format!("option_order+window_size match '{}'", sig.order_key),
                };
            }
        }
    }

    // 2) order not exact, but set_key + win_bucket match
    if let Some(cands) = idx.by_set_win.get(&(sig.set_key.clone(), sig.win_bucket.clone())) {
        let mut best = None::<(&Entry, f32)>;
        for e in cands {
            // Confidence starts at entry confidence, then adjust based on flags and TTL class
            let mut conf = e.confidence - 0.1;
            // Add confidence based on flags
            if e.signature.has_ts == sig.has_ts { conf += 0.03; }
            if e.signature.has_sack == sig.has_sack { conf += 0.03; }
            if e.signature.has_ws == sig.has_ws { conf += 0.03; }

            if let Some(ttl) = sig.ttl_class {
                let fam = map_family(&e.suggested_family);
                if let Some(exp) = ttl_table.get(&fam) {
                    if *exp == ttl { conf += 0.04; }
                }
            }

            if best.map_or(true, |b| conf > b.1) {
                best = Some((e, conf));
            }
        }
        if let Some((e, conf)) = best {
            let family = map_family(&e.suggested_family);
            let confidence = (conf * 100.0).clamp(0.0, 100.0) as u8;
            // Threshold: 50 or higher for assertion, below that for candidate display
            return MatchResult {
                family: family.as_str().to_string(),
                confidence,
                evidence: format!("option_set+window_size match '{}','{}'", sig.set_key, sig.win_bucket),
            };
        }
    }

    // 3) No match found, return unknown
    MatchResult { family: OsFamily::Unknown.as_str().to_string(), confidence: 0, evidence: "no_match".into() }
}

pub fn get_fingerprint(frame: &PacketFrame) -> MatchResult {
    let idx = OsDbIndex::from(db::get_os_family_db());
    let ttl_table = db::get_family_ttl_map();
    classify(frame, &idx, &ttl_table)
}

// return HashMap<IpAddr, String(OS Family)>
pub fn get_fingerprint_map(fingerprints: &Vec<PacketFrame>) -> HashMap<IpAddr, String> {
    let idx = OsDbIndex::from(db::get_os_family_db());
    let ttl_table = db::get_family_ttl_map();
    let mut result: HashMap<IpAddr, String> = HashMap::new();

    for frame in fingerprints {
        if let Some(ip) = &frame.ipv4_header {
            let ip_addr = ip.source;
            let match_result = classify(frame, &idx, &ttl_table);
            result.insert(ip_addr.into(), format!("{} ({})", match_result.family, match_result.evidence));
        } else if let Some(ip6) = &frame.ipv6_header {
            let ip_addr = ip6.source;
            let match_result = classify(frame, &idx, &ttl_table);
            result.insert(ip_addr.into(), format!("{} ({})", match_result.family, match_result.evidence));
        }
    }

    result
}
