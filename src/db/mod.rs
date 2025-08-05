pub mod model;
pub mod oui;
use crate::packet::frame::PacketFrame;
use ndb_oui::OuiDb;
use ndb_tcp_service::TcpServiceDb;

use crate::config;
use crate::ip;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};
use anyhow::Result;

pub static OUI_DB: OnceLock<RwLock<OuiDb>> = OnceLock::new();
pub static TCP_SERVICE_DB: OnceLock<RwLock<TcpServiceDb>> = OnceLock::new();

/// Initialize all databases
pub fn init_databases() -> Result<()> {
    init_oui_db()?;
    init_tcp_service_db()?;
    Ok(())
}

pub fn init_oui_db() -> Result<()> {
    // Initialize OUI database
    let oui_db = OuiDb::bundled();
    OUI_DB
        .set(RwLock::new(oui_db))
        .map_err(|_| anyhow::anyhow!("Failed to set OUI_DB in OnceLock"))?;
    Ok(())
}

pub fn init_tcp_service_db() -> Result<()> {
    // Initialize TCP Service database
    let tcp_service_db = TcpServiceDb::bundled();
    TCP_SERVICE_DB
        .set(RwLock::new(tcp_service_db))
        .map_err(|_| anyhow::anyhow!("Failed to set TCP_SERVICE_DB in OnceLock"))?;
    Ok(())
}

/* pub fn get_oui_db() -> OuiDb {
    OuiDb::bundled()
}

pub fn get_tcp_service_db() -> TcpServiceDb {
    TcpServiceDb::bundled()
} */

pub fn get_default_ports() -> Vec<u16> {
    let default_ports: Vec<u16> = bincode::deserialize(config::DEFAULT_PORTS_BIN).unwrap_or(vec![]);
    default_ports
}

pub fn get_wellknown_ports() -> Vec<u16> {
    let wellknown_ports: Vec<u16> =
        bincode::deserialize(config::WELLKNOWN_PORTS_BIN).unwrap_or(vec![]);
    wellknown_ports
}

pub fn get_http_ports() -> Vec<u16> {
    let http_ports: Vec<u16> = bincode::deserialize(config::HTTP_PORTS_BIN).unwrap_or(vec![]);
    http_ports
}

pub fn get_https_ports() -> Vec<u16> {
    let https_ports: Vec<u16> = bincode::deserialize(config::HTTPS_PORTS_BIN).unwrap_or(vec![]);
    https_ports
}

pub fn get_os_ttl_map() -> HashMap<u8, String> {
    let mut os_ttl_map: HashMap<u8, String> = HashMap::new();
    let ds_os_ttl: Vec<model::OsTtl> = bincode::deserialize(config::OS_TTL_BIN).unwrap_or(vec![]);
    for os_ttl in ds_os_ttl {
        os_ttl_map.insert(os_ttl.initial_ttl, os_ttl.os_description);
    }
    os_ttl_map
}

pub fn get_os_ttl_list() -> Vec<model::OsTtl> {
    let ds_os_ttl: Vec<model::OsTtl> = bincode::deserialize(config::OS_TTL_BIN).unwrap_or(vec![]);
    ds_os_ttl
}

pub fn get_subdomain() -> Vec<String> {
    let subdomain: Vec<String> = bincode::deserialize(config::SUBDOMAIN_BIN).unwrap_or(vec![]);
    subdomain
}

pub fn get_os_family_fingerprints() -> Vec<model::OsFamilyFingerprint> {
    let ds_os_fingerprints: Vec<model::OsFamilyFingerprint> =
        bincode::deserialize(config::OS_FAMILY_FINGERPRINT_BIN).unwrap_or(vec![]);
    ds_os_fingerprints
}

pub fn get_os_family_list() -> Vec<String> {
    let os_families: Vec<String> = bincode::deserialize(config::OS_FAMILY_BIN).unwrap_or(vec![]);
    os_families
}

pub fn is_vm_fingerprint(fingerprint: &model::OsFingerprint) -> bool {
    if fingerprint.os_family == "Player".to_string()
        && fingerprint.device_type == "specialized".to_string()
    {
        return true;
    }
    false
}

pub fn verify_os_family_fingerprint(fingerprint: &PacketFrame, in_vm: bool) -> model::OsFamilyFingerprint {
    let os_family_list: Vec<String> = get_os_family_list();
    let os_family_fingerprints: Vec<model::OsFamilyFingerprint> = get_os_family_fingerprints();

    // 0. Check TTL
    let os_ttl_list: Vec<model::OsTtl> = get_os_ttl_list();
    let initial_ttl = if let Some(ipv4_header) = &fingerprint.ipv4_header {
        ip::guess_initial_ttl(ipv4_header.ttl)
    } else {
        if let Some(ipv6_header) = &fingerprint.ipv6_header {
            ip::guess_initial_ttl(ipv6_header.hop_limit)
        } else {
            0
        }
    };
    let mut tcp_window_size = 0;
    let mut tcp_options: Vec<String> = vec![];
    if let Some(ref tcp_header) = fingerprint.tcp_header {
        tcp_window_size = tcp_header.window;
        for option in &tcp_header.options {
            tcp_options.push(option.kind().name().to_string());
        }
    }
    let tco_option_pattern = tcp_options.join("-");
    let mut os_ttl_info: model::OsTtl = model::OsTtl {
        initial_ttl: initial_ttl,
        os_description: String::new(),
        os_family: String::new(),
    };
    for os_ttl in os_ttl_list {
        if os_ttl.initial_ttl == initial_ttl {
            os_ttl_info.initial_ttl = os_ttl.initial_ttl;
            os_ttl_info.os_description = os_ttl.os_description;
            os_ttl_info.os_family = os_ttl.os_family;
        }
    }
    // 1. Select OS Fingerprint that match tcp_window_size and tcp_option_pattern
    let mut matched_fingerprints: Vec<model::OsFamilyFingerprint> = vec![];
    for f in &os_family_fingerprints {
        let mut window_size_match: bool = false;
        let mut option_pattern_match: bool = false;
        if f.tcp_window_sizes.contains(&tcp_window_size) {
            window_size_match = true;
        }
        for option_pattern in &f.tcp_option_patterns {
            if option_pattern == &tco_option_pattern {
                option_pattern_match = true;
            }
        }
        if window_size_match && option_pattern_match {
            matched_fingerprints.push(f.clone());
        }
    }
    if matched_fingerprints.len() == 1 {
        return matched_fingerprints[0].clone();
    } else if matched_fingerprints.len() > 1 {
        // Check VM Fingerprint
        if in_vm {
            for f in &matched_fingerprints {
                if &f.os_family == "Player" {
                    let mut vmf = f.clone();
                    vmf.os_family = format!("{} (Probably in VM Network)", vmf.os_family);
                    return vmf;
                }
            }
        }
        // Search fingerprint that match general OS Family
        matched_fingerprints.reverse();
        for f in &matched_fingerprints {
            if os_ttl_info.os_family == f.os_family.to_lowercase() {
                return f.clone();
            }
        }
        for f in matched_fingerprints {
            if os_family_list.contains(&f.os_family) {
                return f;
            }
        }
    }
    // 2. Select OS Fingerprint that match tcp_option_pattern and have most closely tcp_window_size
    let mut matched_fingerprints: Vec<model::OsFamilyFingerprint> = vec![];
    for f in os_family_fingerprints {
        let mut window_size_match: bool = false;
        let mut option_pattern_match: bool = false;
        for window_size in &f.tcp_window_sizes {
            if tcp_window_size - 100 < *window_size && *window_size < tcp_window_size + 100 {
                window_size_match = true;
            }
        }
        for option_pattern in &f.tcp_option_patterns {
            if option_pattern == &tco_option_pattern {
                option_pattern_match = true;
            }
        }
        if window_size_match && option_pattern_match {
            matched_fingerprints.push(f.clone());
        }
    }
    if matched_fingerprints.len() == 1 {
        return matched_fingerprints[0].clone();
    } else if matched_fingerprints.len() > 1 {
        // Check VM Fingerprint
        if in_vm {
            for f in &matched_fingerprints {
                if &f.os_family == "Player" {
                    let mut vmf = f.clone();
                    vmf.os_family = format!("{} (Probably in VM network)", vmf.os_family);
                    return vmf;
                }
            }
        }
        // Search fingerprint that match general OS Family
        matched_fingerprints.reverse();
        for f in &matched_fingerprints {
            if os_ttl_info.os_family == f.os_family.to_lowercase() {
                return f.clone();
            }
        }
        for f in matched_fingerprints {
            if os_family_list.contains(&f.os_family) {
                return f;
            }
        }
    }
    // 3. from TTL
    return model::OsFamilyFingerprint {
        os_family: os_ttl_info.os_family,
        tcp_window_sizes: vec![tcp_window_size],
        tcp_option_patterns: vec![tco_option_pattern],
    };
}

pub fn get_os_family(
    fingerprint: &PacketFrame,
    os_family_list: &Vec<String>,
    os_family_fingerprints: &Vec<model::OsFamilyFingerprint>,
    in_vm: bool
) -> model::OsFamilyFingerprint {
    // 0. Check TTL
    let os_ttl_list: Vec<model::OsTtl> = get_os_ttl_list();
    let initial_ttl = if let Some(ipv4_header) = &fingerprint.ipv4_header {
        ip::guess_initial_ttl(ipv4_header.ttl)
    } else {
        if let Some(ipv6_header) = &fingerprint.ipv6_header {
            ip::guess_initial_ttl(ipv6_header.hop_limit)
        } else {
            0
        }
    };
    let mut tcp_window_size = 0;
    let mut tcp_options: Vec<String> = vec![];
    if let Some(ref tcp_header) = fingerprint.tcp_header {
        tcp_window_size = tcp_header.window;
        for option in &tcp_header.options {
            tcp_options.push(option.kind().name().to_string());
        }
    }
    let tco_option_pattern = tcp_options.join("-");
    let mut os_ttl_info: model::OsTtl = model::OsTtl {
        initial_ttl: initial_ttl,
        os_description: String::new(),
        os_family: String::new(),
    };
    for os_ttl in os_ttl_list {
        if os_ttl.initial_ttl == initial_ttl {
            os_ttl_info.initial_ttl = os_ttl.initial_ttl;
            os_ttl_info.os_description = os_ttl.os_description;
            os_ttl_info.os_family = os_ttl.os_family;
        }
    }
    // 1. Select OS Fingerprint that match tcp_window_size and tcp_option_pattern
    let mut matched_fingerprints: Vec<model::OsFamilyFingerprint> = vec![];
    for f in os_family_fingerprints {
        let mut window_size_match: bool = false;
        let mut option_pattern_match: bool = false;
        if f.tcp_window_sizes.contains(&tcp_window_size) {
            window_size_match = true;
        }
        for option_pattern in &f.tcp_option_patterns {
            if option_pattern == &tco_option_pattern {
                option_pattern_match = true;
            }
        }
        if window_size_match && option_pattern_match {
            matched_fingerprints.push(f.clone());
        }
    }
    if matched_fingerprints.len() == 1 {
        return matched_fingerprints[0].clone();
    } else if matched_fingerprints.len() > 1 {
        // Check VM Fingerprint
        if in_vm {
            for f in &matched_fingerprints {
                if &f.os_family == "Player" {
                    let mut vmf = f.clone();
                    vmf.os_family = format!("{} (Probably in VM Network)", vmf.os_family);
                    return vmf;
                }
            }
        }
        // Search fingerprint that match general OS Family
        matched_fingerprints.reverse();
        for f in &matched_fingerprints {
            if os_ttl_info.os_family == f.os_family.to_lowercase() {
                return f.clone();
            }
        }
        for f in matched_fingerprints {
            if os_family_list.contains(&f.os_family) {
                return f;
            }
        }
    }
    // 2. Select OS Fingerprint that match tcp_option_pattern and have most closely tcp_window_size
    let mut matched_fingerprints: Vec<model::OsFamilyFingerprint> = vec![];
    for f in os_family_fingerprints {
        let mut window_size_match: bool = false;
        let mut option_pattern_match: bool = false;
        for window_size in &f.tcp_window_sizes {
            if tcp_window_size - 100 < *window_size && *window_size < tcp_window_size + 100 {
                window_size_match = true;
            }
        }
        for option_pattern in &f.tcp_option_patterns {
            if option_pattern == &tco_option_pattern {
                option_pattern_match = true;
            }
        }
        if window_size_match && option_pattern_match {
            matched_fingerprints.push(f.clone());
        }
    }
    if matched_fingerprints.len() == 1 {
        return matched_fingerprints[0].clone();
    } else if matched_fingerprints.len() > 1 {
        // Check VM Fingerprint
        if in_vm {
            for f in &matched_fingerprints {
                if &f.os_family == "Player" {
                    let mut vmf = f.clone();
                    vmf.os_family = format!("{} (Probably in VM network)", vmf.os_family);
                    return vmf;
                }
            }
        }
        // Search fingerprint that match general OS Family
        matched_fingerprints.reverse();
        for f in &matched_fingerprints {
            if os_ttl_info.os_family == f.os_family.to_lowercase() {
                return f.clone();
            }
        }
        for f in matched_fingerprints {
            if os_family_list.contains(&f.os_family) {
                return f;
            }
        }
    }
    // 3. from TTL
    return model::OsFamilyFingerprint {
        os_family: os_ttl_info.os_family,
        tcp_window_sizes: vec![tcp_window_size],
        tcp_option_patterns: vec![tco_option_pattern],
    };
}

// return HashMap<IpAddr, String(OS Family)>
pub fn get_fingerprint_map(fingerprints: &Vec<PacketFrame>, in_vm: bool) -> HashMap<IpAddr, String> {
    let mut fingerprint_map: HashMap<IpAddr, String> = HashMap::new();
    let os_family_list: Vec<String> = get_os_family_list();
    let os_family_fingerprints: Vec<model::OsFamilyFingerprint> = get_os_family_fingerprints();
    for f in fingerprints {
        let os_fingerprint = get_os_family(&f, &os_family_list, &os_family_fingerprints, in_vm);
        if let Some(ipv4_header) = &f.ipv4_header {
            fingerprint_map.insert(IpAddr::V4(ipv4_header.source), os_fingerprint.os_family);
        } else {
            if let Some(ipv6_header) = &f.ipv6_header {
                fingerprint_map.insert(IpAddr::V6(ipv6_header.source), os_fingerprint.os_family);
            }
        }
    }
    fingerprint_map
}
