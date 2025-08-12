pub mod model;
pub mod oui;
use ndb_oui::OuiDb;
use ndb_tcp_service::TcpServiceDb;

use crate::config;
use crate::fp::{OsClass, OsFamily};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

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
    let default_ports: Vec<u16> = serde_json::from_str(config::DEFAULT_PORTS_JSON)
        .expect("Invalid default-ports.json format");
    default_ports
}

pub fn get_wellknown_ports() -> Vec<u16> {
    let wellknown_ports: Vec<u16> = serde_json::from_str(config::WELLKNOWN_PORTS_JSON)
        .expect("Invalid wellknown-ports.json format");
    wellknown_ports
}

pub fn get_http_ports() -> Vec<u16> {
    let http_ports: Vec<u16> =
        serde_json::from_str(config::HTTP_PORTS_JSON).expect("Invalid http-ports.json format");
    http_ports
}

pub fn get_https_ports() -> Vec<u16> {
    let https_ports: Vec<u16> =
        serde_json::from_str(config::HTTPS_PORTS_JSON).expect("Invalid https-ports.json format");
    https_ports
}

pub fn get_ttl_family_map() -> HashMap<u8, String> {
    let mut ttl_family_map: HashMap<u8, String> = HashMap::new();
    let ds_os_ttl: Vec<model::OsTtl> =
        serde_json::from_str(config::OS_TTL_JSON).expect("Invalid os-ttl.json format");
    for os_ttl in ds_os_ttl {
        ttl_family_map.insert(os_ttl.initial_ttl, os_ttl.os_family.as_str().to_string());
    }
    ttl_family_map
}

pub fn get_ttl_class_map() -> HashMap<u8, String> {
    let mut ttl_class_map: HashMap<u8, String> = HashMap::new();
    let ds_os_ttl: Vec<model::OsClassTtl> =
        serde_json::from_str(config::OS_CLASS_TTL_JSON).expect("Invalid os-class-ttl.json format");
    for os_ttl in ds_os_ttl {
        ttl_class_map.insert(os_ttl.initial_ttl, os_ttl.os_class.as_str().to_string());
    }
    ttl_class_map
}

pub fn get_class_ttl_map() -> HashMap<OsClass, u8> {
    let mut class_ttl_map: HashMap<OsClass, u8> = HashMap::new();
    let ds_os_ttl: Vec<model::OsClassTtl> =
        serde_json::from_str(config::OS_CLASS_TTL_JSON).expect("Invalid os-class-ttl.json format");
    for os_ttl in ds_os_ttl {
        class_ttl_map.insert(os_ttl.os_class, os_ttl.initial_ttl);
    }
    class_ttl_map
}

pub fn get_family_ttl_map() -> HashMap<OsFamily, u8> {
    let mut family_ttl_map: HashMap<OsFamily, u8> = HashMap::new();
    let ds_os_ttl: Vec<model::OsTtl> =
        serde_json::from_str(config::OS_TTL_JSON).expect("Invalid os-ttl.json format");
    for os_ttl in ds_os_ttl {
        family_ttl_map.insert(os_ttl.os_family, os_ttl.initial_ttl);
    }
    family_ttl_map
}

pub fn get_os_ttl_list() -> Vec<model::OsTtl> {
    let ds_os_ttl: Vec<model::OsTtl> =
        serde_json::from_str(config::OS_TTL_JSON).expect("Invalid os-ttl.json format");
    ds_os_ttl
}

pub fn get_subdomain() -> Vec<String> {
    let subdomain: Vec<String> =
        serde_json::from_str(config::SUBDOMAIN_JSON).expect("Invalid subdomain.json format");
    subdomain
}

pub fn get_os_family_db() -> model::OsDb {
    let os_db: model::OsDb = serde_json::from_str(config::OS_FAMILY_FINGERPRINT_JSON)
        .expect("Invalid os-family-fingerprint.json format");
    os_db
}

pub fn get_os_family_fingerprints() -> Vec<model::Entry> {
    let os_db: model::OsDb = serde_json::from_str(config::OS_FAMILY_FINGERPRINT_JSON)
        .expect("Invalid os-family-fingerprint.json format");
    os_db.entries
}

pub fn get_os_family_list() -> Vec<String> {
    let os_families: Vec<String> =
        serde_json::from_str(config::OS_FAMILY_JSON).expect("Invalid os-family.json format");
    os_families
}
