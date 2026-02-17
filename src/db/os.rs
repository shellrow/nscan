use crate::{
    config,
    os::{OsClass, OsClassTtl, OsDb},
};
use anyhow::Result;
use std::{collections::HashMap, sync::OnceLock};

pub static OS_DB: OnceLock<OsDb> = OnceLock::new();

/// Initialize OS database
pub fn init_os_db() -> Result<()> {
    let os_db: OsDb =
        serde_json::from_str(config::db::OS_DB_JSON).expect("Invalid nscan-os-db.json format");
    OS_DB
        .set(os_db)
        .map_err(|_| anyhow::anyhow!("Failed to set OS_DB in OnceLock"))?;
    Ok(())
}

/// Get reference to OS database
pub fn os_db() -> &'static OsDb {
    OS_DB.get().expect("OS_DB not initialized")
}

/// Get initial TTL to OS class mapping
pub fn get_ttl_class_map() -> HashMap<u8, String> {
    let mut ttl_class_map: HashMap<u8, String> = HashMap::new();
    let ds_os_ttl: Vec<OsClassTtl> = serde_json::from_str(config::db::OS_CLASS_TTL_JSON)
        .expect("Invalid os-class-ttl.json format");
    for os_ttl in ds_os_ttl {
        ttl_class_map.insert(os_ttl.initial_ttl, os_ttl.os_class.as_str().to_string());
    }
    ttl_class_map
}

/// Get initial TTL mapping
pub fn get_class_ttl_map() -> HashMap<OsClass, u8> {
    let mut class_ttl_map: HashMap<OsClass, u8> = HashMap::new();
    let ds_os_ttl: Vec<OsClassTtl> = serde_json::from_str(config::db::OS_CLASS_TTL_JSON)
        .expect("Invalid os-class-ttl.json format");
    for os_ttl in ds_os_ttl {
        class_ttl_map.insert(os_ttl.os_class, os_ttl.initial_ttl);
    }
    class_ttl_map
}
