use anyhow::Result;
use serde::Deserialize;
use std::{collections::HashMap, sync::OnceLock};

use crate::config::db::TLS_OID_MAP_JSON;

/// Structure representing the TLS OID mappings.
#[derive(Debug, Deserialize)]
pub struct TlsOidMap {
    /// Mapping of OID to signature algorithm names.
    pub sig: HashMap<String, String>,
    /// Mapping of OID to public key algorithm names.
    pub pubkey: HashMap<String, String>,
}

/// Global static instance of the TLS OID map, initialized once.
pub static TLS_OID_MAP: OnceLock<TlsOidMap> = OnceLock::new();

/// Get a reference to the initialized TLS OID map.
pub fn tls_oid_map() -> &'static TlsOidMap {
    TLS_OID_MAP.get().expect("TLS_OID_MAP not initialized")
}

/// Initialize the TLS OID map from the bundled JSON data.
pub fn init_tls_oid_map() -> Result<()> {
    let map: TlsOidMap = serde_json::from_str(&TLS_OID_MAP_JSON).expect("invalid json");
    TLS_OID_MAP.set(map).map_err(|_| anyhow::anyhow!("Failed to set TLS_OID_MAP in OnceLock"))?;
    Ok(())
}

/// Get the name of a TLS version given its numeric representation.
pub fn oid_sig_name(oid: &str) -> String {
    tls_oid_map().sig.get(oid).cloned().unwrap_or_else(|| oid.to_string())
}

/// Get the name of a public key algorithm given its OID.
pub fn oid_pubkey_name(oid: &str) -> String {
    tls_oid_map().pubkey.get(oid).cloned().unwrap_or_else(|| oid.to_string())
}
