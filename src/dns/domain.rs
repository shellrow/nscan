use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertEntry {
    pub id: u64,
    pub issuer_ca_id: u32,
    pub issuer_name: String,
    pub common_name: String,
    pub name_value: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub entry_timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Domain {
    pub domain_name: String,
    pub ips: Vec<IpAddr>,
}
