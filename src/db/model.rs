use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::fp::{OsClass, OsFamily};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Oui {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Debug, Deserialize)]
pub struct OsDb {
    pub meta: Meta,
    pub entries: Vec<Entry>,
}

pub struct OsDbIndex {
    /// Index by (order_key, win_bucket) for exact match
    /// This is used for fast lookup of OS signatures based on ordered TCP options and window size.
    pub by_order: HashMap<(String, String), Vec<Entry>>,
    /// Index by (set_key, win_bucket) for match
    /// This is used for matching OS signatures based on TCP options set and window size.
    pub by_set_win: HashMap<(String, String), Vec<Entry>>,
}

impl From<OsDb> for OsDbIndex {
    fn from(db: OsDb) -> Self {
        let mut by_order: HashMap<(String, String), Vec<Entry>> = HashMap::new();
        let mut by_set_win: HashMap<(String, String), Vec<Entry>> = HashMap::new();

        for e in db.entries {
            by_order
                .entry((
                    e.signature.order_key.clone(),
                    e.signature.win_bucket.clone(),
                ))
                .or_default()
                .push(e.clone());
            by_set_win
                .entry((e.signature.set_key.clone(), e.signature.win_bucket.clone()))
                .or_default()
                .push(e);
        }

        OsDbIndex {
            by_order,
            by_set_win,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Meta {
    pub name: String,
    pub version: String,
    pub schema: Schema,
    pub confidence_note: String,
}

#[derive(Debug, Deserialize)]
pub struct Schema {
    pub signature: SignatureSchema,
    pub family: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignatureSchema {
    pub order_key: String,
    pub set_key: String,
    pub has_ts: String,
    pub has_sack: String,
    pub has_ws: String,
    pub win_bucket: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub signature: Signature,
    pub family_votes: std::collections::HashMap<String, u32>,
    pub total: u32,
    pub suggested_family: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub order_key: String,
    pub set_key: String,
    pub has_ts: bool,
    pub has_sack: bool,
    pub has_ws: bool,
    pub win_bucket: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsTtl {
    pub os_family: OsFamily,
    pub os_description: String,
    pub initial_ttl: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsClassTtl {
    pub os_class: OsClass,
    pub os_description: String,
    pub initial_ttl: u8,
}
