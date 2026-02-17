use anyhow::Result;
use ndb_oui::OuiDb;
use std::sync::OnceLock;

pub static OUI_DB: OnceLock<OuiDb> = OnceLock::new();

/// Initialize OUI database
pub fn init_oui_db() -> Result<()> {
    let oui_db = OuiDb::bundled();
    OUI_DB
        .set(oui_db)
        .map_err(|_| anyhow::anyhow!("Failed to set OUI_DB in OnceLock"))?;
    Ok(())
}

/// Get reference to OUI database
pub fn oui_db() -> &'static OuiDb {
    OUI_DB.get().expect("OUI_DB not initialized")
}

/// Lookup vendor name from MAC address.
pub fn lookup_vendor_name(mac_addr: &netdev::MacAddr) -> Option<String> {
    let db_mac = ndb_oui::MacAddr(
        mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3, mac_addr.4, mac_addr.5,
    );

    oui_db().lookup_mac(&db_mac).map(|oui| {
        oui.vendor_detail
            .clone()
            .unwrap_or_else(|| oui.vendor.clone())
    })
}
