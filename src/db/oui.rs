use ndb_oui::OuiDb;
use std::sync::LazyLock;
static OUI_DB: LazyLock<OuiDb> = LazyLock::new(OuiDb::bundled);

/// Lookup vendor name from MAC address.
pub fn lookup_vendor_name(mac_addr: &netdev::MacAddr) -> Option<String> {
    let db_mac = ndb_oui::MacAddr(
        mac_addr.0, mac_addr.1, mac_addr.2, mac_addr.3, mac_addr.4, mac_addr.5,
    );

    OUI_DB.lookup_mac(&db_mac).map(|oui| {
        oui.vendor_detail
            .clone()
            .unwrap_or_else(|| oui.vendor.clone())
    })
}
