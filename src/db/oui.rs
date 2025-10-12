use ndb_oui::OuiDb;
use anyhow::Result;
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
