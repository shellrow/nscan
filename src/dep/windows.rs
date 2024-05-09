use super::DependencyError;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

const NPCAP_SOFTWARE_NAME: &str = "Npcap";

pub fn check_dependencies() -> Result<(), DependencyError> {
    if npcap_installed() {
        Ok(())
    } else {
        Err(DependencyError::new("Npcap", "Npcap is not installed. \nOn Windows, Npcap is required for some features. \nPlease install Npcap from https://npcap.com/#download"))
    }
}

pub fn get_os_bit() -> String {
    if cfg!(target_pointer_width = "32") {
        return "32-bit".to_owned();
    } else if cfg!(target_pointer_width = "64") {
        return "64-bit".to_owned();
    } else {
        return "unknown".to_owned();
    }
}

// Get software installation status
pub fn software_installed(software_name: String) -> bool {
    let hklm: RegKey = RegKey::predef(HKEY_LOCAL_MACHINE);
    let os_bit: String = get_os_bit();
    let npcap_key: RegKey = if os_bit == "32-bit" {
        match hklm.open_subkey(format!("SOFTWARE\\{}", software_name)) {
            Ok(key) => key,
            Err(_) => return false,
        }
    } else {
        match hklm.open_subkey(format!("SOFTWARE\\WOW6432Node\\{}", software_name)) {
            Ok(key) => key,
            Err(_) => return false,
        }
    };
    let _version: String = npcap_key.get_value("").unwrap_or(String::new());
    true
}

/// Check if npcap is installed.
/// This function only check if npcap is installed, not check version.
pub fn npcap_installed() -> bool {
    software_installed(NPCAP_SOFTWARE_NAME.to_owned())
}
