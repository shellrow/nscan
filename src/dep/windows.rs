use super::DependencyError;

pub fn check_dependencies() -> Result<(), DependencyError> {
    if nex_npcap_helper::npcap::npcap_installed() {
        Ok(())
    } else {
        Err(DependencyError::new("Npcap", "Npcap is not installed. \nOn Windows, Npcap is required for some features. \nPlease install Npcap from https://npcap.com/#download"))
    }
}
