#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
pub fn get_install_path(install_dir_name: &str) -> Option<PathBuf> {
    match home::home_dir() {
        Some(path) => {
            let path: PathBuf = path.join(install_dir_name);
            Some(path)
        }
        None => None,
    }
}

#[cfg(target_os = "windows")]
pub fn check_dependencies() -> bool {
    use nex_npcap_helper::npcap;
    npcap::npcap_installed()
}

#[cfg(not(target_os = "windows"))]
pub fn check_dependencies() -> bool {
    true
}

#[cfg(target_os = "windows")]
pub fn resolve_dependencies() {
    use nex_npcap_helper::npcap;
    use inquire::Confirm;
    // Check if npcap is installed
    if !npcap::npcap_installed() {
        let ans: bool = Confirm::new("Npcap is not installed, would you like to install it ?")
            .prompt()
            .unwrap();
        if ans == false {
            println!("Exiting...");
            return;
        }
    } else {
        let ans: bool = Confirm::new("Npcap is already installed. Would you like to reinstall (or update) Npcap ?")
            .prompt()
            .unwrap();
        if ans == false {
            println!("Exiting...");
            return;
        }
    }
    let dst_path = match get_install_path("Downloads") {
        Some(path) => path,
        None => {
            println!("Failed to get the path to the Downloads directory.");
            return;
        },
    };
    // Download the latest release of npcap installer
    let installer_path = match npcap::download_npcap_with_progress(&dst_path) {
        Ok(path) => {
            println!("Npcap installer downloaded successfully.");
            path
        },
        Err(e) => {
            println!("{}", e);
            return;
        },
    };
    // Verify the checksum of the downloaded npcap installer
    match npcap::verify_installer_checksum(&installer_path) {
        Ok(_) => {},
        Err(e) => {
            println!("{}", e);
            return;
        },
    }
    // Install npcap
    match npcap::run_npcap_installer(&installer_path) {
        Ok(_) => println!("Npcap installed successfully."),
        Err(e) => {
            println!("{}", e);
            return;
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn resolve_dependencies() {

}
