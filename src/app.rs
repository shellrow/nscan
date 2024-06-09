use clap::{crate_name, crate_version, crate_description};
use crate::sys;

// APP information
pub const CRATE_BIN_NAME: &str = "nscan";
pub const CRATE_UPDATE_DATE: &str = "2024-06-09";
pub const CRATE_REPOSITORY: &str = "https://github.com/shellrow/nscan";

pub enum AppCommands {
    PortScan,
    HostScan,
    Subdomain,
    Interfaces,
    Interface,
    CheckDependencies,
}

impl AppCommands {
    pub fn from_str(s: &str) -> Option<AppCommands> {
        match s {
            "port" => Some(AppCommands::PortScan),
            "host" => Some(AppCommands::HostScan),
            "subdomain" => Some(AppCommands::Subdomain),
            "interfaces" => Some(AppCommands::Interfaces),
            "interface" => Some(AppCommands::Interface),
            "check" => Some(AppCommands::CheckDependencies),
            _ => None
        }
    }
}

pub fn show_app_desc() {
    println!(
        "{} v{} ({}) {}",
        crate_name!(),
        crate_version!(),
        CRATE_UPDATE_DATE,
        sys::os::get_os_type()
    );
    println!("{}", crate_description!());
    println!("{}", CRATE_REPOSITORY);
    println!();
    println!("'{} --help' for more information.", CRATE_BIN_NAME);
    println!();
}

pub fn show_banner_with_starttime() {
    println!(
        "{} v{} {}",
        crate_name!(),
        crate_version!(),
        sys::os::get_os_type()
    );
    println!();
    println!("Starting at {}", sys::time::get_sysdate());
    println!();
}

pub fn exit_with_error_message(message: &str) {
    println!();
    println!("Error: {}", message);
    std::process::exit(1);
}
