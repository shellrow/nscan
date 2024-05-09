#[cfg(target_os = "windows")]
pub fn get_os_type() -> String {
    "windows".to_owned()
}

#[cfg(target_os = "linux")]
pub fn get_os_type() -> String {
    "linux".to_owned()
}

#[cfg(target_os = "macos")]
pub fn get_os_type() -> String {
    "macos".to_owned()
}
