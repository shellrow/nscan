use uuid::Uuid;

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

pub fn get_probe_id() -> String {
    let id = Uuid::new_v4();
    id.to_string().replace("-", "")
}

pub fn get_sysdate() -> String {
    let now = chrono::Local::now();
    now.to_rfc3339()
}