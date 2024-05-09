use uuid::Uuid;

pub fn get_probe_id() -> String {
    let id = Uuid::new_v4();
    id.to_string().replace("-", "")
}

pub fn get_host_id(hostname: String) -> String {
    let id = Uuid::new_v5(&Uuid::NAMESPACE_DNS, hostname.as_bytes());
    id.to_string().replace("-", "")
}
