pub const DEFAULT_LOCAL_TCP_PORT: u16 = 44322;
pub const DEFAULT_LOCAL_UDP_PORT: u16 = 53445;
pub const DEFAULT_BASE_TARGET_UDP_PORT: u16 = 33435;
pub const DEFAULT_HOP_LIMIT: u8 = 64;
pub const DEFAULT_PING_COUNT: u32 = 4;
pub const DEFAULT_HOSTS_CONCURRENCY: usize = 50;
pub const DEFAULT_PORTS_CONCURRENCY: usize = 100;

// Database
pub const DEFAULT_PORTS_JSON: &str = include_str!("../../resources/default-ports.json");
pub const HTTP_PORTS_JSON: &str = include_str!("../../resources/http-ports.json");
pub const HTTPS_PORTS_JSON: &str = include_str!("../../resources/https-ports.json");
pub const OS_FAMILY_FINGERPRINT_JSON: &str =
    include_str!("../../resources/os-family-fingerprint.json");
pub const OS_FAMILY_JSON: &str = include_str!("../../resources/os-family.json");
pub const OS_TTL_JSON: &str = include_str!("../../resources/os-ttl.json");
pub const OS_CLASS_TTL_JSON: &str = include_str!("../../resources/os-class-ttl.json");
pub const SUBDOMAIN_JSON: &str = include_str!("../../resources/subdomain.json");
pub const WELLKNOWN_PORTS_JSON: &str = include_str!("../../resources/wellknown-ports.json");
