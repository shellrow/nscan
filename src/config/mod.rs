pub const DEFAULT_LOCAL_TCP_PORT: u16 = 44322;
pub const DEFAULT_LOCAL_UDP_PORT: u16 = 53445;
pub const DEFAULT_BASE_TARGET_UDP_PORT: u16 = 33435;
pub const DEFAULT_HOP_LIMIT: u8 = 64;
pub const DEFAULT_PING_COUNT: u32 = 4;
pub const DEFAULT_HOSTS_CONCURRENCY: usize = 50;
pub const DEFAULT_PORTS_CONCURRENCY: usize = 100;
pub const PCAP_WAIT_TIME_MILLIS: u64 = 10;

// Database
pub const DEFAULT_PORTS_BIN: &[u8] = include_bytes!("../../resources/ndb-default-ports.bin");
pub const HTTP_PORTS_BIN: &[u8] = include_bytes!("../../resources/ndb-http-ports.bin");
pub const HTTPS_PORTS_BIN: &[u8] = include_bytes!("../../resources/ndb-https-ports.bin");
pub const OS_FAMILY_FINGERPRINT_BIN: &[u8] =
    include_bytes!("../../resources/ndb-os-family-fingerprint.bin");
pub const OS_TTL_BIN: &[u8] = include_bytes!("../../resources/ndb-os-ttl.bin");
pub const OS_FAMILY_BIN: &[u8] = include_bytes!("../../resources/ndb-os-family.bin");
pub const SUBDOMAIN_BIN: &[u8] = include_bytes!("../../resources/ndb-subdomain.bin");
pub const WELLKNOWN_PORTS_BIN: &[u8] = include_bytes!("../../resources/ndb-wellknown-ports.bin");
