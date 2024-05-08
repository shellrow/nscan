pub const DEFAULT_LOCAL_TCP_PORT: u16 = 44322;
pub const DEFAULT_LOCAL_UDP_PORT: u16 = 53445;
pub const DEFAULT_BASE_TARGET_UDP_PORT: u16 = 33435;
pub const DEFAULT_HOP_LIMIT: u8 = 64;
pub const DEFAULT_PING_COUNT: u32 = 4;
pub const DEFAULT_HOSTS_CONCURRENCY: usize = 50;
pub const DEFAULT_PORTS_CONCURRENCY: usize = 100;
pub const PCAP_WAIT_TIME_MILLIS: u64 = 10;

// Database
pub const OS_FAMILY_FINGERPRINT_BIN: &[u8] = include_bytes!("../../resources/ndb-os-family-fingerprint.bin");
pub const OS_TTL_BIN: &[u8] = include_bytes!("../../resources/ndb-os-ttl.bin");
pub const OS_FAMILY_BIN: &[u8] = include_bytes!("../../resources/ndb-os-family.bin");
pub const OUI_BIN: &[u8] = include_bytes!("../../resources/ndb-oui.bin");
pub const OUI_VM_BIN: &[u8] = include_bytes!("../../resources/ndb-oui-vm.bin");
