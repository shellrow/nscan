// Setting
/// Default source port
pub const DEFAULT_SRC_PORT: u16 = 53443;
/// Default hosts concurrency
pub const DEFAULT_HOSTS_CONCURRENCY: usize = 50;
/// Default ports concurrency
pub const DEFAULT_PORTS_CONCURRENCY: usize = 100;
/// Default timeout in milliseconds
pub const DEFAULT_TIMEOUT: u64 = 30000;
/// Default wait time in milliseconds
pub const DEFAULT_WAIT_TIME: u64 = 500;
/// Default send rate(interval) in milliseconds
pub const DEFAULT_SEND_RATE: u64 = 0;

// Database
pub const DEFAULT_PORTS_BIN: &[u8] = include_bytes!("../resources/np-default-ports.bin");
pub const HTTP_PORTS_BIN: &[u8] = include_bytes!("../resources/np-http-ports.bin");
pub const HTTPS_PORTS_BIN: &[u8] = include_bytes!("../resources/np-https-ports.bin");
pub const OS_FINGERPRINT_BIN: &[u8] = include_bytes!("../resources/np-os-fingerprint.bin");
pub const OS_TTL_BIN: &[u8] = include_bytes!("../resources/np-os-ttl.bin");
pub const OS_FAMILY_BIN: &[u8] = include_bytes!("../resources/np-os-family.bin");
pub const OUI_BIN: &[u8] = include_bytes!("../resources/np-oui.bin");
pub const OUI_VM_BIN: &[u8] = include_bytes!("../resources/np-oui-vm.bin");
pub const TCP_SERVICE_BIN: &[u8] = include_bytes!("../resources/np-tcp-service.bin");
pub const WELLKNOWN_PORTS_BIN: &[u8] = include_bytes!("../resources/np-wellknown-ports.bin");

// MPSC(Multi Producer, Single Consumer) FIFO queue communication messages
pub const MESSAGE_START_PORTSCAN: &str = "START_PORTSCAN";
pub const MESSAGE_END_PORTSCAN: &str = "END_PORTSCAN";
pub const MESSAGE_START_SERVICEDETECTION: &str = "START_SERVICEDETECTION";
pub const MESSAGE_END_SERVICEDETECTION: &str = "END_SERVICEDETECTION";
pub const MESSAGE_START_OSDETECTION: &str = "START_OSDETECTION";
pub const MESSAGE_END_OSDETECTION: &str = "END_OSDETECTION";
pub const MESSAGE_START_HOSTSCAN: &str = "START_HOSTSCAN";
pub const MESSAGE_END_HOSTSCAN: &str = "END_HOSTSCAN";
pub const MESSAGE_START_LOOKUP: &str = "START_LOOKUP";
pub const MESSAGE_END_LOOKUP: &str = "END_LOOKUP";
pub const MESSAGE_START_CHECK_RESULTS: &str = "START_CHECK_RESULTS";
pub const MESSAGE_END_CHECK_RESULTS: &str = "END_CHECK_RESULTS";
