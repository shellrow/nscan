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
pub const DEFAULT_PORTS_TXT: &str = include_str!("../resources/np-default-ports.txt");
pub const HTTP_PORTS_TXT: &str = include_str!("../resources/np-http-ports.txt");
pub const HTTPS_PORTS_TXT: &str = include_str!("../resources/np-https-ports.txt");
pub const OS_FINGERPRINT_JSON: &str = include_str!("../resources/np-os-fingerprint.json");
pub const OS_TTL_JSON: &str = include_str!("../resources/np-os-ttl.json");
pub const OS_FAMILY_TXT: &str = include_str!("../resources/np-os-family.txt");
pub const OUI_JSON: &str = include_str!("../resources/np-oui.json");
pub const OUI_VM_JSON: &str = include_str!("../resources/np-oui-vm.json");
pub const TCP_SERVICE_JSON: &str = include_str!("../resources/np-tcp-service.json");
pub const WELLKNOWN_PORTS_TXT: &str = include_str!("../resources/np-wellknown-ports.txt");

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
