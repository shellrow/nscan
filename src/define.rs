// APP information
pub const CRATE_UPDATE_DATE: &str = "2023-06-10";
pub const CRATE_REPOSITORY: &str = "https://github.com/shellrow/nscan";

// Setting
pub const DEFAULT_SRC_PORT: u16 = 53443;

// Database
pub const DEFAULT_PORTS_TXT: &str = include_str!("../resources/nscan-default-ports.txt");
pub const HTTP_PORTS_TXT: &str = include_str!("../resources/nscan-http-ports.txt");
pub const HTTPS_PORTS_TXT: &str = include_str!("../resources/nscan-https-ports.txt");
pub const OS_FINGERPRINT_JSON: &str = include_str!("../resources/nscan-os-fingerprint.json");
pub const OS_TTL_JSON: &str = include_str!("../resources/nscan-os-ttl.json");
pub const OUI_JSON: &str = include_str!("../resources/nscan-oui.json");
pub const TCP_SERVICE_JSON: &str = include_str!("../resources/nscan-tcp-service.json");
pub const WELLKNOWN_PORTS_TXT: &str = include_str!("../resources/nscan-wellknown-ports.txt");

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
