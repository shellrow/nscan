pub const CRATE_UPDATE_DATE: &str = "2022-04-24";
pub const CRATE_AUTHOR_GITHUB: &str = "shellrow <https://github.com/shellrow>";
pub const CRATE_REPOSITORY: &str = "https://github.com/shellrow/nscan";
pub const PORTSCAN_TYPE_SYN_SCAN: &str = "SYN";
pub const PORTSCAN_TYPE_CONNECT_SCAN: &str = "CONNECT";
pub const NSCAN_OUI: &str = include_str!("../data/nscan-oui.json");
pub const NSCAN_TCP_PORT: &str = include_str!("../data/nscan-tcp-port.json");
pub const NSCAN_DEFAULT_PORTS: &str = include_str!("../data/nscan-default-ports.txt");
pub const NSCAN_HTTP: &str = include_str!("../data/nscan-http.txt");
pub const NSCAN_HTTPS: &str = include_str!("../data/nscan-https.txt");
pub const NSCAN_OS: &str = include_str!("../data/nscan-os-simple.json");
#[allow(dead_code)]
pub const NSCAN_OS_TTL: &str = include_str!("../data/nscan-os-ttl.json");
