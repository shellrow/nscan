/// Default local TCP port for sending probes
pub const DEFAULT_LOCAL_TCP_PORT: u16 = 44322;
/// Default local UDP port for sending probes
pub const DEFAULT_LOCAL_UDP_PORT: u16 = 53445;
/// Default base target UDP port for traceroute or ping
pub const DEFAULT_BASE_TARGET_UDP_PORT: u16 = 33435;
/// Default hop limit (TTL)
pub const DEFAULT_HOP_LIMIT: u8 = 64;
/// Default ping count for ping command
pub const DEFAULT_PING_COUNT: u32 = 4;
/// Default concurrency for host scanning
pub const DEFAULT_HOSTS_CONCURRENCY: usize = 50;
/// Default concurrency for port scanning
pub const DEFAULT_PORTS_CONCURRENCY: usize = 100;
