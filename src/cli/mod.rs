pub mod host;
pub mod ping;
pub mod port;

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum, value_parser};

use crate::{config::default::DEFAULT_PORTS_CONCURRENCY, endpoint::TransportProtocol};

/// nscan - Network scan tool for host and service discovery
#[derive(Parser, Debug)]
#[command(author, version, about = "nscan - Network scan tool for host and service discovery\nhttps://github.com/shellrow/nscan", long_about = None)]
pub struct Cli {
    /// Global log level
    #[arg(global = true, long, default_value = "info")]
    pub log_level: LogLevel,

    /// Log to file (in addition to stderr)
    #[arg(global = true, long, action = ArgAction::SetTrue, default_value_t = false)]
    pub log_file: bool,

    /// Log file path (default: ~/.nscan/nscan.log)
    #[arg(global = true, long, value_name = "FILE", value_parser = value_parser!(PathBuf))]
    pub log_file_path: Option<PathBuf>,

    /// Suppress non-error logs
    #[arg(global = true, long, action = ArgAction::SetTrue, default_value_t = false)]
    pub quiet: bool,

    /// Save result to a JSON file
    #[arg(global = true, short, long, value_name = "FILE", value_parser = value_parser!(PathBuf))]
    pub output: Option<PathBuf>,

    /// Suppress stdout output (use with --output)
    #[arg(global = true, long, action = ArgAction::SetTrue, default_value_t = false)]
    pub no_stdout: bool,

    /// Subcommands
    #[command(subcommand)]
    pub command: Command,
}

/// Log level
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// Convert to `tracing::Level`
    pub fn to_level_filter(&self) -> tracing::Level {
        match self {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        }
    }
}

/// Subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan ports on target host(s) (TCP/QUIC)
    Port(PortScanArgs),

    /// Discover alive hosts (ICMP/UDP/TCP)
    Host(HostScanArgs),

    /// Subdomain enumeration
    Domain(DomainScanArgs),

    /// Show network interface information
    Interface(InterfaceArgs),
}

/// Port scan methods. Default: connect
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum PortScanMethod {
    Connect,
    Syn,
}

/// Port scan transport.
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum PortScanTransport {
    Tcp,
    Quic,
}

impl PortScanTransport {
    /// Convert to TransportProtocol.
    pub fn to_transport(self) -> TransportProtocol {
        match self {
            PortScanTransport::Tcp => TransportProtocol::Tcp,
            PortScanTransport::Quic => TransportProtocol::Quic,
        }
    }
    /// Convert to lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            PortScanTransport::Tcp => "tcp",
            PortScanTransport::Quic => "quic",
        }
    }
}

/// Host scan protocols. Default: ICMP
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum HostScanProto {
    Icmp,
    Udp,
    Tcp,
}

impl HostScanProto {
    /// Convert to &str
    pub fn as_str(&self) -> &str {
        match self {
            HostScanProto::Icmp => "icmp",
            HostScanProto::Udp => "udp",
            HostScanProto::Tcp => "tcp",
        }
    }
}

/// Port scan arguments
#[derive(Args, Debug)]
pub struct PortScanArgs {
    /// Target IP or hostname
    #[arg(required = true)]
    pub target: Vec<String>,

    /// Port spec: "common" | "1-1024,80,443" | "22-25"
    #[arg(short, long, default_value = "common")]
    pub ports: String,

    /// Transport to scan
    #[arg(long, value_enum, default_value_t = PortScanTransport::Tcp)]
    pub proto: PortScanTransport,

    /// Scanning method (default: connect)
    #[arg(long, value_enum, default_value_t = PortScanMethod::Connect)]
    pub method: PortScanMethod,

    /// Enable service detection (banner/TLS/etc.)
    #[arg(short='S', long, default_value_t = false, action=ArgAction::SetTrue)]
    pub service_detect: bool,

    /// Request OS identification through Nmap (requires raw packet privileges)
    #[arg(short = 'O', long, default_value_t = false, action = ArgAction::SetTrue)]
    pub os_detect: bool,

    /// Request detailed TCP service identification through an installed Nmap
    #[arg(long)]
    pub nmap: bool,

    /// Nmap executable path (used only with --nmap or --os-detect)
    #[arg(long, default_value = "nmap")]
    pub nmap_path: PathBuf,

    /// Total timeout for the Nmap identification phase in milliseconds
    #[arg(long, default_value_t = 120_000, value_parser = value_parser!(u64).range(1..=3_600_000))]
    pub nmap_timeout_ms: u64,

    /// Built-in probe selection (used with --service-detect)
    #[arg(long, value_enum, default_value_t = crate::service::probe::ProbeMode::Auto, requires = "service_detect")]
    pub service_probe: crate::service::probe::ProbeMode,

    /// Enable QUIC probing on UDP ports (e.g., 443/udp)
    #[arg(long, action=ArgAction::SetTrue)]
    pub quic: bool,

    /// SNI for QUIC/TLS probing (defaults to target name)
    #[arg(long)]
    pub sni: Option<String>,

    /// Network interface name to bind
    #[arg(long)]
    pub interface: Option<String>,

    /// Concurrency (tasks)
    #[arg(long, default_value_t = DEFAULT_PORTS_CONCURRENCY, value_parser = parse_concurrency)]
    pub concurrency: usize,

    /// Base connect timeout in ms (auto-adapted by RTT)
    #[arg(long, value_parser = value_parser!(u64).range(1..=10_000))]
    pub connect_timeout_ms: Option<u64>,

    /// Service probe timeout in ms (used with --service-detect)
    #[arg(long, value_parser = value_parser!(u64).range(1..=10_000))]
    pub read_timeout_ms: Option<u64>,

    /// Wait after sending probes (ms)
    #[arg(short='w', long, value_parser = value_parser!(u64).range(10..=5000))]
    pub wait_ms: Option<u64>,

    /// Task timeout in ms
    #[arg(long, default_value_t = 30000, value_parser = value_parser!(u64).range(1..=60_000))]
    pub task_timeout_ms: u64,

    /// Scan ports in ascending order (default is randomized)
    #[arg(long, action=ArgAction::SetTrue)]
    pub ordered: bool,

    /// Skip initial reachability/RTT ping
    #[arg(long, action=ArgAction::SetTrue)]
    pub no_ping: bool,
}

/// Host scan arguments
#[derive(Args, Debug)]
pub struct HostScanArgs {
    /// Targets (CIDR, IP, hostname, or @file).
    #[arg(required = true)]
    pub target: Vec<String>,

    /// Protocol to use (default: ICMP)
    #[arg(long, value_enum, default_value_t = HostScanProto::Icmp)]
    pub proto: HostScanProto,

    /// Port spec: "80" | "80,443" | "22-25"
    #[arg(short, long, default_value = "80")]
    pub ports: String,

    /// Wait after sending probes (ms)
    #[arg(short='w', long, default_value_t = 300, value_parser = value_parser!(u64).range(10..=5000))]
    pub wait_ms: u64,

    /// Timeout per probe (ms)
    #[arg(long, default_value_t = 600, value_parser = value_parser!(u64).range(50..=5000))]
    pub timeout_ms: u64,

    /// Network interface name to bind
    #[arg(long)]
    pub interface: Option<String>,

    /// Concurrency (in-flight probes)
    #[arg(long, default_value_t = 512, value_parser = parse_concurrency)]
    pub concurrency: usize,

    /// Scan hosts in ascending IP order (default is randomized)
    #[arg(long, action=ArgAction::SetTrue)]
    pub ordered: bool,
}

/// Subdomain scan arguments
#[derive(Args, Debug)]
pub struct DomainScanArgs {
    /// Base domain (e.g., example.com)
    #[arg(required = true)]
    pub domain: String,

    /// Wordlist path
    #[arg(short, long)]
    pub wordlist: Option<PathBuf>,

    /// DNS lookup concurrency
    #[arg(long, default_value_t = 256, value_parser = parse_concurrency)]
    pub concurrency: usize,

    /// Total scan timeout (ms)
    #[arg(long, default_value_t = 30000, value_parser = value_parser!(u64).range(1..=86_400_000))]
    pub timeout_ms: u64,

    /// Per-lookup timeout (ms)
    #[arg(long, default_value_t = 2000, value_parser = value_parser!(u64).range(1..=60_000))]
    pub resolve_timeout_ms: u64,
}

/// Network interface arguments
#[derive(Args, Debug)]
pub struct InterfaceArgs {
    /// Show all interfaces
    #[arg(short, long, action=ArgAction::SetTrue)]
    pub all: bool,
}

fn parse_concurrency(raw: &str) -> Result<usize, String> {
    let value = raw.parse::<usize>().map_err(|e| e.to_string())?;
    if !(1..=4096).contains(&value) {
        return Err("concurrency must be between 1 and 4096".into());
    }
    Ok(value)
}
