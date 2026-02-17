pub mod dns;
pub mod generic;
pub mod http;
pub mod null;
pub mod quic;
pub mod tls;

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::endpoint::{ServiceInfo, TransportProtocol};

/// Metadata for the database
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Meta {
    pub name: String,
    pub version: String,
}

/// Supported service probes
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServiceProbe {
    TcpNull,
    TcpGenericLines,
    TcpHTTPGet,
    TcpHTTPSGet,
    TcpHTTPOptions,
    TcpDNSVersionBindReq,
    TcpHelp,
    TcpTlsSession,
    UdpDNSVersionBindReq,
    UdpQuic,
}

impl ServiceProbe {
    /// Convert the ServiceProbe enum to its string representation.
    pub fn as_str(&self) -> &str {
        match self {
            ServiceProbe::TcpNull => "tcp:null",
            ServiceProbe::TcpGenericLines => "tcp:generic_lines",
            ServiceProbe::TcpHTTPGet => "tcp:http_get",
            ServiceProbe::TcpHTTPSGet => "tcp:https_get",
            ServiceProbe::TcpHTTPOptions => "tcp:http_options",
            ServiceProbe::TcpDNSVersionBindReq => "tcp:dns_version_bind_req",
            ServiceProbe::TcpHelp => "tcp:help",
            ServiceProbe::TcpTlsSession => "tcp:tls_session",
            ServiceProbe::UdpDNSVersionBindReq => "udp:dns_version_bind_req",
            ServiceProbe::UdpQuic => "udp:quic",
        }
    }
    /// Create a ServiceProbe enum from its string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "tcp:null" => Some(ServiceProbe::TcpNull),
            "tcp:generic_lines" => Some(ServiceProbe::TcpGenericLines),
            "tcp:http_get" => Some(ServiceProbe::TcpHTTPGet),
            "tcp:https_get" => Some(ServiceProbe::TcpHTTPSGet),
            "tcp:http_options" => Some(ServiceProbe::TcpHTTPOptions),
            "tcp:dns_version_bind_req" => Some(ServiceProbe::TcpDNSVersionBindReq),
            "tcp:help" => Some(ServiceProbe::TcpHelp),
            "tcp:tls_session" => Some(ServiceProbe::TcpTlsSession),
            "udp:dns_version_bind_req" => Some(ServiceProbe::UdpDNSVersionBindReq),
            "udp:quic" => Some(ServiceProbe::UdpQuic),
            _ => None,
        }
    }
    /// Get the transport protocol associated with the ServiceProbe.
    pub fn transport(&self) -> TransportProtocol {
        match self {
            ServiceProbe::TcpNull
            | ServiceProbe::TcpGenericLines
            | ServiceProbe::TcpHTTPGet
            | ServiceProbe::TcpHTTPSGet
            | ServiceProbe::TcpHTTPOptions
            | ServiceProbe::TcpDNSVersionBindReq
            | ServiceProbe::TcpHelp
            | ServiceProbe::TcpTlsSession => TransportProtocol::Tcp,
            ServiceProbe::UdpDNSVersionBindReq | ServiceProbe::UdpQuic => TransportProtocol::Udp,
        }
    }
}

/// Encoding type for probe payloads
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum PayloadEncoding {
    Raw,
    Base64,
}

/// Database mapping ports to associated probes
#[derive(Serialize, Deserialize)]
pub struct PortProbeDb {
    pub meta: Meta,
    // port -> probe_id[]
    pub map: BTreeMap<u16, Vec<String>>,
}

impl PortProbeDb {
    /// Create a new empty PortProbeDb
    pub fn new() -> Self {
        PortProbeDb {
            meta: Meta {
                name: "Port Probe Database".into(),
                version: "1.0".into(),
            },
            map: BTreeMap::new(),
        }
    }
}

/// Definition of a probe payload
#[derive(Serialize, Deserialize, Clone)]
pub struct ProbePayload {
    pub id: String,
    pub protocol: TransportProtocol,
    pub name: String,
    pub payload: String,
    pub payload_encoding: PayloadEncoding,
    pub wait_ms: Option<u64>,
    pub ports: Vec<u16>,
}

/// Database of probe payloads
#[derive(Serialize, Deserialize)]
pub struct ProbePayloadDb {
    pub meta: Meta,
    pub probes: Vec<ProbePayload>,
}

impl ProbePayloadDb {
    /// Create a new empty ProbePayloadDb
    pub fn new() -> Self {
        ProbePayloadDb {
            meta: Meta {
                name: "Probe Payload Database".into(),
                version: "1.0".into(),
            },
            probes: Vec::new(),
        }
    }
}

/// Definition of a response signature for service identification
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseSignature {
    pub probe_id: String,
    pub service: String,
    pub regex: String,
    pub regex_literal_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
}

/// Database of response signatures
#[derive(Serialize, Deserialize)]
pub struct ResponseSignaturesDb {
    pub meta: Meta,
    pub signatures: Vec<ResponseSignature>,
}

impl ResponseSignaturesDb {
    /// Create a new empty SignaturesDb
    pub fn new() -> Self {
        ResponseSignaturesDb {
            meta: Meta {
                name: "Signatures Database".into(),
                version: "1.0".into(),
            },
            signatures: Vec::new(),
        }
    }
}

/// Definition of a port probe
#[derive(Debug, Clone)]
pub struct PortProbe {
    pub probe_id: ServiceProbe,
    pub probe_name: String,
    pub port: u16,
    pub transport: TransportProtocol,
    pub payload: String, // Raw or Base64
    pub payload_encoding: PayloadEncoding,
}

impl PortProbe {
    pub fn null_probe(port: u16, transport: TransportProtocol) -> Self {
        PortProbe {
            probe_id: ServiceProbe::TcpNull,
            probe_name: "tcp:null".into(),
            port,
            transport,
            payload: String::new(),
            payload_encoding: PayloadEncoding::Raw,
        }
    }
}

/// Context for running a probe against a target
#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub probe: PortProbe,
    pub timeout: Duration,
    pub max_read_size: usize,
    pub sni: bool,
    pub skip_cert_verify: bool,
}

/// Result of running a probe against a target
#[derive(Debug, Clone)]
pub struct PortProbeResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub port: u16,
    pub transport: TransportProtocol,
    pub probe_id: ServiceProbe,
    pub service_info: ServiceInfo,
}
