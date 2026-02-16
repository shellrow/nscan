use netdev::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

mod ports_vec {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(map: &BTreeMap<Port, PortResult>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec: Vec<&PortResult> = map.values().collect();
        vec.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<BTreeMap<Port, PortResult>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = <Vec<PortResult>>::deserialize(d)?;
        Ok(vec.into_iter().map(|pr| (pr.port, pr)).collect())
    }
}

/// Transport protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Quic,
}

impl TransportProtocol {
    /// Create a TransportProtocol from a string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(TransportProtocol::Tcp),
            "udp" => Some(TransportProtocol::Udp),
            "quic" => Some(TransportProtocol::Quic),
            _ => None,
        }
    }
    /// Get the string representation of the TransportProtocol.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
            TransportProtocol::Quic => "quic",
        }
    }
}

/// Network port with transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct Port {
    pub number: u16,
    pub transport: TransportProtocol,
}

impl Port {
    /// Create a new Port instance.
    pub fn new(number: u16, transport: TransportProtocol) -> Self {
        Self { number, transport }
    }
    /// Get the SocketAddr for the given IP address and this port.
    pub fn socket_addr(&self, ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, self.number)
    }
}

impl From<(u16, TransportProtocol)> for Port {
    fn from(t: (u16, TransportProtocol)) -> Self {
        Self {
            number: t.0,
            transport: t.1,
        }
    }
}
impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            match self.transport {
                TransportProtocol::Tcp => "tcp",
                TransportProtocol::Udp => "udp",
                TransportProtocol::Quic => "quic",
            },
            self.number
        )
    }
}

/// Port state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl PortState {
    /// Create a PortState from a string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "open" => Some(PortState::Open),
            "closed" => Some(PortState::Closed),
            "filtered" => Some(PortState::Filtered),
            _ => None,
        }
    }
    /// Get the string representation of the PortState.
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        }
    }
}

/// Node type
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum NodeType {
    Gateway,
    Hop,
    Destination,
}

impl NodeType {
    /// Create a NodeType from a string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "gateway" => Some(NodeType::Gateway),
            "hop" => Some(NodeType::Hop),
            "destination" => Some(NodeType::Destination),
            _ => None,
        }
    }
    /// Get the string representation of the NodeType.
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeType::Gateway => "gateway",
            NodeType::Hop => "hop",
            NodeType::Destination => "destination",
        }
    }
    /// Get the display name of the NodeType.
    pub fn name(&self) -> String {
        match *self {
            NodeType::Gateway => String::from("Gateway"),
            NodeType::Hop => String::from("Hop"),
            NodeType::Destination => String::from("Destination"),
        }
    }
}

/// Service information detected on a port
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub quic_version: Option<String>,
    pub banner: Option<String>,
    pub raw: Option<String>,
    pub cpes: Vec<String>,
    pub tls_info: Option<TlsInfo>,
}

/// TLS information extracted from a TLS handshake
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub sni: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    /// Not before date in RFC2822 format
    pub not_before: Option<String>,
    /// Not after date in RFC2822 format
    pub not_after: Option<String>,
    pub san_list: Vec<String>,
    pub serial_hex: Option<String>,
    /// Signature algorithm name
    pub sig_algorithm: Option<String>,
    /// Public key algorithm name
    pub pubkey_algorithm: Option<String>,
}

/// Result of probing a specific port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: Port,
    pub state: PortState,
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub service: ServiceInfo,
}

/// OS guess information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsGuess {
    pub family: Option<String>,
    pub confidence: Option<f32>,
    pub ttl_observed: Option<u8>,
}

impl OsGuess {
    pub fn with_family(self, family: String) -> Self {
        Self {
            family: Some(family),
            confidence: None,
            ttl_observed: None,
        }
    }
    pub fn with_confidence(self, confidence: f32) -> Self {
        Self {
            family: self.family,
            confidence: Some(confidence),
            ttl_observed: self.ttl_observed,
        }
    }
    pub fn with_ttl_observed(self, ttl: u8) -> Self {
        Self {
            family: self.family,
            confidence: self.confidence,
            ttl_observed: Some(ttl),
        }
    }
}

/// Representation of a host (IP address and optional hostname)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            hostname: None,
        }
    }
}

impl Host {
    /// Create a new Host instance.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            ..Default::default()
        }
    }
    /// Create a new Host instance with the specified hostname.
    pub fn with_hostname(ip: IpAddr, hostname: String) -> Self {
        Self {
            ip,
            hostname: Some(hostname),
            ..Default::default()
        }
    }
}

/// Representation of an endpoint with IP, hostname, MAC address, tags, and ports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac_addr: Option<MacAddr>,
    pub tags: Vec<String>,
    pub ports: Vec<Port>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            hostname: None,
            mac_addr: None,
            tags: Vec::new(),
            ports: Vec::new(),
        }
    }
}

impl Endpoint {
    /// Create a new Endpoint instance.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            ..Default::default()
        }
    }
    /// Create a new Endpoint instance with the specified hostname.
    pub fn with_hostname(ip: IpAddr, hostname: String) -> Self {
        Self {
            ip,
            hostname: Some(hostname),
            ..Default::default()
        }
    }
    /// Add a port to the endpoint if it does not already exist.
    pub fn upsert_port(&mut self, port: Port) {
        if !self.ports.contains(&port) {
            self.ports.push(port);
        }
    }
    /// Merge another Endpoint into this one, combining tags and ports.
    pub fn merge(&mut self, other: Endpoint) {
        if self.hostname.is_none() {
            self.hostname = other.hostname;
        }
        if self.mac_addr.is_none() {
            self.mac_addr = other.mac_addr;
        }

        for t in other.tags {
            if !self.tags.contains(&t) {
                self.tags.push(t);
            }
        }

        for p in other.ports {
            if !self.ports.contains(&p) {
                self.ports.push(p);
            }
        }
    }
    /// Get the SocketAddr instances for the specified transport protocol.
    pub fn socket_addrs(&self, transport: TransportProtocol) -> Vec<SocketAddr> {
        self.ports
            .iter()
            .filter(|p| p.transport == transport)
            .map(|p| p.socket_addr(self.ip))
            .collect()
    }
}

/// Result of scanning an endpoint, including ports and OS guess
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac_addr: Option<MacAddr>,
    pub vendor_name: Option<String>,
    pub os: OsGuess,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, with = "ports_vec")]
    pub ports: BTreeMap<Port, PortResult>,
    pub cpes: Vec<String>,
}

impl Default for EndpointResult {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            hostname: None,
            mac_addr: None,
            vendor_name: None,
            os: OsGuess::default(),
            tags: Vec::new(),
            ports: BTreeMap::new(),
            cpes: Vec::new(),
        }
    }
}

impl EndpointResult {
    /// Create a new EndpointResult instance.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            ..Default::default()
        }
    }
    /// Create a new EndpointResult instance with the specified hostname.
    pub fn with_hostname(ip: IpAddr, hostname: String) -> Self {
        Self {
            ip,
            hostname: Some(hostname),
            ..Default::default()
        }
    }
    /// Add or update a PortResult in the endpoint's ports map.
    pub fn upsert_port(&mut self, pr: PortResult) {
        self.ports.insert(pr.port, pr);
    }
    /// Merge another EndpointResult into this one, combining tags, ports, and OS guess.
    pub fn merge(&mut self, other: EndpointResult) {
        if self.hostname.is_none() {
            self.hostname = other.hostname;
        }
        if self.mac_addr.is_none() {
            self.mac_addr = other.mac_addr;
        }
        if self.vendor_name.is_none() {
            self.vendor_name = other.vendor_name;
        }

        //self.cpes = other.cpes;
        let incoming: Vec<String> = other
            .cpes
            .into_iter()
            .filter(|c| !self.cpes.contains(c))
            .collect();

        self.cpes.extend(incoming);

        if other.os.confidence.unwrap_or(0.0) > self.os.confidence.unwrap_or(0.0) {
            self.os = other.os;
        } else if self.os.ttl_observed.is_none() && other.os.ttl_observed.is_some() {
            self.os.ttl_observed = other.os.ttl_observed;
        }

        for t in other.tags {
            if !self.tags.contains(&t) {
                self.tags.push(t);
            }
        }

        for (k, v) in other.ports {
            // check service data exists
            if let Some(existing) = self.ports.get_mut(&k) {
                if existing.service.banner.is_none() {
                    self.ports.insert(k, v);
                }
            } else {
                self.ports.insert(k, v);
            }
        }
    }
    /// Get the SocketAddr instances for the specified transport protocol.
    pub fn socket_addrs(&self, transport: TransportProtocol) -> Vec<SocketAddr> {
        self.ports
            .keys()
            .filter(|p| p.transport == transport)
            .map(|p| p.socket_addr(self.ip))
            .collect()
    }
    /// Convert to a simpler Endpoint representation.
    pub fn to_endpoint(&self) -> Endpoint {
        Endpoint {
            ip: self.ip,
            hostname: self.hostname.clone(),
            mac_addr: self.mac_addr,
            tags: self.tags.clone(),
            ports: self.ports.keys().cloned().collect(),
        }
    }
    /// Get a list of open ports.
    pub fn get_open_ports(&self) -> Vec<Port> {
        self.ports
            .iter()
            .filter(|(_, v)| v.state == PortState::Open)
            .map(|(k, _)| *k)
            .collect()
    }
    /// Get an active Endpoint if there are any open ports.
    pub fn active_endpoint(&self) -> Option<Endpoint> {
        let open_ports = self.get_open_ports();
        if open_ports.is_empty() {
            None
        } else {
            Some(Endpoint {
                ip: self.ip,
                hostname: self.hostname.clone(),
                mac_addr: self.mac_addr,
                tags: self.tags.clone(),
                ports: open_ports,
            })
        }
    }
}

impl From<IpAddr> for EndpointResult {
    fn from(ip: IpAddr) -> Self {
        EndpointResult::new(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string_pretty};

    #[test]
    fn ports_roundtrip() {
        let mut ep = EndpointResult::new("93.184.216.34".parse().unwrap());
        ep.upsert_port(PortResult {
            port: Port::new(80, TransportProtocol::Tcp),
            state: PortState::Open,
            rtt_ms: Some(23),
            service: ServiceInfo {
                name: Some("http".into()),
                ..Default::default()
            },
        });
        ep.upsert_port(PortResult {
            port: Port::new(443, TransportProtocol::Tcp),
            state: PortState::Open,
            rtt_ms: None,
            service: ServiceInfo {
                name: Some("https".into()),
                tls_info: Some(TlsInfo {
                    version: Some("TLS 1.2".into()),
                    cipher_suite: Some("TLS_AES_128_GCM_SHA256".into()),
                    alpn: Some("h2".into()),
                    sni: Some("example.com".into()),
                    subject: Some("CN=example.com".into()),
                    issuer: Some("CN=Example CA".into()),
                    not_before: Some("2023-01-01T00:00:00Z".into()),
                    not_after: Some("2024-01-01T00:00:00Z".into()),
                    san_list: vec!["example.com".into(), "www.example.com".into()],
                    serial_hex: Some("1234567890abcdef".into()),
                    sig_algorithm: Some("sha256WithRSAEncryption".into()),
                    pubkey_algorithm: Some("RSA".into()),
                }),
                ..Default::default()
            },
        });

        let json = to_string_pretty(&ep).unwrap();

        assert!(json.contains("\"ports\": ["));

        let back: EndpointResult = from_str(&json).unwrap();
        assert_eq!(back.ports.len(), 2);
        assert!(back
            .ports
            .contains_key(&Port::new(80, TransportProtocol::Tcp)));
        assert!(back
            .ports
            .contains_key(&Port::new(443, TransportProtocol::Tcp)));
    }
}
