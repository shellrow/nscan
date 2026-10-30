use crate::endpoint::TransportProtocol;
use ndb_tcp_service::TcpServiceDb;
use ndb_udp_service::UdpServiceDb;
use std::sync::LazyLock;

/// Conventional registry label, not a detected service identity.
pub fn registered_name(port: u16, transport: TransportProtocol) -> Option<String> {
    static TCP: LazyLock<TcpServiceDb> = LazyLock::new(TcpServiceDb::bundled);
    static UDP: LazyLock<UdpServiceDb> = LazyLock::new(UdpServiceDb::bundled);
    match transport {
        TransportProtocol::Tcp => TCP.get_name(port).map(str::to_string),
        TransportProtocol::Udp | TransportProtocol::Quic => UDP.get_name(port).map(str::to_string),
    }
}
