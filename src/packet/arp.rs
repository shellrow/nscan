use netdev::Interface;
use nex::net::mac::MacAddr;
use nex::packet::builder::arp::ArpPacketBuilder;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Build ARP packet
pub fn build_arp_packet(interface: &Interface, dst_ip: IpAddr) -> Vec<u8> {
    let src_mac = interface.mac_addr.unwrap_or(MacAddr::zero());
    let src_ipv4 = crate::interface::get_interface_ipv4(interface).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let src_global_ipv6 =
        crate::interface::get_interface_global_ipv6(interface).unwrap_or(Ipv6Addr::UNSPECIFIED);
    let src_local_ipv6 =
        crate::interface::get_interface_local_ipv6(interface).unwrap_or(Ipv6Addr::UNSPECIFIED);

    let src_ip: IpAddr = match dst_ip {
        IpAddr::V4(_) => IpAddr::V4(src_ipv4),
        IpAddr::V6(_) => {
            if nex::net::ip::is_global_ip(&dst_ip) {
                IpAddr::V6(src_global_ipv6)
            } else {
                IpAddr::V6(src_local_ipv6)
            }
        }
    };

    match src_ip {
        IpAddr::V4(src_ipv4) => {
            match dst_ip {
                IpAddr::V4(dst_ipv4) => {
                    // ARP Header
                    let arp_builder = ArpPacketBuilder::new(src_mac, src_ipv4, dst_ipv4)
                        .operation(nex::packet::arp::ArpOperation::Request);
                    // Ethernet Header
                    let eth_builder = EthernetPacketBuilder::new()
                        .source(src_mac)
                        .destination(MacAddr::broadcast())
                        .ethertype(EtherType::Arp);

                    let packet = eth_builder.payload(arp_builder.build().to_bytes()).build();

                    return packet.to_bytes().to_vec();
                }
                IpAddr::V6(_) => {
                    // ARP is not used with IPv6, return empty vector
                    return Vec::new();
                }
            }
        }
        IpAddr::V6(_) => {
            return Vec::new(); // ARP is not used with IPv6
        }
    }
}
