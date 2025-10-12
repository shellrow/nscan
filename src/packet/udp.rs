use bytes::Bytes;
use netdev::{Interface, MacAddr};
use nex::packet::builder::{
    ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
    udp::UdpPacketBuilder,
};
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::Ipv4Flags;
use nex::packet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::default::DEFAULT_LOCAL_UDP_PORT;

/// Build UDP packet
pub fn build_udp_packet(interface: &Interface, dst_ip: IpAddr, dst_port: u16, is_ip_packet: bool) -> Vec<u8> {
    let src_mac = interface.mac_addr.unwrap_or(MacAddr::zero());
    let dst_mac = match &interface.gateway {
        Some(gateway) => gateway.mac_addr,
        None => MacAddr::zero(),
    };
    let src_ipv4 = crate::interface::get_interface_ipv4(interface).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let src_global_ipv6 =
        crate::interface::get_interface_global_ipv6(interface).unwrap_or(Ipv6Addr::UNSPECIFIED);
    let src_local_ipv6 =
        crate::interface::get_interface_local_ipv6(interface).unwrap_or(Ipv6Addr::UNSPECIFIED);

    let src_ip: IpAddr = match dst_ip {
        IpAddr::V4(_) => {
            IpAddr::V4(src_ipv4)
        },
        IpAddr::V6(_) => {
            if nex::net::ip::is_global_ip(&dst_ip) {
                IpAddr::V6(src_global_ipv6)
            } else {
                IpAddr::V6(src_local_ipv6)
            }
        },
    };

    let udp_packet = UdpPacketBuilder::new(src_ip, dst_ip)
        .source(DEFAULT_LOCAL_UDP_PORT)
        .destination(dst_port)
        .build();

    let ip_packet: Bytes = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
            .source(src)
            .destination(dst)
            .protocol(IpNextProtocol::Udp)
            .flags(Ipv4Flags::DontFragment)
            .payload(udp_packet.to_bytes())
            .build()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpNextProtocol::Udp)
            .payload(udp_packet.to_bytes())
            .build()
            .to_bytes(),
        _ => panic!("Source and destination IP version mismatch"),
    };

    let ethernet_packet = EthernetPacketBuilder::new()
        .source(if is_ip_packet {
            MacAddr::zero()
        } else {
            src_mac
        })
        .destination(if is_ip_packet {
            MacAddr::zero()
        } else {
            dst_mac
        })
        .ethertype(match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    let packet: Bytes = if is_ip_packet {
        ethernet_packet.ip_packet().unwrap()
    } else {
        ethernet_packet.to_bytes()
    };

    packet.to_vec()
}
