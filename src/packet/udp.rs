use crate::packet::setting::PacketBuildSetting;
use bytes::Bytes;
use netdev::MacAddr;
use nex::packet::builder::{
    ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
    udp::UdpPacketBuilder,
};
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::Ipv4Flags;
use nex::packet::packet::Packet;
use std::net::IpAddr;

/// Build UDP packet
pub fn build_udp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let udp_packet = UdpPacketBuilder::new(setting.src_ip, setting.dst_ip)
        .source(setting.src_port)
        .destination(setting.dst_port)
        .build();

    let ip_packet: Bytes = match (setting.src_ip, setting.dst_ip) {
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
        .source(if setting.ip_packet {
            MacAddr::zero()
        } else {
            setting.src_mac
        })
        .destination(if setting.ip_packet {
            MacAddr::zero()
        } else {
            setting.dst_mac
        })
        .ethertype(match setting.dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    let packet: Bytes = if setting.ip_packet {
        ethernet_packet.ip_packet().unwrap()
    } else {
        ethernet_packet.to_bytes()
    };

    packet.to_vec()
}

pub fn build_ip_next_udp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    // UDP Header
    let udp_packet = UdpPacketBuilder::new(setting.src_ip, setting.dst_ip)
        .source(setting.src_port)
        .destination(setting.dst_port)
        .build();
    udp_packet.to_bytes().to_vec()
}
