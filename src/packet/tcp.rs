use crate::packet::setting::PacketBuildSetting;
use bytes::Bytes;
use netdev::MacAddr;
use nex::packet::builder::{
    ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
    tcp::TcpPacketBuilder,
};
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::Ipv4Flags;
use nex::packet::packet::Packet;
use nex::packet::tcp::{TcpFlags, TcpOptionPacket};
use std::net::IpAddr;

/// Build TCP SYN packet with default options
pub fn build_tcp_syn_packet(setting: PacketBuildSetting) -> Vec<u8> {
    // Packet builder for TCP SYN
    let tcp_packet = TcpPacketBuilder::new(setting.src_ip, setting.dst_ip)
        .source(setting.src_port)
        .destination(setting.dst_port)
        .flags(TcpFlags::SYN)
        .window(65535)
        .options(vec![
            TcpOptionPacket::mss(1460),
            TcpOptionPacket::nop(),
            TcpOptionPacket::wscale(6),
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::timestamp(u32::MAX, u32::MIN),
            TcpOptionPacket::sack_perm(),
        ])
        .build();

    let ip_packet = match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
            .source(src)
            .destination(dst)
            .protocol(IpNextProtocol::Tcp)
            .flags(Ipv4Flags::DontFragment)
            .payload(tcp_packet.to_bytes())
            .build()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpNextProtocol::Tcp)
            .payload(tcp_packet.to_bytes())
            .build()
            .to_bytes(),
        _ => unreachable!(),
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

    // Send TCP SYN packets
    let packet: Bytes = if setting.ip_packet {
        ethernet_packet.ip_packet().unwrap()
    } else {
        ethernet_packet.to_bytes()
    };
    packet.to_vec()
}

/// Build TCP SYN packet with minimum options
pub fn build_tcp_syn_packet_min(setting: PacketBuildSetting) -> Vec<u8> {
    // Packet builder for TCP SYN
    let tcp_packet = TcpPacketBuilder::new(setting.src_ip, setting.dst_ip)
        .source(setting.src_port)
        .destination(setting.dst_port)
        .flags(TcpFlags::SYN)
        .window(65535)
        .options(vec![
            TcpOptionPacket::mss(1460),
            TcpOptionPacket::sack_perm(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::wscale(7),
        ])
        .build();

    let ip_packet = match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
            .source(src)
            .destination(dst)
            .protocol(IpNextProtocol::Tcp)
            .flags(Ipv4Flags::DontFragment)
            .payload(tcp_packet.to_bytes())
            .build()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpNextProtocol::Tcp)
            .payload(tcp_packet.to_bytes())
            .build()
            .to_bytes(),
        _ => unreachable!(),
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

    // Send TCP SYN packets
    let packet: Bytes = if setting.ip_packet {
        ethernet_packet.ip_packet().unwrap()
    } else {
        ethernet_packet.to_bytes()
    };
    packet.to_vec()
}

pub fn build_ip_next_tcp_syn_packet(setting: PacketBuildSetting) -> Vec<u8> {
    // Packet builder for TCP SYN
    let tcp_packet = TcpPacketBuilder::new(setting.src_ip, setting.dst_ip)
        .source(setting.src_port)
        .destination(setting.dst_port)
        .flags(TcpFlags::SYN)
        .window(65535)
        .options(vec![
            TcpOptionPacket::mss(1460),
            TcpOptionPacket::nop(),
            TcpOptionPacket::wscale(6),
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::timestamp(u32::MAX, u32::MIN),
            TcpOptionPacket::sack_perm(),
        ])
        .build();
    tcp_packet.to_bytes().to_vec()
}
