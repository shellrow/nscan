use anyhow::Result;
use bytes::Bytes;
use netdev::{Interface, MacAddr};
use nex::packet::builder::{
    ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
    tcp::TcpPacketBuilder,
};
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::Ipv4Flags;
use nex::packet::packet::Packet;
use nex::packet::tcp::{TcpFlags, TcpOptionPacket};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::default::DEFAULT_LOCAL_TCP_PORT;

/// Build TCP SYN packet with default options
pub fn build_tcp_syn_packet(
    interface: &Interface,
    dst_ip: IpAddr,
    dst_port: u16,
    is_ip_packet: bool,
) -> Result<Vec<u8>> {
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
        IpAddr::V4(_) => IpAddr::V4(src_ipv4),
        IpAddr::V6(_) => {
            if nex::net::ip::is_global_ip(&dst_ip) {
                IpAddr::V6(src_global_ipv6)
            } else {
                IpAddr::V6(src_local_ipv6)
            }
        }
    };

    // Packet builder for TCP SYN
    let tcp_packet = TcpPacketBuilder::new(src_ip, dst_ip)
        .source(DEFAULT_LOCAL_TCP_PORT)
        .destination(dst_port)
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

    let ip_packet = match (src_ip, dst_ip) {
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
        ethernet_packet
            .ip_packet()
            .ok_or_else(|| anyhow::anyhow!("failed to extract IP packet payload"))?
    } else {
        ethernet_packet.to_bytes()
    };
    Ok(packet.to_vec())
}
