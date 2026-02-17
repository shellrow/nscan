use bytes::Bytes;
use anyhow::Result;
use netdev::{Interface, MacAddr};
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::builder::icmp::IcmpPacketBuilder;
use nex::packet::builder::icmpv6::Icmpv6PacketBuilder;
use nex::packet::builder::ipv4::Ipv4PacketBuilder;
use nex::packet::builder::ipv6::Ipv6PacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::icmp;
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6;
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::Ipv4Flags;
use nex::packet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Build ICMP packet. Supports both ICMPv4 and ICMPv6
pub fn build_icmp_packet(interface: &Interface, dst_ip: IpAddr, is_ip_packet: bool) -> Result<Vec<u8>> {
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

    let icmp_packet: Bytes = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => IcmpPacketBuilder::new(src, dst)
            .icmp_type(IcmpType::EchoRequest)
            .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
            .echo_fields(0x1234, 0x1)
            .payload(Bytes::from_static(b"hello"))
            .build()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Icmpv6PacketBuilder::new(src, dst)
            .icmpv6_type(Icmpv6Type::EchoRequest)
            .icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode)
            .echo_fields(0x1234, 0x1)
            .payload(Bytes::from_static(b"hello"))
            .build()
            .to_bytes(),
        _ => anyhow::bail!("source and destination IP version mismatch"),
    };

    let ip_packet = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
            .source(src)
            .destination(dst)
            .protocol(IpNextProtocol::Icmp)
            .flags(Ipv4Flags::DontFragment)
            .payload(icmp_packet)
            .build()
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpNextProtocol::Icmpv6)
            .payload(icmp_packet)
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

    if is_ip_packet {
        Ok(ethernet_packet
            .ip_packet()
            .ok_or_else(|| anyhow::anyhow!("failed to extract IP packet payload"))?
            .to_vec())
    } else {
        Ok(ethernet_packet.to_bytes().to_vec())
    }
}
