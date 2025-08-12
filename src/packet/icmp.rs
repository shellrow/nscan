use bytes::Bytes;
use netdev::MacAddr;
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
use std::net::IpAddr;

use crate::fp::setting::FingerprintType;
use crate::packet::setting::PacketBuildSetting;

/// Build ICMP packet. Supports both ICMPv4 and ICMPv6
pub fn build_icmp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let icmp_packet: Bytes = match (setting.src_ip, setting.dst_ip) {
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
        _ => panic!("Source and destination IP version mismatch"),
    };

    let ip_packet = match (setting.src_ip, setting.dst_ip) {
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

    if setting.ip_packet {
        ethernet_packet.ip_packet().unwrap().to_vec()
    } else {
        ethernet_packet.to_bytes().to_vec()
    }
}

/// Build ICMP probe packet. Supports both ICMPv4 and ICMPv6
pub fn build_icmp_probe_packet(
    setting: PacketBuildSetting,
    probe_type: FingerprintType,
) -> Vec<u8> {
    let icmp_packet: Bytes = match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let icmp_type = match probe_type {
                FingerprintType::IcmpEcho => IcmpType::EchoRequest,
                FingerprintType::IcmpTimestamp => IcmpType::TimestampRequest,
                FingerprintType::IcmpAddressMask => IcmpType::AddressMaskRequest,
                FingerprintType::IcmpInformation => IcmpType::InformationRequest,
                _ => IcmpType::EchoRequest,
            };
            IcmpPacketBuilder::new(src, dst)
                .icmp_type(icmp_type)
                .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
                .echo_fields(0x1234, 0x1)
                .payload(Bytes::from_static(b"hello"))
                .build()
                .to_bytes()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => Icmpv6PacketBuilder::new(src, dst)
            .icmpv6_type(Icmpv6Type::EchoRequest)
            .icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode)
            .echo_fields(0x1234, 0x1)
            .payload(Bytes::from_static(b"hello"))
            .build()
            .to_bytes(),
        _ => panic!("Source and destination IP version mismatch"),
    };

    let ip_packet = match (setting.src_ip, setting.dst_ip) {
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

    if setting.ip_packet {
        ethernet_packet.ip_packet().unwrap().to_vec()
    } else {
        ethernet_packet.to_bytes().to_vec()
    }
}

pub fn build_ip_next_icmp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    // ICMP Header
    let icmp_packet: Bytes = match (setting.src_ip, setting.dst_ip) {
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
        _ => panic!("Source and destination IP version mismatch"),
    };
    icmp_packet.to_vec()
}
