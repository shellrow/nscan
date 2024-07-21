use crate::packet::setting::PacketBuildSetting;
use nex::net::mac::MacAddr;
use nex::packet::ethernet::EtherType;
use nex::util::packet_builder::arp::ArpPacketBuilder;
use nex::util::packet_builder::builder::PacketBuilder;
use nex::util::packet_builder::ethernet::EthernetPacketBuilder;
use std::net::IpAddr;

/// Build ARP packet
pub fn build_arp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    // Ethernet Header
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: setting.src_mac,
        dst_mac: MacAddr::broadcast(),
        ether_type: EtherType::Arp,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match setting.src_ip {
        IpAddr::V4(src_ipv4) => {
            match setting.dst_ip {
                IpAddr::V4(dst_ipv4) => {
                    // ARP Header
                    let arp_packet = ArpPacketBuilder {
                        src_mac: setting.src_mac,
                        dst_mac: MacAddr::broadcast(),
                        src_ip: src_ipv4,
                        dst_ip: dst_ipv4,
                    };
                    packet_builder.set_arp(arp_packet);
                }
                IpAddr::V6(_) => {}
            }
        }
        IpAddr::V6(_) => {}
    }
    packet_builder.packet()
}
