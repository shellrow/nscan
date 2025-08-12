use crate::packet::setting::PacketBuildSetting;
use nex::net::mac::MacAddr;
use nex::packet::builder::arp::ArpPacketBuilder;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::packet::Packet;
use std::net::IpAddr;

/// Build ARP packet
pub fn build_arp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    match setting.src_ip {
        IpAddr::V4(src_ipv4) => {
            match setting.dst_ip {
                IpAddr::V4(dst_ipv4) => {
                    // ARP Header
                    let arp_builder = ArpPacketBuilder::new(setting.src_mac, src_ipv4, dst_ipv4)
                        .operation(nex::packet::arp::ArpOperation::Request);
                    // Ethernet Header
                    let eth_builder = EthernetPacketBuilder::new()
                        .source(setting.src_mac)
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
