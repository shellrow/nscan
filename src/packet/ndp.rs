use crate::packet::setting::PacketBuildSetting;
use nex::net::mac::MacAddr;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::builder::ipv6::Ipv6PacketBuilder;
use nex::packet::builder::ndp::NdpPacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextProtocol;
use nex::packet::packet::Packet;
use std::net::{IpAddr, Ipv6Addr};

/// Compute multicast MAC address from solicited-node multicast IPv6 address
fn ipv6_multicast_mac(ipv6: &Ipv6Addr) -> MacAddr {
    let segments = ipv6.segments();
    MacAddr::new(
        0x33,
        0x33,
        ((segments[6] >> 8) & 0xff) as u8,
        (segments[6] & 0xff) as u8,
        ((segments[7] >> 8) & 0xff) as u8,
        (segments[7] & 0xff) as u8,
    )
}

/// Build NDP packet
pub fn build_ndp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    // Build NDP packet
    //let ndp_payload_len = (NDP_SOL_PACKET_LEN + NDP_OPT_PACKET_LEN + MAC_ADDR_LEN) as u16;
    match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            panic!("NDP is not used with IPv4 addresses");
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ipv6 = Ipv6PacketBuilder::new()
                .source(src)
                .destination(dst)
                .next_header(IpNextProtocol::Icmpv6)
                .hop_limit(255);

            let dst_mac = ipv6_multicast_mac(&dst);

            let ndp = NdpPacketBuilder::new(setting.src_mac, src, dst);

            let ethernet = EthernetPacketBuilder::new()
                .source(setting.src_mac)
                .destination(dst_mac)
                .ethertype(EtherType::Ipv6)
                .payload(ipv6.payload(ndp.build().to_bytes()).build().to_bytes());

            let packet = ethernet.build().to_bytes();
            packet.to_vec()
        }
        _ => panic!("Source and destination IP versions must match"),
    }
}
