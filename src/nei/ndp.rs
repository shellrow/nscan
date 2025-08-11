use std::net::{IpAddr, Ipv6Addr};
use netdev::{Interface, MacAddr};
use anyhow::Result;
use nex::packet::{frame::{Frame, ParseOption}, icmpv6::Icmpv6Type};

use crate::{nei::NetworkDevice, packet::setting::PacketBuildSetting};

pub fn send_ndp(ipv6_addr: Ipv6Addr, iface: &Interface) -> Result<NetworkDevice> {
    let src_ip = iface.ipv6.iter()
        .map(|n| n.addr())
        .find(|ip| ip.segments()[0] == 0xfe80)
        .unwrap_or_else(|| iface.ipv6[0].addr());
    let src_mac = iface.mac_addr.expect("No MAC address on interface");
    let next_hop = crate::ip::next_hop_ip(iface, IpAddr::V6(ipv6_addr))
        .ok_or_else(|| anyhow::anyhow!("No next hop found for {}", ipv6_addr))?;
    let build_setting = PacketBuildSetting {
        src_mac: src_mac,
        dst_mac: MacAddr::broadcast(),
        src_ip: IpAddr::V6(src_ip),
        dst_ip: next_hop,
        src_port: 0,
        dst_port: 0,
        hop_limit: 64,
        payload: Vec::new(),
        ip_packet: false,
    };
    let packet = crate::packet::ndp::build_ndp_packet(build_setting);

    let (mut tx, mut rx) = match nex::datalink::channel(&iface, Default::default()) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };

    match tx.send(&packet) {
        Some(_) => {},
        None => return Err(anyhow::anyhow!("Failed to send NDP Request")),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option = ParseOption::default();
                if iface.is_tun() {
                    parse_option.from_ip_packet = true;
                    parse_option.offset = if iface.is_loopback() { 14 } else { 0 };
                }

                if let Some(frame) = Frame::from_buf(&packet, parse_option) {
                    if let Some(ip_layer) = &frame.ip {
                        if let Some(icmpv6) = &ip_layer.icmpv6 {
                            if icmpv6.icmpv6_type == Icmpv6Type::NeighborAdvertisement {
                                if let Some(ipv6_hdr) = &ip_layer.ipv6 {
                                    if let Some(dlink) = &frame.datalink {
                                        if let Some(eth) = &dlink.ethernet {
                                            // eth.source is the MAC address of the device that replied
                                            if ipv6_hdr.destination == src_ip && ipv6_hdr.source == ipv6_addr {
                                                return Ok(NetworkDevice {
                                                    mac_addr: eth.source,
                                                    ipv4: Vec::new(),
                                                    ipv6: vec![ipv6_hdr.source],
                                                });
                                            } else {
                                                eprintln!("Received NDP reply from unexpected source: {}", ipv6_hdr.source);
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Receive failed: {}", e),
        }
    }
}
