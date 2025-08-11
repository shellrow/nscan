use std::net::{IpAddr, Ipv4Addr};
use netdev::{Interface, MacAddr};
use anyhow::Result;
use nex::packet::{arp::ArpOperation, frame::{Frame, ParseOption}};

use crate::{nei::NetworkDevice, packet::setting::PacketBuildSetting};

pub fn send_arp(ipv4_addr: Ipv4Addr, iface: &Interface) -> Result<NetworkDevice> {
    let src_mac = iface.mac_addr.clone()
        .ok_or_else(|| anyhow::anyhow!("Interface does not have a MAC address"))?;
    let src_ip = iface.ipv4.iter()
        .map(|n| n.addr())
        .find(|ip| {
            let mask = iface.ipv4.iter().find(|n| n.contains(&ipv4_addr)).map(|n| n.netmask()).unwrap_or(Ipv4Addr::new(255,255,255,0));
            (u32::from(*ip) & u32::from(mask)) == (u32::from(ipv4_addr) & u32::from(mask))
        })
        .unwrap_or_else(|| iface.ipv4[0].addr());
    let next_hop = crate::ip::next_hop_ip(iface, IpAddr::V4(ipv4_addr))
        .ok_or_else(|| anyhow::anyhow!("No next hop found for {}", ipv4_addr))?;
    let build_setting = PacketBuildSetting {
        src_mac: src_mac,
        dst_mac: MacAddr::broadcast(),
        src_ip: IpAddr::V4(src_ip),
        dst_ip: next_hop,
        src_port: 0,
        dst_port: 0,
        hop_limit: 64,
        payload: Vec::new(),
        ip_packet: false,
    };
    let packet = crate::packet::arp::build_arp_packet(build_setting);

    let (mut tx, mut rx) = match nex::datalink::channel(&iface, Default::default()) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };
    match tx.send(&packet) {
        Some(_) => {},
        None => return Err(anyhow::anyhow!("Failed to send ARP Request")),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let frame = Frame::from_buf(&packet, ParseOption::default()).unwrap();
                match &frame.datalink {
                    Some(dlink) => {
                        if let Some(arp) = &dlink.arp {
                            if arp.operation == ArpOperation::Reply
                                && arp.sender_proto_addr == next_hop
                            {
                                return Ok(NetworkDevice {
                                    mac_addr: arp.sender_hw_addr,
                                    ipv4: vec![arp.sender_proto_addr],
                                    ipv6: Vec::new(),
                                });
                            }
                        }
                    }
                    None => continue,
                }
            }
            Err(e) => eprintln!("Receive failed: {}", e),
        }
    }
    
}
