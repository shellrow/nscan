use ipnet::{Ipv4Net, Ipv6Net};
use std::{net::{IpAddr, Ipv4Addr}, collections::HashMap, time::Duration};
use cross_socket::{datalink::interface::Interface, socket::DataLinkSocket, packet::builder::PacketBuildOption};
use cross_socket::datalink::MacAddr;

pub fn get_network_address(ip_addr: IpAddr) -> Result<String, String> {
    match ip_addr {
        IpAddr::V4(ipv4_addr) => {
            let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
            Ok(net.network().to_string())
        }
        IpAddr::V6(ipv6_addr) => {
            let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24).unwrap();
            Ok(net.network().to_string())
        }
    }
}

pub fn is_global_addr(ip_addr: IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ip) => !(ip.is_loopback() || ip.is_private()),
        IpAddr::V6(ip) => !(ip.is_loopback() || ((ip.segments()[0] & 0xfe00) == 0xfc00)),
    }
}

pub fn in_same_network(src_ip: IpAddr, dst_ip: IpAddr) -> bool {
    let src_ip_nw = match get_network_address(src_ip) {
        Ok(nw) => nw,
        Err(_) => return false,
    };
    let dst_ip_nw = match get_network_address(dst_ip) {
        Ok(nw) => nw,
        Err(_) => return false,
    };
    if src_ip_nw == dst_ip_nw {
        true
    } else {
        false
    }
}

pub fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    } else if 64 < ttl && ttl <= 128 {
        128
    } else {
        255
    }
}

fn get_mac_through_arp(
    interface: Interface,
    target_ip: Ipv4Addr,
) -> MacAddr {
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet option for ARP request
    let mut packet_option = PacketBuildOption::new();
    packet_option.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_option.dst_mac = MacAddr::zero();
    packet_option.ether_type = cross_socket::packet::ethernet::EtherType::Arp;
    packet_option.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_option.dst_ip = IpAddr::V4(target_ip);

    // Send ARP request to default gateway
    match socket.send(packet_option) {
        Ok(_) => {}
        Err(_) => {}
    }
    let src_mac = socket.interface.mac_addr.clone().unwrap();
    let timeout = Duration::from_millis(10000);
    let start = std::time::Instant::now();
    // Receive packets
    loop {
        match socket.receive() {
            Ok(packet) => {
                let ethernet_packet = cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                if ethernet_packet.ethertype != cross_socket::packet::ethernet::EtherType::Arp {
                    continue;
                }
                let arp_packet =
                    cross_socket::packet::arp::ArpPacket::from_bytes(&ethernet_packet.payload);
                if arp_packet.sender_hw_addr.address() != src_mac.address() {
                    return arp_packet.sender_hw_addr;
                }
            }
            Err(_) => {}
        }
        // break if timeout
        if start.elapsed() > timeout {
            return MacAddr::zero();
        }
    }
}

pub fn get_mac_addresses(ips: Vec<IpAddr>, src_ip: IpAddr) -> HashMap<IpAddr, String> {
    let mut map : HashMap<IpAddr, String> = HashMap::new();
    if let Some(c_interface) = crate::interface::get_interface_by_ip(src_ip) {
        for ip in ips {
            if !is_global_addr(ip) && in_same_network(src_ip, ip) {
                let mac_addr = get_mac_through_arp(c_interface.clone(), ip.to_string().parse::<Ipv4Addr>().unwrap()).to_string();
                map.insert(ip, mac_addr);
                /* if mac_addr.len() > 16 {
                    let prefix8 = mac_addr[0..8].to_uppercase();
                    vendor_map.insert(ip.to_string(), (mac_addr, oui_map.get(&prefix8).unwrap_or(&String::from("Unknown")).to_string()));
                }else{
                    vendor_map.insert(ip.to_string(), (mac_addr, String::from("Unknown")));
                } */
            }
        }
    }
    map
}
