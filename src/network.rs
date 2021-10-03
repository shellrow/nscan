use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use ipnet::{Ipv4Net, Ipv6Net};
use pnet::packet::{Packet, MutablePacket};

pub fn get_network_address(ip_str: String) -> Result<String, String>{
    let addr = IpAddr::from_str(&ip_str);
    match addr {
        Ok(ip_addr) => {
            match ip_addr {
                IpAddr::V4(ipv4_addr) => {
                    let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
                IpAddr::V6(ipv6_addr) => {
                    let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
            }
        },
        Err(_) => {
            Err(String::from("Invalid IP Address"))
        }
    }
}

pub fn get_mac_through_arp(interface: &pnet::datalink::NetworkInterface, target_ip: Ipv4Addr) -> pnet::datalink::MacAddr {
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();

    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(pnet::datalink::MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = pnet::packet::arp::MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet::packet::arp::ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(pnet::datalink::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    let mut target_mac_addr: pnet::datalink::MacAddr = pnet::datalink::MacAddr::zero();

    for _x in 0..2 {
        let buf = receiver.next().unwrap();
        let arp = pnet::packet::arp::ArpPacket::new(&buf[pnet::packet::ethernet::MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_hw_addr() != interface.mac.unwrap() {
            target_mac_addr = arp.get_sender_hw_addr();
            break;
        }
    }
    return target_mac_addr;
}
