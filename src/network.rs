use ipnet::{Ipv4Net, Ipv6Net};
use pnet_packet::{MutablePacket, Packet};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use std::thread;
use futures::stream::{self, StreamExt};
use trust_dns_resolver::{Resolver, AsyncResolver};
#[cfg(not(any(unix, target_os = "windows")))]
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

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

pub fn get_mac_through_arp(
    interface: &pnet_datalink::NetworkInterface,
    target_ip: Ipv4Addr,
) -> pnet_datalink::MacAddr {
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();

    let (mut sender, mut receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet =
        pnet_packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(pnet_datalink::MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(pnet_packet::ethernet::EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = pnet_packet::arp::MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet_packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(pnet_packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet_packet::arp::ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(pnet_datalink::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    let mut target_mac_addr: pnet_datalink::MacAddr = pnet_datalink::MacAddr::zero();

    for _x in 0..2 {
        let buf = receiver.next().unwrap();
        let arp = pnet_packet::arp::ArpPacket::new(
            &buf[pnet_packet::ethernet::MutableEthernetPacket::minimum_packet_size()..],
        )
        .unwrap();
        if arp.get_sender_hw_addr() != interface.mac.unwrap() {
            target_mac_addr = arp.get_sender_hw_addr();
            break;
        }
    }
    return target_mac_addr;
}

pub fn get_mac_addresses(ips: Vec<IpAddr>, src_ip: IpAddr) -> HashMap<IpAddr, String> {
    let mut map: HashMap<IpAddr, String> = HashMap::new();
    if let Some(c_interface) = get_interface_by_ip(src_ip) {
        let interfaces = pnet_datalink::interfaces();
        let iface = interfaces
            .into_iter()
            .filter(|interface: &pnet_datalink::NetworkInterface| {
                interface.index == c_interface.index
            })
            .next()
            .expect("Failed to get Interface");
        for ip in ips {
            if !is_global_addr(ip) && in_same_network(src_ip, ip) {
                let mac_addr =
                    get_mac_through_arp(&iface, ip.to_string().parse::<Ipv4Addr>().unwrap())
                        .to_string();
                map.insert(ip, mac_addr);
            }
        }
    }
    map
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

pub fn lookup_host_name(host_name: String) -> Option<IpAddr> {
    let ip_vec: Vec<IpAddr> = resolve_domain(host_name);
    let mut ipv6_vec: Vec<IpAddr> = vec![];
    for ip in ip_vec {
        match ip {
            IpAddr::V4(_) => {
                return Some(ip);
            }
            IpAddr::V6(_) => {
                ipv6_vec.push(ip);
            }
        }
    }
    if ipv6_vec.len() > 0 {
        return Some(ipv6_vec[0]);
    } else {
        None
    }
}

pub fn lookup_ip_addr(ip_addr: String) -> String {
    let ips: Vec<String> = resolve_ip(ip_addr);
    if ips.len() > 0 {
        return ips[0].clone();
    } else {
        return String::new();
    }
}

#[cfg(any(unix, target_os = "windows"))]
fn resolve_domain(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = Resolver::from_system_conf().unwrap();
    match resolver.lookup_ip(host_name) {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        },
        Err(_) => {},
    }
    ips
}

#[cfg(not(any(unix, target_os = "windows")))]
fn resolve_domain(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.lookup_ip(host_name) {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        },
        Err(_) => {},
    }
    ips
}

#[cfg(any(unix, target_os = "windows"))]
fn resolve_ip(ip_addr: String) -> Vec<String> {
    let ip_addr: IpAddr = IpAddr::from_str(ip_addr.as_str()).unwrap();
    let mut names: Vec<String> = vec![];
    let mut system_conf = trust_dns_resolver::system_conf::read_system_conf().unwrap();
    if is_global_addr(ip_addr) {
        system_conf.1.timeout = Duration::from_millis(1000);
    }else{
        system_conf.1.timeout = Duration::from_millis(200);
    }
    let resolver = Resolver::new(system_conf.0, system_conf.1).unwrap();
    match resolver.reverse_lookup(ip_addr) {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len()-1].to_string());
                        }else {
                            names.push(name);
                        }
                    },
                    None => {},
                }
            }
            names
        },
        Err(_) => {
            return names;
        },
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn resolve_ip(ip_addr: String) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.reverse_lookup(IpAddr::from_str(ip_addr.as_str()).unwrap()) {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len()-1].to_string());
                        }else {
                            names.push(name);
                        }
                    },
                    None => {},
                }
            }
            names
        },
        Err(_) => {
            return names;
        },
    }
}


#[cfg(any(unix, target_os = "windows"))]
#[allow(dead_code)]
async fn resolve_domain_async(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = AsyncResolver::tokio_from_system_conf().unwrap();
    match resolver.lookup_ip(host_name).await {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        },
        Err(_) => {},
    }
    ips
}

#[cfg(not(any(unix, target_os = "windows")))]
#[allow(dead_code)]
async fn resolve_domain_async(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.lookup_ip(host_name).await {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        },
        Err(_) => {},
    }
    ips
}

#[cfg(any(unix, target_os = "windows"))]
async fn resolve_ip_async(ip_addr: String) -> Vec<String> {
    let ip_addr: IpAddr = IpAddr::from_str(ip_addr.as_str()).unwrap();
    let mut names: Vec<String> = vec![];
    let mut system_conf = trust_dns_resolver::system_conf::read_system_conf().unwrap();
    if is_global_addr(ip_addr) {
        system_conf.1.timeout = Duration::from_millis(1000);
    }else{
        system_conf.1.timeout = Duration::from_millis(200);
    }
    let resolver = AsyncResolver::tokio(system_conf.0, system_conf.1).unwrap();
    match resolver.reverse_lookup(ip_addr).await {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len()-1].to_string());
                        }else {
                            names.push(name);
                        }
                    },
                    None => {},
                }
            }
            names
        },
        Err(_) => {
            return names;
        },
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
async fn resolve_ip_async(ip_addr: String) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.reverse_lookup(IpAddr::from_str(ip_addr.as_str()).unwrap()).await {
        Ok(rlookup) => {
            for record in rlookup.as_lookup().record_iter() {
                match record.data() {
                    Some(data) => {
                        let name = data.to_string();
                        if name.ends_with(".") {
                            names.push(name[0..name.len()-1].to_string());
                        }else {
                            names.push(name);
                        }
                    },
                    None => {},
                }
            }
            names
        },
        Err(_) => {
            return names;
        },
    }
}

pub async fn lookup_ips_async(ips: Vec<IpAddr>) -> HashMap<IpAddr, String> {
    let mut tasks = stream::iter(ips).map(|ip| {
        async move {
            let names = resolve_ip_async(ip.to_string()).await;
            (ip, names)
        }
    }).buffer_unordered(10);
    let mut results: HashMap<IpAddr, String> = HashMap::new();
    while let Some(result) = tasks.next().await {
        results.insert(result.0, result.1.first().unwrap_or(&String::new()).to_string());
    }
    results
}

pub fn lookup_ips(ips: Vec<IpAddr>) -> HashMap<IpAddr, String> {
    let rt: tokio::runtime::Runtime = tokio::runtime::Runtime::new().unwrap();
    let handle = thread::spawn(move || rt.block_on(async { lookup_ips_async(ips).await }));
    handle.join().unwrap()
}

pub fn get_interface_by_ip(ip_addr: IpAddr) -> Option<default_net::Interface> {
    for iface in default_net::get_interfaces() {
        match ip_addr {
            IpAddr::V4(ipv4) => {
                for ip in &iface.ipv4 {
                    if ip.addr == ipv4 {
                        return Some(iface);
                    }
                }
            }
            IpAddr::V6(ipv6) => {
                for ip in &iface.ipv6 {
                    if ip.addr == ipv6 {
                        return Some(iface);
                    }
                }
            }
        }
    }
    return None;
}

pub fn get_interface_by_name(if_name: String) -> Option<default_net::Interface> {
    for iface in default_net::get_interfaces() {
        if iface.name == if_name {
            return Some(iface);
        }
        if let Some(friendly_name) = &iface.friendly_name {
            if friendly_name == &if_name {
                return Some(iface);
            }
        }
    }
    return None;
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
