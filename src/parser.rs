use super::define;
use super::process;
use super::validator;
use crate::db;
use crate::sys;
use crate::network;
use crate::option;
use crate::option::Protocol;
use crate::option::TargetInfo;
use clap::ArgMatches;
use ipnet::IpNet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

fn get_default_option() -> option::ScanOption {
    let mut opt = option::ScanOption::new();
    opt.src_port = define::DEFAULT_SRC_PORT;
    match default_net::get_default_interface() {
        Ok(interface) => {
            opt.interface_index = interface.index;
            opt.interface_name = interface.name;
            if interface.ipv4.len() > 0 {
                opt.src_ip = IpAddr::V4(interface.ipv4[0].addr);
            } else {
                if interface.ipv6.len() > 0 {
                    opt.src_ip = IpAddr::V6(interface.ipv6[0].addr);
                }
            }
        }
        Err(_) => {}
    }
    if process::privileged() {
        opt.port_scan_type = option::ScanType::TcpSynScan;
        if sys::get_os_type() == "windows" {
            opt.async_scan = false;
        }
    } else {
        opt.port_scan_type = option::ScanType::TcpConnectScan;
        opt.async_scan = true;
    }
    opt
}

pub fn parse_args(matches: ArgMatches) -> option::ScanOption {
    let mut opt = get_default_option();
    // Mode
    if matches.contains_id("port") {
        opt.command_type = option::CommandType::PortScan;
        let target: &str = matches.value_of("port").unwrap();
        let socketaddr_vec: Vec<&str> = target.split(":").collect();
        let host: String = socketaddr_vec[0].to_string();
        let mut target_info: TargetInfo = TargetInfo::new();
        if validator::is_ipaddr(host.clone()) {
            target_info.ip_addr = host.parse::<IpAddr>().unwrap();
            target_info.host_name = network::lookup_ip_addr(host);
        } else {
            match network::lookup_host_name(host.clone()) {
                Some(ip) => {
                    if ip.is_ipv4() {
                        target_info.ip_addr = ip;
                        target_info.host_name = host;
                    }
                }
                None => {}
            }
        }
        if socketaddr_vec.len() > 1 {
            let port_opt = socketaddr_vec[1].to_string();
            if port_opt.contains("-") {
                let range: Vec<&str> = port_opt.split("-").collect();
                let s: u16 = match range[0].parse::<u16>() {
                    Ok(s) => s,
                    Err(_) => 0,
                };
                let e: u16 = match range[1].parse::<u16>() {
                    Ok(e) => e,
                    Err(_) => 0,
                };
                if s != 0 && e != 0 && s < e {
                    target_info.set_dst_ports_from_range(s, e);
                }
            } else if port_opt.contains(",") {
                target_info.set_dst_ports_from_csv(port_opt);
            }
        } else {
            if matches.contains_id("wellknown") {
                opt.wellknown = true;
                target_info.ports = db::get_wellknown_ports();
            } else if matches.contains_id("list") {
                let list: &str = matches.value_of("list").unwrap();
                match validator::validate_filepath(list) {
                    Ok(_) => {
                        target_info.set_dst_ports_from_list(list.to_string());
                    }
                    Err(_) => {
                        target_info.ports = db::get_default_ports();
                    }
                }
            } else {
                opt.default_scan = true;
                target_info.ports = db::get_default_ports();
            }
        }
        opt.targets.push(target_info);
        opt.tcp_map = db::get_tcp_map();
    } else if matches.contains_id("host") {
        opt.command_type = option::CommandType::HostScan;
        opt.protocol = option::Protocol::ICMPv4;
        opt.host_scan_type = option::ScanType::IcmpPingScan;
        let target: &str = matches.value_of("host").unwrap();
        let target_vec: Vec<&str> = target.split("/").collect();
        let mut port: u16 = if opt.protocol == option::Protocol::ICMPv4
            || opt.protocol == option::Protocol::ICMPv6
        {
            0
        } else {
            80
        };
        if validator::is_ipaddr(target_vec[0].to_string())
            || validator::is_socketaddr(target_vec[0].to_string())
        {
            let ip_addr: IpAddr = if validator::is_socketaddr(target_vec[0].to_string()) {
                let socket_addr = SocketAddr::from_str(target_vec[0]).unwrap();
                port = socket_addr.port();
                socket_addr.ip()
            } else {
                IpAddr::from_str(target_vec[0]).unwrap()
            };
            let nw_addr: String = match network::get_network_address(ip_addr) {
                Ok(nw_addr) => nw_addr,
                Err(e) => {
                    print!("{}", e);
                    std::process::exit(0);
                }
            };
            // network
            match target.parse::<IpNet>() {
                Ok(ipnet) => {
                    let prefix_len: u8 = ipnet.prefix_len();
                    opt.set_dst_hosts_from_na(nw_addr, prefix_len, Some(port));
                }
                Err(_) => {
                    opt.set_dst_hosts_from_na(nw_addr, 24, Some(port));
                }
            }
        } else {
            // list
            match validator::validate_filepath(target) {
                Ok(_) => {
                    opt.set_dst_hosts_from_list(target.to_string());
                }
                Err(_) => {
                    let ip_vec: Vec<&str> = target.split(",").collect();
                    for ip_str in ip_vec {
                        match IpAddr::from_str(&ip_str) {
                            Ok(ip) => {
                                opt.targets.push(TargetInfo::new_with_socket(ip, port));
                            }
                            Err(_) => {
                                if let Some(ip) = network::lookup_host_name(ip_str.to_string()) {
                                    opt.targets.push(TargetInfo::new_with_socket(ip, port));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Flags
    if matches.contains_id("interface") {
        let v_interface: String = matches.get_one::<String>("interface").unwrap().to_string();
        if let Some(interface) = network::get_interface_by_name(v_interface) {
            opt.interface_index = interface.index;
            opt.interface_name = interface.name;
            if interface.ipv4.len() > 0 {
                opt.src_ip = IpAddr::V4(interface.ipv4[0].addr);
            } else {
                if interface.ipv6.len() > 0 {
                    opt.src_ip = IpAddr::V6(interface.ipv6[0].addr);
                }
            }
        }
    }
    if matches.contains_id("source") {
        let v_src_ip: String = matches.get_one::<String>("source").unwrap().to_string();
        match v_src_ip.parse::<IpAddr>() {
            Ok(ip_addr) => {
                opt.src_ip = ip_addr;
            }
            Err(_) => {}
        }
    }
    if matches.contains_id("protocol") {
        let v_protocol: String = matches.get_one::<String>("protocol").unwrap().to_string();
        if v_protocol == "TCP" || v_protocol == "tcp" {
            opt.protocol = Protocol::TCP;
            opt.host_scan_type = option::ScanType::TcpPingScan;
        } else if v_protocol == "UDP" || v_protocol == "udp" {
            opt.protocol = Protocol::UDP;
            opt.host_scan_type = option::ScanType::UdpPingScan;
        } else if v_protocol == "ICMPv4"
            || v_protocol == "icmpv4"
            || v_protocol == "ICMP"
            || v_protocol == "icmp"
        {
            opt.protocol = Protocol::ICMPv4;
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        } else if v_protocol == "ICMPv6" || v_protocol == "icmpv6" {
            opt.protocol = Protocol::ICMPv6;
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        }
    }
    if matches.contains_id("maxhop") {
        let v_maxhop: String = matches.get_one::<String>("maxhop").unwrap().to_string();
        match v_maxhop.parse::<u8>() {
            Ok(maxhop) => {
                opt.max_hop = maxhop;
            }
            Err(_) => {}
        }
    }
    if matches.contains_id("scantype") {
        let v_scantype: String = matches.get_one::<String>("scantype").unwrap().to_string();
        if v_scantype == "SYN" || v_scantype == "syn" {
            opt.port_scan_type = option::ScanType::TcpSynScan;
        } else if v_scantype == "CONNECT" || v_scantype == "connect" {
            opt.port_scan_type = option::ScanType::TcpConnectScan;
        } else if v_scantype == "ICMPv4" || v_scantype == "icmpv4" {
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        } else if v_scantype == "ICMPv6" || v_scantype == "icmpv6" {
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        } else if v_scantype == "TCP" || v_scantype == "tcp" {
            opt.host_scan_type = option::ScanType::TcpPingScan;
        } else if v_scantype == "UDP" || v_scantype == "udp" {
            opt.host_scan_type = option::ScanType::UdpPingScan;
        }
    }
    if matches.contains_id("timeout") {
        let v_timeout: u64 = matches
            .get_one::<String>("timeout")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        opt.timeout = Duration::from_millis(v_timeout);
    }
    if matches.contains_id("waittime") {
        let v_waittime: u64 = matches
            .get_one::<String>("waittime")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        opt.wait_time = Duration::from_millis(v_waittime);
    }
    if matches.contains_id("rate") {
        let v_rate: u64 = matches
            .get_one::<String>("rate")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        opt.send_rate = Duration::from_millis(v_rate);
    }
    if matches.contains_id("count") {
        let v_count: u32 = matches
            .get_one::<String>("count")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        opt.count = v_count;
    }
    if matches.contains_id("service") {
        opt.service_detection = true;
        opt.http_ports = db::get_http_ports();
        opt.https_ports = db::get_https_ports();
    }
    if matches.contains_id("os") {
        opt.os_detection = true;
    }
    if matches.contains_id("async") {
        opt.async_scan = true;
    }
    if matches.contains_id("list") {
        let v_list: String = matches.get_one::<String>("list").unwrap().to_string();
        opt.use_wordlist = true;
        opt.wordlist_path = v_list;
    }
    if matches.contains_id("json") {
        opt.json_output = true;
    }
    if matches.contains_id("save") {
        let v_save: String = matches.get_one::<String>("save").unwrap().to_string();
        opt.save_file_path = v_save;
    }
    if matches.contains_id("acceptinvalidcerts") {
        opt.accept_invalid_certs = true;
    }

    opt
}
