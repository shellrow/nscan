use super::validator;
use clap::ArgMatches;
use ipnet::IpNet;
use crate::ip;
use crate::option::HostScanType;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use rand::seq::SliceRandom;
use netprobe::dns;

use crate::interface;
use crate::option::{PortScanOption, HostScanOption, TargetInfo, PortListOption, PortScanType, IpNextLevelProtocol};

pub fn parse_port_args(matches: ArgMatches) -> Result<PortScanOption, String>  {
    if !matches.contains_id("port") {
        return Err("Invalid command".to_string());  
    }
    let mut opt: PortScanOption = PortScanOption::default();
    let target: &str = matches.value_of("port").unwrap();
    let socketaddr_vec: Vec<&str> = target.split(":").collect();
    let host: String = socketaddr_vec[0].to_string();
    let mut target_info: TargetInfo = TargetInfo::new();
    if validator::is_ipaddr(host.clone()) {
        target_info.ip_addr = host.parse::<IpAddr>().unwrap();
        target_info.host_name = dns::lookup_ip_addr(target_info.ip_addr).unwrap_or(host.clone());
    } else {
        match dns::lookup_host_name(host.clone()) {
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
                target_info.set_ports_from_range(s, e);
            }
        } else if port_opt.contains(",") {
            target_info.set_ports_from_csv(port_opt);
        }
    } else {
        if matches.contains_id("wellknown") {
            target_info.set_ports_from_option(PortListOption::Wellknown);
        } else if matches.contains_id("list") {
            let list: &str = matches.value_of("list").unwrap();
            match validator::validate_filepath(list) {
                Ok(_) => {
                    target_info.set_ports_from_list(list.to_string());
                }
                Err(_) => {
                    target_info.set_ports_from_option(PortListOption::Default);
                }
            }
        } else {
            target_info.set_ports_from_option(PortListOption::Default);
        }
    }
    opt.targets.push(target_info);

    // Flags
    if matches.contains_id("interface") {
        let v_interface: String = matches.get_one::<String>("interface").unwrap().to_string();
        if let Some(interface) = interface::get_interface_by_name(v_interface) {
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
    if matches.contains_id("scantype") {
        let v_scantype: String = matches.get_one::<String>("scantype").unwrap().to_string();
        if v_scantype.to_lowercase() == PortScanType::TcpSynScan.arg_name() {
            opt.scan_type = PortScanType::TcpSynScan;
        } else if v_scantype.to_lowercase() == PortScanType::TcpConnectScan.arg_name() {
            opt.scan_type = PortScanType::TcpConnectScan;
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
    if matches.contains_id("service") {
        opt.service_detection = true;
    }
    if matches.contains_id("async") {
        opt.async_scan = true;
    }
    if matches.contains_id("list") {
        let v_list: String = matches.get_one::<String>("list").unwrap().to_string();
        opt.list_file_path = v_list;
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
    // Randomize targets by default
    if !matches.contains_id("random") {        
        let mut rng = rand::thread_rng();
        for target in opt.targets.iter_mut() {
            target.ports.shuffle(&mut rng);
        }
        opt.targets.shuffle(&mut rng);
    }
    Ok(opt)
}

pub fn parse_host_args(matches: ArgMatches) -> Result<HostScanOption, String>  {
    if !matches.contains_id("host") {
        return Err("Invalid command".to_string());  
    }
    let mut opt: HostScanOption = HostScanOption::default();
    // Set protocol
    if matches.contains_id("protocol") {
        let v_protocol: String = matches.get_one::<String>("protocol").unwrap().to_string();
        if v_protocol.to_lowercase() == IpNextLevelProtocol::ICMPv4.id() {
            opt.protocol = IpNextLevelProtocol::ICMPv4;
            opt.scan_type = HostScanType::IcmpPingScan;
        } else if v_protocol.to_lowercase() == IpNextLevelProtocol::ICMPv6.id() {
            opt.protocol = IpNextLevelProtocol::ICMPv6;
            opt.scan_type = HostScanType::IcmpPingScan;
        } else if v_protocol.to_lowercase() == IpNextLevelProtocol::TCP.id() {
            opt.protocol = IpNextLevelProtocol::TCP;
            opt.scan_type = HostScanType::TcpPingScan;
        } else if v_protocol.to_lowercase() == IpNextLevelProtocol::UDP.id() {
            opt.protocol = IpNextLevelProtocol::UDP;
            opt.scan_type = HostScanType::UdpPingScan;
        }
    }
    if matches.contains_id("scantype") {
        let v_scantype: String = matches.get_one::<String>("scantype").unwrap().to_string();
        if v_scantype.to_lowercase() == HostScanType::IcmpPingScan.arg_name() {
            opt.scan_type = HostScanType::IcmpPingScan;
            if opt.protocol != IpNextLevelProtocol::ICMPv4 && opt.protocol != IpNextLevelProtocol::ICMPv6 {
                opt.protocol = IpNextLevelProtocol::ICMPv4;
            }
        } else if v_scantype.to_lowercase() == HostScanType::TcpPingScan.arg_name() {
            opt.scan_type = HostScanType::TcpPingScan;
            opt.protocol = IpNextLevelProtocol::TCP;
        } else if v_scantype.to_lowercase() == HostScanType::UdpPingScan.arg_name() {
            opt.scan_type = HostScanType::UdpPingScan;
            opt.protocol = IpNextLevelProtocol::UDP;
        }
    }
    // Set targets
    let target: &str = matches.value_of("host").unwrap();
    let target_vec: Vec<&str> = target.split("/").collect();
    let mut port: u16 = if opt.protocol == IpNextLevelProtocol::ICMPv4
        || opt.protocol == IpNextLevelProtocol::ICMPv6
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
        if ip_addr.is_ipv6() && opt.scan_type == HostScanType::IcmpPingScan {
            opt.protocol = IpNextLevelProtocol::ICMPv6;
        }
        let nw_addr: String = match ip::get_network_address(ip_addr) {
            Ok(nw_addr) => nw_addr,
            Err(e) => {
                print!("{}", e);
                std::process::exit(0);
            }
        };
        // network
        if opt.protocol == IpNextLevelProtocol::ICMPv6 {
            return Err("ICMPv6 network scan is not supported".to_string());
        }
        match target.parse::<IpNet>() {
            Ok(ipnet) => {
                let prefix_len: u8 = ipnet.prefix_len();
                opt.set_hosts_from_na(nw_addr, prefix_len, Some(port));
            }
            Err(_) => {
                opt.set_hosts_from_na(nw_addr, 24, Some(port));
            }
        }
    } else {
        // list
        match validator::validate_filepath(target) {
            Ok(_) => {
                opt.set_hosts_from_list(target.to_string(), None);
            }
            Err(_) => {
                let ip_vec: Vec<&str> = target.split(",").collect();
                for ip_str in ip_vec {
                    match IpAddr::from_str(&ip_str) {
                        Ok(ip) => {
                            opt.targets.push(TargetInfo::new_with_socket(ip, port));
                        }
                        Err(_) => {
                            if let Some(ip) = dns::lookup_host_name(ip_str.to_string()) {
                                opt.targets.push(TargetInfo::new_with_socket(ip, port));
                            }
                        }
                    }
                }
            }
        }
    }
    if opt.targets.len() > 0 {
        if crate::ip::is_global_addr(opt.targets[0].ip_addr) && opt.scan_type == HostScanType::IcmpPingScan {
            opt.wait_time = Duration::from_millis(1000);
        }
    }
    // Flags
    if matches.contains_id("interface") {
        let v_interface: String = matches.get_one::<String>("interface").unwrap().to_string();
        if let Some(interface) = interface::get_interface_by_name(v_interface) {
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
    if matches.contains_id("async") {
        opt.async_scan = true;
    }
    if matches.contains_id("list") {
        let v_list: String = matches.get_one::<String>("list").unwrap().to_string();
        opt.list_file_path = v_list;
    }
    if matches.contains_id("json") {
        opt.json_output = true;
    }
    if matches.contains_id("save") {
        let v_save: String = matches.get_one::<String>("save").unwrap().to_string();
        opt.save_file_path = v_save;
    }
    // Randomize targets by default
    if !matches.contains_id("random") {        
        let mut rng = rand::thread_rng();
        opt.targets.shuffle(&mut rng);
    }
    Ok(opt)
}
