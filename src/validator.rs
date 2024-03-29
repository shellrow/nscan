use crate::interface;
use ipnet::IpNet;
use netprobe::dns;
use regex::Regex;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

pub fn validate_port_opt(v: &str) -> Result<(), String> {
    let re_addr_range = Regex::new(r"\S+:\d+-\d+$").unwrap();
    let re_addr_csv = Regex::new(r"\S+:[0-9]+(?:,[0-9]+)*$").unwrap();
    let re_host_range = Regex::new(r"[\w\-._]+\.[A-Za-z]+:\d+-\d+$").unwrap();
    let re_host_csv = Regex::new(r"[\w\-._]+\.[A-Za-z]+:[0-9]+(?:,[0-9]+)*$").unwrap();
    match IpAddr::from_str(v) {
        Ok(_) => return Ok(()),
        Err(_) => {
            let addr_vec: Vec<&str> = v.split(":").collect();
            if addr_vec.len() > 1 {
                if !re_addr_range.is_match(&v)
                    && !re_addr_csv.is_match(&v)
                    && !re_host_range.is_match(&v)
                    && !re_host_csv.is_match(&v)
                {
                    return Err(String::from(
                        "Please specify ip address(or hostname) and port number.",
                    ));
                }
            }
            match IpAddr::from_str(addr_vec[0]) {
                Ok(_) => return Ok(()),
                Err(_) => {
                    if dns::lookup_host_name(addr_vec[0].to_string()).is_none() {
                        return Err(format!("Invalid target: {}", addr_vec[0]));
                    }
                }
            }
        },
    }
    Ok(())
}

pub fn validate_network_opt(v: &str) -> Result<(), String> {
    match v.parse::<IpNet>() {
        Ok(_) => return Ok(()),
        Err(_) => match IpAddr::from_str(&v) {
            Ok(_) => return Ok(()),
            Err(_) => {
                return Err(String::from("Please specify network address"));
            }
        },
    }
}

pub fn validate_hostscan_opt(v: &str) -> Result<(), String> {
    match validate_network_opt(v) {
        Ok(_) => return Ok(()),
        Err(_) => {}
    }
    if Path::new(&v).exists() {
        return Ok(());
    } else {
        let ip_vec: Vec<&str> = v.split(",").collect();
        for ip_str in ip_vec {
            match IpAddr::from_str(&ip_str) {
                Ok(_) => {}
                Err(_) => match SocketAddr::from_str(&ip_str) {
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(_) => {
                        if dns::lookup_host_name(ip_str.to_string()).is_none() {
                            return Err(format!("Invalid target: {}", ip_str));
                        }
                    }
                },
            }
        }
    }
    Ok(())
}

pub fn validate_filepath(v: &str) -> Result<(), String> {
    if !Path::new(&v).exists() {
        return Err(format!("File {} does not exist", v));
    }
    Ok(())
}

pub fn validate_timeout(v: &str) -> Result<(), String> {
    let timeout_v = v.parse::<u64>();
    match timeout_v {
        Ok(timeout) => {
            if timeout <= 0 {
                return Err(String::from("Invalid timeout value"));
            }
        }
        Err(_) => {
            return Err(String::from("Invalid timeout value"));
        }
    }
    Ok(())
}

pub fn validate_waittime(v: &str) -> Result<(), String> {
    let wait_time = v.parse::<u64>();
    match wait_time {
        Ok(_) => Ok(()),
        Err(_) => {
            return Err(String::from("Invalid wait time value"));
        }
    }
}

pub fn validate_interface(v: &str) -> Result<(), String> {
    match interface::get_interface_by_name(v.to_string()) {
        Some(_) => Ok(()),
        None => {
            return Err(String::from("Invalid interface name"));
        }
    }
}

pub fn validate_portscantype(v: &str) -> Result<(), String> {
    let valid_scan_types = vec!["SYN", "CONNECT"];
    if valid_scan_types.contains(&v) {
        Ok(())
    } else {
        Err(String::from("Invalid PortScanType"))
    }
}

pub fn validate_protocol(v: &str) -> Result<(), String> {
    let valid_protocols = vec!["ICMP", "ICMPv4", "ICMPv6", "TCP", "UDP"];
    if valid_protocols.contains(&v) {
        Ok(())
    } else {
        Err(String::from("Invalid Protocol"))
    }
}

pub fn validate_count(v: &str) -> Result<(), String> {
    match v.parse::<u8>() {
        Ok(_) => Ok(()),
        Err(_) => {
            return Err(String::from("Invalid value"));
        }
    }
}

pub fn validate_ip_address(v: &str) -> Result<(), String> {
    match IpAddr::from_str(&v) {
        Ok(_) => Ok(()),
        Err(_) => {
            return Err(String::from("Invalid IP Address"));
        }
    }
}

pub fn is_ipaddr(host: String) -> bool {
    let ipaddr = IpAddr::from_str(&host);
    match ipaddr {
        Ok(_) => {
            return true;
        }
        Err(_) => {
            return false;
        }
    }
}

pub fn is_socketaddr(host: String) -> bool {
    let socket_addr = SocketAddr::from_str(&host);
    match socket_addr {
        Ok(_) => {
            return true;
        }
        Err(_) => {
            return false;
        }
    }
}
