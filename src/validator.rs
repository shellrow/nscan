use regex::Regex;
use std::str::FromStr;
use std::net::IpAddr;
use std::path::Path;
use dns_lookup::lookup_host;
use crate::interface;

pub fn validate_port_opt(v: String) -> Result<(), String> {
    let re_addr_range = Regex::new(r"\S+:\d+-\d+$").unwrap();
    let re_addr_csv = Regex::new(r"\S+:[0-9]+(?:,[0-9]+)*$").unwrap();
    let re_host_range = Regex::new(r"[\w\-._]+\.[A-Za-z]+:\d+-\d+$").unwrap();
    let re_host_csv = Regex::new(r"[\w\-._]+\.[A-Za-z]+:[0-9]+(?:,[0-9]+)*$").unwrap();
    if v.to_string().contains(":") {
        if !re_addr_range.is_match(&v) && !re_addr_csv.is_match(&v) && !re_host_range.is_match(&v) && !re_host_csv.is_match(&v) {
            return Err(String::from("Please specify ip address(or hostname) and port number."));
        }
    }
    let a_vec: Vec<&str> = v.split(":").collect();
    let ipaddr = IpAddr::from_str(a_vec[0]);
    match ipaddr {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            match lookup_host(a_vec[0]) {
                Ok(_) => {
                    return Ok(())
                },
                Err(_) => {
                    return Err(String::from("Please specify ip address or hostname"));
                },
            }
        }
    }
}

pub fn validate_network_opt(v: String) -> Result<(), String> {
    let addr = IpAddr::from_str(&v);
    match addr {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please specify ip address"));
        }
    }
}

pub fn validate_host_opt(v: String) -> Result<(), String> {
    let re_host = Regex::new(r"[\w\-._]+\.[A-Za-z]+").unwrap();
    if Path::new(&v).exists() {
        return Ok(());
    }else{
        let ip_vec: Vec<&str> = v.split(",").collect();
        for ip_str in ip_vec {
            match IpAddr::from_str(&ip_str) {
                Ok(_) => {},
                Err(_) => {
                    if !re_host.is_match(ip_str) {
                        return Err(String::from("Please specify ip address or host name"));
                    }
                }
            }
        }
    }
    Ok(())
}

/* pub fn validate_domain_opt(v: String) -> Result<(), String> {
    let re = Regex::new(r"[\w\-._]+\.[A-Za-z]+").unwrap();
    if !re.is_match(&v) {
        return Err(String::from("Please specify domain name"));
    }
    Ok(())
} */

pub fn validate_filepath(v: String) -> Result<(), String> {
    if !Path::new(&v).exists() {
        return Err(format!("File {} does not exist", v));
    }
    Ok(())
}

pub fn validate_timeout(v: String) -> Result<(), String> {
    let timeout_v = v.parse::<u64>();
    match timeout_v {
        Ok(timeout) => {
            if timeout <= 0 {
                return Err(String::from("Invalid timeout value"));
            }
        },
        Err(_) => {
            return Err(String::from("Invalid timeout value"));
        },
    }
    Ok(())
}

pub fn validate_waittime(v: String) -> Result<(), String> {
    let wait_time = v.parse::<u64>();
    match wait_time {
        Ok(_) => {
            Ok(())
        },
        Err(_) => {
            return Err(String::from("Invalid wait time value"));
        },
    }
}

pub fn validate_interface(v: String) -> Result<(), String> {
    let ip_addr = match IpAddr::from_str(&v) {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            return Err(String::from("Please specify ip address"));
        }
    };
    match interface::get_interface_index_by_ip(ip_addr) {
        Some(_)=>{
            Ok(())
        },
        None => {
            Err(String::from("Invalid network interface name"))
        },
    }
}

pub fn validate_portscantype(v: String) -> Result<(), String> {
    let valid_scan_types = vec!["SYN","CONNECT","FIN","XMAS","NULL"];
    if valid_scan_types.contains(&v.as_str()) {
        Ok(())
    }else{
        Err(String::from("Invalid PortScanType"))
    }
}

pub fn is_ipaddr(host: String) -> bool {
    let ipaddr = IpAddr::from_str(&host);
    match ipaddr {
        Ok(_) => {
            return true;
        },
        Err(_) => {
            return false;
        }
    }
}