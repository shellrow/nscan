use regex::Regex;
use std::str::FromStr;
use std::net::IpAddr;
use std::path::Path;
use super::interface;

pub fn validate_port_opt(v: String) -> Result<(), String> {
    let re_range = Regex::new(r"\S+:\d+-\d+$").unwrap();
    let re_csv = Regex::new(r"\S+:[0-9]+(?:,[0-9]+)*$").unwrap();
    if !re_range.is_match(&v) && !re_csv.is_match(&v) && v.to_string().contains(":") {
        return Err(String::from("Please specify ip address and port number."));
    }
    let a_vec: Vec<&str> = v.split(":").collect();
    let addr = IpAddr::from_str(a_vec[0]);
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
    match interface::get_interface_index_by_name(v) {
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
