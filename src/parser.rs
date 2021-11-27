use clap::ArgMatches;
use dns_lookup::lookup_host;
use std::net::IpAddr;
use std::str::FromStr;
use crate::option;
use crate::validator;
use crate::db;
use crate::network;

pub fn parse_port_args(matches: ArgMatches) -> option::PortOption {
    let mut opt = option::PortOption::new();
    if let Some(v) = matches.value_of("port") {
        let socketaddr_vec: Vec<&str> = v.split(":").collect();
        let host = socketaddr_vec[0].to_string();
        opt.set_src_port(65432);
        if validator::is_ipaddr(host.clone()) {
            opt.set_dst_ip_addr(host);
        }else {
            opt.set_dst_host_name(host.clone());
            match lookup_host(&host) {
                Ok(addrs) => {
                    for addr in addrs {
                        if addr.is_ipv4() {
                            opt.set_dst_ip_addr(addr.to_string());
                            opt.set_dst_host_name(host);
                            break;
                        }
                    }
                },
                Err(_) => {},
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
                    opt.set_dst_ports_from_range(s, e);
                }
            }else if port_opt.contains(",") {
                opt.set_dst_ports_from_csv(port_opt);
            }
        }else{
            opt.set_default_scan(true);
            opt.set_dst_ports(db::get_default_ports());
        }
        if let Some(w) = matches.value_of("list") {
            opt.set_dst_ports_from_list(w.to_string());
        }
        if let Some(i) = matches.value_of("interface") {
            opt.set_src_ip(i.to_string());
        }
        if let Some(t) = matches.value_of("timeout") {
            opt.set_timeout(t.parse::<u64>().unwrap_or(30000));
        }
        if let Some(a) = matches.value_of("waittime") {
            opt.set_wait_time(a.parse::<u64>().unwrap_or(100));
        }
        if let Some(p) = matches.value_of("portscantype") {
            opt.set_scan_type(p.to_string());
        }
        if matches.is_present("service") {
            opt.set_service_detection(true);
        }
        if matches.is_present("acceptinvalidcerts") {
            opt.set_accept_invalid_certs(true);
        }
        if let Some(s) = matches.value_of("output") {
            opt.set_save_file_path(s.to_string());
        }
        if matches.is_present("async") {
            opt.set_async_scan(true);
        }
        if matches.is_present("OS") {
            opt.set_os_detection(true);
        }
    }
    return opt;
}

pub fn parse_host_args(matches: ArgMatches) -> option::HostOption {
    let mut opt = option::HostOption::new();
    if matches.is_present("network") || matches.is_present("host") {
        if let Some(v) = matches.value_of("network") {
            match network::get_network_address(v.to_string()) {
                Ok(nw_addr) => {
                    opt.set_dst_hosts_from_na(nw_addr);
                },
                Err(e) => {
                    print!("{}", e);
                    std::process::exit(0);
                },
            }
        }
        if let Some(v) = matches.value_of("host") {
            match validator::validate_filepath(v.to_string()) {
                Ok(_) => {
                    opt.set_dst_hosts_from_list(v.to_string());
                },
                Err(_) => {
                    let ip_vec: Vec<&str> = v.split(",").collect();
                    for ip_str in ip_vec {
                        match IpAddr::from_str(&ip_str) {
                            Ok(ip) => {
                                opt.add_dst_host(ip.to_string());
                            },
                            Err(_) => {
                                if let Some(ip) = network::lookup_host_name(ip_str.to_string()) {
                                    opt.add_dst_host(ip.to_string());
                                }
                            },
                        }
                    }
                },
            }
        }
        if let Some(t) = matches.value_of("timeout") {
            opt.set_timeout(t.parse::<u64>().unwrap_or(30000));
        }
        if let Some(a) = matches.value_of("waittime") {
            opt.set_wait_time(a.parse::<u64>().unwrap_or(200));
        }
        if let Some(s) = matches.value_of("output") {
            opt.set_save_file_path(s.to_string());
        }
        if let Some(i) = matches.value_of("interface") {
            opt.set_src_ip(i.to_string());
        }
        if matches.is_present("async") {
            opt.set_async_scan(true);
        }
        if matches.is_present("OS") {
            opt.set_os_detection(true);
        }
    }
    return opt;
}
