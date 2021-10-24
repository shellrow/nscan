use clap::ArgMatches;
use dns_lookup::lookup_host;
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
        if matches.is_present("detail") {
            opt.set_include_detail(true);
        }
        if matches.is_present("acceptinvalidcerts") {
            opt.set_accept_invalid_certs(true);
        }
        if let Some(s) = matches.value_of("save") {
            opt.set_save_file_path(s.to_string());
        }
    }
    return opt;
}

pub fn parse_host_args(matches: ArgMatches) -> option::HostOption {
    let mut opt = option::HostOption::new();
    if let Some(v) = matches.value_of("host") {
        match network::get_network_address(v.to_string()) {
            Ok(nw_addr) => {
                opt.set_dst_hosts_from_na(nw_addr);
            },
            Err(e) => {
                print!("{}", e);
                std::process::exit(0);
            },
        }
        if let Some(w) = matches.value_of("list") {
            opt.set_dst_hosts_from_list(w.to_string());
        }
        if let Some(t) = matches.value_of("timeout") {
            opt.set_timeout(t.parse::<u64>().unwrap_or(30000));
        }
        if let Some(a) = matches.value_of("waittime") {
            opt.set_wait_time(a.parse::<u64>().unwrap_or(200));
        }
        if matches.is_present("detail") {
            opt.set_include_detail(true);
        }
        if let Some(s) = matches.value_of("save") {
            opt.set_save_file_path(s.to_string());
        }
        if let Some(i) = matches.value_of("interface") {
            opt.set_src_ip(i.to_string());
        }
    }
    return opt;
}
