use crate::output;
use crate::ping::{pinger::Pinger, result::PingResult, setting::PingSetting};
use crate::protocol::Protocol;
use crate::util::tree::node_label;
use clap::ArgMatches;
use netdev::Interface;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use termtree::Tree;

pub fn oneshot_ping(
    if_index: u32,
    dst_ip: IpAddr,
    protocol: Protocol,
    port: Option<u16>,
) -> Result<PingResult, String> {
    let interface: Interface = match crate::interface::get_interface_by_index(if_index) {
        Some(interface) => interface,
        None => return Err("Failed to get interface information".to_string()),
    };
    let setting: PingSetting = match protocol {
        Protocol::ICMP => PingSetting::icmp_ping(&interface, dst_ip, 1).unwrap(),
        Protocol::TCP => PingSetting::tcp_ping(&interface, dst_ip, port.unwrap_or(80), 1).unwrap(),
        Protocol::UDP => PingSetting::udp_ping(&interface, dst_ip, 1).unwrap(),
        _ => {
            return Err("Unsupported protoco".to_string());
        }
    };
    let pinger: Pinger = match Pinger::new(setting) {
        Ok(pinger) => pinger,
        Err(e) => return Err(format!("Failed to create pinger: {}", e)),
    };
    match pinger.ping() {
        Ok(ping_result) => {
            if ping_result.probe_status.kind == crate::probe::ProbeStatusKind::Done {
                Ok(ping_result)
            } else {
                Err(format!(
                    "Failed to ping: {}",
                    ping_result.probe_status.message
                ))
            }
        }
        Err(e) => Err(format!("Failed to ping: {}", e)),
    }
}

pub fn initial_ping(
    if_index: u32,
    target_ip_addr: IpAddr,
    target_host_name: String,
) -> Result<Duration, String> {
    // 1. Check reachability by ICMP ping (one-shot)
    match super::ping::oneshot_ping(if_index, target_ip_addr, Protocol::ICMP, None) {
        Ok(ping_result) => {
            let response = &ping_result.stat.responses[0];
            if target_host_name != target_ip_addr.to_string() {
                output::log_with_time(
                    &format!(
                        "[ICMP] {}({}) is up. RTT:{:?}",
                        target_host_name, target_ip_addr, response.rtt
                    ),
                    "INFO",
                );
            } else {
                output::log_with_time(
                    &format!("[ICMP] {} is up. RTT:{:?}", target_ip_addr, response.rtt),
                    "INFO",
                );
            }
            return Ok(crate::sys::time::ceil_duration_millis(
                response.rtt.mul_f64(1.5),
            ));
        }
        Err(e) => {
            output::log_with_time(&format!("[ICMP] {}", e), "ERROR");
            output::log_with_time(
                &format!(
                    "[ICMP] {}({}) is down or unreachable.",
                    target_host_name, target_ip_addr
                ),
                "ERROR",
            );
        }
    }
    // 2. Check reachability by UDP ping (one-shot)
    match super::ping::oneshot_ping(if_index, target_ip_addr, Protocol::UDP, None) {
        Ok(ping_result) => {
            let response = &ping_result.stat.responses[0];
            if target_host_name != target_ip_addr.to_string() {
                output::log_with_time(
                    &format!(
                        "[UDP] {}({}) is up. RTT:{:?}",
                        target_host_name, target_ip_addr, response.rtt
                    ),
                    "INFO",
                );
            } else {
                output::log_with_time(
                    &format!("[UDP] {} is up. RTT:{:?}", target_ip_addr, response.rtt),
                    "INFO",
                );
            }
            return Ok(crate::sys::time::ceil_duration_millis(
                response.rtt.mul_f64(1.5),
            ));
        }
        Err(e) => {
            output::log_with_time(&format!("[UDP] {}", e), "ERROR");
            output::log_with_time(
                &format!(
                    "[UDP] {}({}) is down or unreachable.",
                    target_host_name, target_ip_addr
                ),
                "ERROR",
            );
        }
    }
    // 3. Check reachability by TCP ping (one-shot)
    match super::ping::oneshot_ping(if_index, target_ip_addr, Protocol::TCP, Some(80)) {
        Ok(ping_result) => {
            let response = &ping_result.stat.responses[0];
            if target_host_name != target_ip_addr.to_string() {
                output::log_with_time(
                    &format!(
                        "[TCP] {}({}) is up. RTT:{:?}",
                        target_host_name, target_ip_addr, response.rtt
                    ),
                    "INFO",
                );
            } else {
                output::log_with_time(
                    &format!("[TCP] {} is up. RTT:{:?}", target_ip_addr, response.rtt),
                    "INFO",
                );
            }
            return Ok(crate::sys::time::ceil_duration_millis(
                response.rtt.mul_f64(1.5),
            ));
        }
        Err(e) => {
            output::log_with_time(&format!("[TCP] {}", e), "ERROR");
            output::log_with_time(
                &format!(
                    "[TCP] {}({}) is down or unreachable.",
                    target_host_name, target_ip_addr
                ),
                "ERROR",
            );
        }
    }
    Err(format!(
        "Failed to initial ping to {}({})",
        target_host_name, target_ip_addr
    ))
}

pub fn handle_ping(args: &ArgMatches) {
    output::log_with_time("Initiating ping...", "INFO");
    let ping_args = match args.subcommand_matches("ping") {
        Some(matches) => matches,
        None => return,
    };
    let interface: netdev::Interface = if let Some(if_name) = args.get_one::<String>("interface") {
        match crate::interface::get_interface_by_name(if_name.to_string()) {
            Some(iface) => iface,
            None => return,
        }
    } else {
        match netdev::get_default_interface() {
            Ok(iface) => iface,
            Err(_) => return,
        }
    };
    let target: String = match ping_args.get_one::<String>("target") {
        Some(target) => target.to_owned(),
        None => return,
    };
    let count: u32 = match ping_args.get_one::<u32>("count") {
        Some(count) => *count,
        None => 4,
    };
    let maxhop: u8 = match ping_args.get_one::<u8>("maxhop") {
        Some(maxhop) => *maxhop,
        None => 64,
    };
    let mut protocol: Protocol = match ping_args.get_one::<String>("protocol") {
        Some(target) => match Protocol::from_str(&target) {
            Some(protocol) => protocol,
            None => {
                output::log_with_time("Invalid protocol", "ERROR");
                return;
            }
        },
        None => Protocol::ICMP,
    };
    let mut port: u16 = match ping_args.get_one::<u16>("port") {
        Some(port) => *port,
        None => 80,
    };
    let dst_ip: IpAddr = match IpAddr::from_str(&target) {
        Ok(ip_addr) => ip_addr,
        Err(_) => match SocketAddr::from_str(&target) {
            Ok(socket_addr) => {
                port = socket_addr.port();
                if protocol == Protocol::ICMP {
                    protocol = Protocol::TCP;
                }
                socket_addr.ip()
            }
            Err(_) => match crate::dns::lookup_host_name(&target) {
                Some(ip_addr) => ip_addr,
                None => {
                    output::log_with_time("Failed to resolve domain", "ERROR");
                    return;
                }
            },
        },
    };
    let timeout = match ping_args.get_one::<u64>("timeout") {
        Some(timeout) => Duration::from_millis(*timeout),
        None => Duration::from_secs(30),
    };
    let wait_time = match ping_args.get_one::<u64>("waittime") {
        Some(wait_time) => Duration::from_millis(*wait_time),
        None => Duration::from_secs(1),
    };
    let send_rate = match ping_args.get_one::<u64>("rate") {
        Some(send_rate) => Duration::from_millis(*send_rate),
        None => Duration::from_secs(1),
    };
    let mut setting: PingSetting = match protocol {
        Protocol::ICMP => PingSetting::icmp_ping(&interface, dst_ip, count).unwrap(),
        Protocol::TCP => PingSetting::tcp_ping(&interface, dst_ip, port, count).unwrap(),
        Protocol::UDP => PingSetting::udp_ping(&interface, dst_ip, count).unwrap(),
        _ => {
            output::log_with_time("Unsupported protocol", "ERROR");
            return;
        }
    };
    setting.dst_hostname = target
        .split(":")
        .collect::<Vec<&str>>()
        .get(0)
        .unwrap()
        .to_string();
    setting.hop_limit = maxhop;
    setting.receive_timeout = wait_time;
    setting.probe_timeout = timeout;
    setting.send_rate = send_rate;

    let target_addr: String =
        if setting.dst_ip.to_string() != setting.dst_hostname && !setting.dst_hostname.is_empty() {
            format!("{}({})", setting.dst_hostname, setting.dst_ip)
        } else {
            setting.dst_ip.to_string()
        };

    print_option(&setting, &interface);

    let pinger: Pinger = Pinger::new(setting).unwrap();
    let rx = pinger.get_progress_receiver();
    let handle = thread::spawn(move || pinger.ping());
    for r in rx.lock().unwrap().iter() {
        let source: String = if r.ip_addr.to_string() != r.host_name && !r.host_name.is_empty() {
            format!("{}({})", r.host_name, r.ip_addr)
        } else {
            r.ip_addr.to_string()
        };
        if r.probe_status.kind == crate::probe::ProbeStatusKind::Done {
            if let Some(port) = r.port_number {
                output::log_with_time(
                    &format!(
                        "{} [{:?}] {} Bytes from {}:{}, HOP:{}, TTL:{}, RTT:{:?}",
                        r.seq,
                        r.protocol,
                        r.received_packet_size,
                        source,
                        port,
                        r.hop,
                        r.ttl,
                        r.rtt
                    ),
                    "INFO",
                );
            } else {
                output::log_with_time(
                    &format!(
                        "{} [{:?}] {} Bytes from {}, HOP:{}, TTL:{}, RTT:{:?}",
                        r.seq, r.protocol, r.received_packet_size, source, r.hop, r.ttl, r.rtt
                    ),
                    "INFO",
                );
            }
        } else {
            if let Some(port) = r.port_number {
                output::log_with_time(
                    &format!(
                        "{} [{:?}] {}:{} {}",
                        r.seq, r.protocol, source, port, r.probe_status.message
                    ),
                    "ERROR",
                );
            } else {
                output::log_with_time(
                    &format!(
                        "{} [{:?}] {} {}",
                        r.seq, r.protocol, source, r.probe_status.message
                    ),
                    "ERROR",
                );
            }
        }
    }
    match handle.join() {
        Ok(ping_result) => match ping_result {
            Ok(ping_result) => {
                if ping_result.probe_status.kind == crate::probe::ProbeStatusKind::Done {
                    // Print results
                    if args.get_flag("json") {
                        let json_result = serde_json::to_string_pretty(&ping_result).unwrap();
                        println!("{}", json_result);
                    } else {
                        show_ping_result(&ping_result, target_addr);
                    }
                    match args.get_one::<PathBuf>("save") {
                        Some(file_path) => {
                            match crate::fs::save_text(
                                file_path,
                                serde_json::to_string_pretty(&ping_result).unwrap(),
                            ) {
                                Ok(_) => {
                                    output::log_with_time(
                                        &format!("Saved to {}", file_path.to_string_lossy()),
                                        "INFO",
                                    );
                                }
                                Err(e) => {
                                    output::log_with_time(
                                        &format!("Failed to save: {}", e),
                                        "ERROR",
                                    );
                                }
                            }
                        }
                        None => {}
                    }
                } else {
                    output::log_with_time(
                        &format!("Failed to ping: {}", ping_result.probe_status.message),
                        "ERROR",
                    );
                }
            }
            Err(e) => println!("{:?}", e),
        },
        Err(e) => println!("{:?}", e),
    }
}

fn print_option(setting: &PingSetting, interface: &Interface) {
    if crate::app::is_quiet_mode() {
        return;
    }
    println!();
    // Options
    let mut tree = Tree::new(node_label("Ping Config", None, None));
    let mut setting_tree = Tree::new(node_label("Settings", None, None));
    setting_tree.push(node_label("Interface", Some(interface.name.as_str()), None));
    setting_tree.push(node_label(
        "Protocol",
        Some(format!("{:?}", setting.protocol).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Count",
        Some(setting.count.to_string().as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Hop Limit",
        Some(setting.hop_limit.to_string().as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Timeout",
        Some(format!("{:?}", setting.probe_timeout).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Wait Time",
        Some(format!("{:?}", setting.receive_timeout).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Send Rate",
        Some(format!("{:?}", setting.send_rate).as_str()),
        None,
    ));
    tree.push(setting_tree);
    // Target
    let mut target_tree = Tree::new(node_label("Target", None, None));
    target_tree.push(node_label(
        "IP Address",
        Some(setting.dst_ip.to_string().as_str()),
        None,
    ));
    if setting.dst_ip.to_string() != setting.dst_hostname && !setting.dst_hostname.is_empty() {
        target_tree.push(node_label("Host Name", Some(&setting.dst_hostname), None));
    }
    if let Some(port) = setting.dst_port {
        target_tree.push(node_label("Port", Some(port.to_string().as_str()), None));
    }
    tree.push(target_tree);
    println!("{}", tree);
}

fn show_ping_result(ping_result: &PingResult, target_addr: String) {
    if !crate::app::is_quiet_mode() {
        println!();
    }
    let mut tree = Tree::new(node_label(
        &format!("Ping Result - {}", target_addr),
        None,
        None,
    ));
    // Responses
    let mut responses_tree = Tree::new(node_label("Responses", None, None));
    for response in &ping_result.stat.responses {
        let mut response_tree = Tree::new(node_label(
            "Sequence",
            Some(response.seq.to_string().as_str()),
            None,
        ));
        response_tree.push(node_label(
            "IP Address",
            Some(&response.ip_addr.to_string()),
            None,
        ));
        response_tree.push(node_label(
            "Protocol",
            Some(format!("{:?}", response.protocol).as_str()),
            None,
        ));
        response_tree.push(node_label(
            "Received Bytes",
            Some(response.received_packet_size.to_string().as_str()),
            None,
        ));
        response_tree.push(node_label(
            "HOP",
            Some(response.hop.to_string().as_str()),
            None,
        ));
        response_tree.push(node_label(
            "TTL",
            Some(response.ttl.to_string().as_str()),
            None,
        ));
        response_tree.push(node_label(
            "RTT",
            Some(format!("{:?}", response.rtt).as_str()),
            None,
        ));

        responses_tree.push(response_tree);
    }
    tree.push(responses_tree);

    // Statistics
    let mut stat_tree = Tree::new(node_label("Statistics", None, None));
    stat_tree.push(node_label(
        "Transmitted",
        Some(format!("{}", ping_result.stat.transmitted_count).as_str()),
        None,
    ));
    stat_tree.push(node_label(
        "Received",
        Some(format!("{}", ping_result.stat.received_count).as_str()),
        None,
    ));
    stat_tree.push(node_label(
        "Loss",
        Some(
            format!(
                "{}%",
                100.0
                    - (ping_result.stat.received_count as f64
                        / ping_result.stat.transmitted_count as f64)
                        * 100.0
            )
            .as_str(),
        ),
        None,
    ));
    stat_tree.push(node_label(
        "Min",
        Some(format!("{:?}", ping_result.stat.min).as_str()),
        None,
    ));
    stat_tree.push(node_label(
        "Max",
        Some(format!("{:?}", ping_result.stat.max).as_str()),
        None,
    ));
    stat_tree.push(node_label(
        "Avg",
        Some(format!("{:?}", ping_result.stat.avg).as_str()),
        None,
    ));
    tree.push(stat_tree);

    println!("{}", tree);
}
