use futures::stream::{self, StreamExt};
use netdev::Interface;
use nex::packet::builder::icmp::IcmpPacketBuilder;
use nex::packet::builder::icmpv6::Icmpv6PacketBuilder;
use nex::packet::icmp::{IcmpPacket, IcmpType};
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::ipv4::Ipv4Packet;
use nex::packet::packet::Packet;
use nex::socket::icmp::{AsyncIcmpSocket, IcmpConfig, IcmpKind};
use nex::socket::tcp::{AsyncTcpSocket, TcpConfig};
use nex::socket::udp::{AsyncUdpSocket, UdpConfig};
use rand::{thread_rng, Rng};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use crate::host::{Host, Port, PortStatus};

use super::packet::{build_hostscan_ip_next_packet, build_portscan_ip_next_packet};
use super::result::ScanResult;
use super::setting::{HostScanSetting, PortScanSetting};

use crate::packet::frame::PacketFrame;
use crate::pcap::PacketCaptureOptions;
use nex::packet::ip::IpNextProtocol;
use std::collections::HashSet;
use std::thread;

use super::result::{parse_hostscan_result, parse_portscan_result, ScanStatus};
use super::setting::{HostScanType, PortScanType};

pub(crate) async fn send_portscan_packets(
    interface: &Interface,
    socket: &AsyncTcpSocket,
    scan_setting: &PortScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.concurrency,
        |dst| async move {
            let fut_port = stream::iter(dst.get_ports()).for_each_concurrent(
                scan_setting.concurrency,
                |port| {
                    let target = dst.clone();
                    let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, port);
                    async move {
                        let packet_bytes: Vec<u8> =
                            build_portscan_ip_next_packet(&interface, target.ip_addr, port);
                        match socket.send_to(&packet_bytes, dst_socket_addr) {
                            Ok(_) => {}
                            Err(_) => {}
                        }
                        match ptx.lock() {
                            Ok(lr) => match lr.send(dst_socket_addr) {
                                Ok(_) => {}
                                Err(_) => {}
                            },
                            Err(_) => {}
                        }
                        //thread::sleep(scan_setting.send_rate);
                    }
                },
            );
            fut_port.await;
        },
    );
    fut_host.await;
}

pub(crate) async fn send_hostscan_packets(
    interface: &Interface,
    scan_setting: &HostScanSetting,
    ptx: &Arc<Mutex<Sender<Host>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.concurrency,
        |dst| async move {
            let packet_bytes =
                build_hostscan_ip_next_packet(&interface, &dst, &scan_setting.scan_type);
            let target = SocketAddr::new(dst.ip_addr, 0);
            match scan_setting.scan_type {
                HostScanType::IcmpPingScan => {
                    let config = match dst.ip_addr {
                        IpAddr::V4(_) => IcmpConfig::new(IcmpKind::V4),
                        IpAddr::V6(_) => IcmpConfig::new(IcmpKind::V6),
                    };
                    let socket = Arc::new(AsyncIcmpSocket::new(&config).await.unwrap());
                    let _ = socket.send_to(&packet_bytes, target).await;
                }
                HostScanType::TcpPingScan => {
                    let config = match dst.ip_addr {
                        IpAddr::V4(_) => TcpConfig::raw_v4(),
                        IpAddr::V6(_) => TcpConfig::raw_v6(),
                    };
                    let socket = AsyncTcpSocket::from_config(&config).unwrap();
                    let _ = socket.send_to(&packet_bytes, target);
                }
                HostScanType::UdpPingScan => {
                    let config = match dst.ip_addr {
                        IpAddr::V4(_) => {
                            let mut conf = UdpConfig::new();
                            conf.socket_family = nex::socket::SocketFamily::IPV4;
                            conf.socket_type = nex::socket::udp::UdpSocketType::Raw;
                            conf
                        }
                        IpAddr::V6(_) => {
                            let mut conf = UdpConfig::new();
                            conf.socket_family = nex::socket::SocketFamily::IPV6;
                            conf.socket_type = nex::socket::udp::UdpSocketType::Raw;
                            conf
                        }
                    };
                    let socket = AsyncUdpSocket::from_config(&config).unwrap();
                    let _ = socket.send_to(&packet_bytes, target);
                }
            }
            match ptx.lock() {
                Ok(lr) => match lr.send(dst) {
                    Ok(_) => {}
                    Err(_) => {}
                },
                Err(_) => {}
            }
            //thread::sleep(scan_setting.send_rate);
        },
    );
    fut_host.await;
}

/// Experimental: non-root async host scan
pub async fn run_icmp_sock_hostscan(
    interface: &Interface,
    scan_setting: &HostScanSetting,
    ptx: &Arc<Mutex<Sender<Host>>>,
) -> ScanResult {
    let v4_config = IcmpConfig::new(IcmpKind::V4);
    let v4_socket = Arc::new(AsyncIcmpSocket::new(&v4_config).await.unwrap());

    let v6_config = IcmpConfig::new(IcmpKind::V6);
    let v6_socket = Arc::new(AsyncIcmpSocket::new(&v6_config).await.unwrap());

    // Receiver task
    let v4_socket_rx = v4_socket.clone();
    let v6_socket_rx = v6_socket.clone();

    let src_ipv4 = crate::interface::get_interface_ipv4(interface).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let src_global_ipv6 =
        crate::interface::get_interface_global_ipv6(interface).unwrap_or(Ipv6Addr::UNSPECIFIED);
    let src_local_ipv6 =
        crate::interface::get_interface_local_ipv6(interface).unwrap_or(Ipv6Addr::UNSPECIFIED);

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let replies: Arc<Mutex<Vec<Host>>> = Arc::new(Mutex::new(Vec::new()));
    let replies_rx = Arc::clone(&replies);
    let dns_map = scan_setting.dns_map.clone();

    let recv_task = tokio::spawn(async move {
        let mut v4_buf = [0u8; 512];
        let mut v6_buf = [0u8; 512];
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                res = v4_socket_rx.recv_from(&mut v4_buf) => {
                    if let Ok((n, from)) = res {
                        match from {
                            SocketAddr::V4(_from) => {
                                if let Some(ipv4_packet) = Ipv4Packet::from_buf(&v4_buf[..n]) {
                                    if ipv4_packet.header.next_level_protocol
                                        == nex::packet::ip::IpNextProtocol::Icmp
                                    {
                                        if let Some(icmp_packet) = IcmpPacket::from_bytes(ipv4_packet.payload()) {
                                            match nex::packet::icmp::echo_reply::EchoReplyPacket::try_from(icmp_packet) {
                                                Ok(_reply) => {
                                                    let name = match dns_map.get(&IpAddr::V4(ipv4_packet.header.source)) {
                                                        Some(name) => name.clone(),
                                                        None => String::new(),
                                                    };
                                                    let host = Host {
                                                        ip_addr: IpAddr::V4(ipv4_packet.header.source),
                                                        hostname: name,
                                                        ports: Vec::new(),
                                                        mac_addr: netdev::MacAddr::zero(),
                                                        vendor_name: String::new(),
                                                        os_family: String::new(),
                                                        ttl: Some(ipv4_packet.header.ttl),
                                                    };
                                                    replies_rx.lock().unwrap().push(host);
                                                }
                                                Err(_) => {}
                                            }
                                        }
                                    }
                                }
                            }
                            SocketAddr::V6(_from) => {

                            }
                        }
                    }
                }
                res = v6_socket_rx.recv_from(&mut v6_buf) => {
                    if let Ok((n, from)) = res {
                        match from {
                            SocketAddr::V4(_from) => {

                            }
                            SocketAddr::V6(from) => {
                                // The IPv6 header is automatically cropped off when recvfrom() is used.
                                if let Some(_icmpv6_packet) = nex::packet::icmpv6::Icmpv6Packet::from_buf(&v6_buf[..n]) {
                                    match nex::packet::icmpv6::echo_reply::EchoReplyPacket::from_buf(&v6_buf[..n]) {
                                        Some(_reply) => {
                                            let name = match dns_map.get(&IpAddr::V6(*from.ip())) {
                                                Some(name) => name.clone(),
                                                None => String::new(),
                                            };
                                            let host = Host {
                                                ip_addr: IpAddr::V6(*from.ip()),
                                                hostname: name,
                                                ports: Vec::new(),
                                                mac_addr: netdev::MacAddr::zero(),
                                                vendor_name: String::new(),
                                                os_family: String::new(),
                                                ttl: None,
                                            };
                                            replies_rx.lock().unwrap().push(host);
                                        }
                                        None => {
                                            println!("Failed to parse ICMPv6 Echo Reply");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let mut handles = Vec::new();
    let start_time = std::time::Instant::now();
    for target in &scan_setting.targets {
        let id: u16 = thread_rng().gen();
        let seq: u16 = 1;
        let socket: Arc<AsyncIcmpSocket> = if target.ip_addr.is_ipv4() {
            v4_socket.clone()
        } else {
            v6_socket.clone()
        };
        let target = target.clone();
        let ptx_clone = ptx.clone();
        handles.push(tokio::spawn(async move {
            let pkt = match target.ip_addr {
                IpAddr::V4(addr) => {
                    let pkt = IcmpPacketBuilder::new(src_ipv4, addr)
                        .icmp_type(IcmpType::EchoRequest)
                        .icmp_code(nex::packet::icmp::echo_request::IcmpCodes::NoCode)
                        .echo_fields(id, seq)
                        //.payload(Bytes::from_static(b"ping"))
                        .to_bytes();
                    pkt
                }
                IpAddr::V6(addr) => {
                    let src_ipv6 = if nex::net::ip::is_global_ipv6(&addr) {
                        src_global_ipv6
                    } else {
                        src_local_ipv6
                    };
                    let pkt = Icmpv6PacketBuilder::new(src_ipv6, addr)
                        .icmpv6_type(Icmpv6Type::EchoRequest)
                        .icmpv6_code(nex::packet::icmpv6::echo_request::Icmpv6Codes::NoCode)
                        .echo_fields(id, seq)
                        //.payload(Bytes::from_static(b"ping"))
                        .to_bytes();
                    pkt
                }
            };
            let dst = SocketAddr::new(target.ip_addr, 0);
            let _ = socket.send_to(&pkt, dst).await;
            match ptx_clone.lock() {
                Ok(lr) => match lr.send(target.clone()) {
                    Ok(_) => {}
                    Err(_) => {}
                },
                Err(_) => {}
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    tokio::time::sleep(scan_setting.wait_time).await;
    // Stop the receiver task
    let _ = stop_tx.send(());
    let _ = recv_task.await;

    let mut result = ScanResult::new();
    match Arc::into_inner(replies) {
        Some(mutex) => {
            let mut vec = match std::sync::Mutex::into_inner(mutex) {
                Ok(v) => v,
                Err(poisoned) => poisoned.into_inner(),
            };
            vec.sort_unstable_by_key(|h| h.ip_addr);
            vec.dedup_by_key(|h| h.ip_addr);
            result.hosts = vec;
        }
        None => {
            result.hosts = Vec::new();
        }
    }
    result.scan_time = start_time.elapsed();
    result.scan_status = crate::scan::result::ScanStatus::Done;
    result
}

pub async fn try_connect_ports(
    target: Host,
    concurrency: usize,
    timeout: Duration,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> Host {
    let (channel_tx, channel_rx) = mpsc::channel();
    let fut = stream::iter(target.get_ports()).for_each_concurrent(concurrency, |port| {
        let channel_tx = channel_tx.clone();
        async move {
            let socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, port);
            let cfg = if socket_addr.is_ipv4() {
                TcpConfig::v4_stream()
            } else {
                TcpConfig::v6_stream()
            };
            let socket = AsyncTcpSocket::from_config(&cfg).unwrap();
            match socket.connect_timeout(socket_addr, timeout).await {
                Ok(mut stream) => {
                    let _ = channel_tx.send(port);
                    match stream.shutdown().await {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
                Err(_) => {}
            }
            match ptx.lock() {
                Ok(lr) => match lr.send(socket_addr) {
                    Ok(_) => {}
                    Err(_) => {}
                },
                Err(_) => {}
            }
        }
    });
    fut.await;
    drop(channel_tx);
    let mut open_ports: Vec<Port> = vec![];
    loop {
        match channel_rx.recv() {
            Ok(port) => {
                open_ports.push(Port {
                    number: port,
                    status: PortStatus::Open,
                    service_name: String::new(),
                    service_version: String::new(),
                });
            }
            Err(_) => {
                break;
            }
        }
    }
    Host {
        ip_addr: target.ip_addr,
        hostname: target.hostname,
        ports: open_ports,
        mac_addr: target.mac_addr,
        vendor_name: target.vendor_name,
        os_family: String::new(),
        ttl: target.ttl,
    }
}

pub fn run_connect_scan(
    scan_setting: PortScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        let start_time = std::time::Instant::now();
        let mut tasks = vec![];
        for target in scan_setting.targets {
            let ptx = ptx.clone();
            tasks.push(tokio::spawn(async move {
                let host = try_connect_ports(
                    target,
                    scan_setting.concurrency,
                    scan_setting.connect_timeout,
                    &ptx,
                )
                .await;
                host
            }));
        }
        let mut hosts: Vec<Host> = vec![];
        for task in tasks {
            match task.await {
                Ok(host) => {
                    hosts.push(host);
                }
                Err(e) => {
                    println!("error: {}", e);
                }
            }
        }
        let mut result = ScanResult::new();
        result.hosts = hosts;
        result.scan_time = start_time.elapsed();
        result.scan_status = crate::scan::result::ScanStatus::Done;
        result
    });
    result
}

pub(crate) async fn scan_hosts(
    scan_setting: HostScanSetting,
    ptx: &Arc<Mutex<Sender<Host>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    if scan_setting.detect_only {
        return run_icmp_sock_hostscan(&interface, &scan_setting, ptx).await;
    }
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(scan_setting.wait_time),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut _tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return ScanResult::error("Unhandled channel type".to_string()),
        Err(e) => return ScanResult::error(format!("Failed to create channel: {}", e)),
    };
    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        capture_timeout: scan_setting.timeout,
        read_timeout: scan_setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    for target in scan_setting.targets.clone() {
        capture_options.src_ips.insert(target.ip_addr);
    }
    match scan_setting.scan_type {
        HostScanType::IcmpPingScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Icmp);
            capture_options.ip_protocols.insert(IpNextProtocol::Icmpv6);
        }
        HostScanType::TcpPingScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
            for target in scan_setting.targets.clone() {
                for port in target.get_ports() {
                    capture_options.src_ports.insert(port);
                }
            }
        }
        HostScanType::UdpPingScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Udp);
            capture_options.ip_protocols.insert(IpNextProtocol::Icmp);
            capture_options.ip_protocols.insert(IpNextProtocol::Icmpv6);
        }
    }
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let stop_handle = Arc::clone(&stop);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);
    // Spawn pcap thread
    let pcap_handler = thread::spawn(move || {
        let packets: Vec<PacketFrame> =
            crate::pcap::start_capture(&mut rx, capture_options, &stop_handle);
        // Notify that pcap is ready
        match ready_tx.send(()) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Failed to send ready signal: {:?}", e);
            }
        }
        match receive_packets.lock() {
            Ok(mut receive_packets) => {
                for p in packets {
                    receive_packets.push(p);
                }
            }
            Err(e) => {
                eprintln!("Failed to lock receive_packets: {}", e);
            }
        }
    });

    // Wait for listener to start
    let _ = ready_rx.await;

    let start_time = std::time::Instant::now();
    // Send probe packets
    send_hostscan_packets(&interface, &scan_setting, ptx).await;
    thread::sleep(scan_setting.wait_time);
    // Stop pcap
    match stop.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Failed to lock stop: {}", e);
        }
    }
    // Wait for listener to stop
    match pcap_handler.join() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to join pcap_handler: {:?}", e);
        }
    }

    let mut scan_result: ScanResult = ScanResult::new();
    match packets.lock() {
        Ok(packets) => {
            scan_result = parse_hostscan_result(packets.clone(), scan_setting);
        }
        Err(e) => {
            eprintln!("Failed to lock packets: {}", e);
        }
    }
    scan_result.scan_time = start_time.elapsed();
    scan_result.scan_status = ScanStatus::Done;
    scan_result
}

pub(crate) async fn scan_ports(
    scan_setting: PortScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(scan_setting.wait_time),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut _tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return ScanResult::error("Unhandled channel type".to_string()),
        Err(e) => return ScanResult::error(format!("Failed to create channel: {}", e)),
    };

    if scan_setting.targets.len() == 0 {
        return ScanResult::error("No targets specified".to_string());
    }

    let config = match scan_setting.targets[0].ip_addr {
        IpAddr::V4(_) => TcpConfig::raw_v4(),
        IpAddr::V6(_) => TcpConfig::raw_v6(),
    };
    let socket = AsyncTcpSocket::from_config(&config).unwrap();

    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        capture_timeout: scan_setting.task_timeout,
        read_timeout: scan_setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    for target in scan_setting.targets.clone() {
        capture_options.src_ips.insert(target.ip_addr);
        capture_options.src_ports.extend(target.get_ports());
    }
    match scan_setting.scan_type {
        PortScanType::TcpSynScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
        }
        PortScanType::TcpConnectScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
        }
    }
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let stop_handle = Arc::clone(&stop);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);
    // Spawn pcap thread
    let pcap_handler = thread::spawn(move || {
        let packets: Vec<PacketFrame> =
            crate::pcap::start_capture(&mut rx, capture_options, &stop_handle);
        // Notify that pcap is ready
        match ready_tx.send(()) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Failed to send ready signal: {:?}", e);
            }
        }
        match receive_packets.lock() {
            Ok(mut receive_packets) => {
                for p in packets {
                    receive_packets.push(p);
                }
            }
            Err(e) => {
                eprintln!("Failed to lock receive_packets: {}", e);
            }
        }
    });
    // Wait for listener to start
    let _ = ready_rx.await;
    let start_time = std::time::Instant::now();
    // Send probe packets
    send_portscan_packets(&interface, &socket, &scan_setting, ptx).await;
    thread::sleep(scan_setting.wait_time);
    // Stop pcap
    match stop.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Failed to lock stop: {}", e);
        }
    }
    // Wait for listener to stop
    match pcap_handler.join() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to join pcap_handler: {:?}", e);
        }
    }
    let mut scan_result: ScanResult = ScanResult::new();
    match packets.lock() {
        Ok(packets) => {
            scan_result = parse_portscan_result(packets.clone(), scan_setting);
        }
        Err(e) => {
            eprintln!("Failed to lock packets: {}", e);
        }
    }
    scan_result.scan_time = start_time.elapsed();
    scan_result.scan_status = ScanStatus::Done;
    scan_result
}
