use crate::interface;
use futures::stream::StreamExt;
use nex::datalink::async_io::AsyncRawReceiver;
use nex::net::interface::Interface;
use nex::packet::frame::Frame;
use nex::packet::frame::ParseOption;
use nex::packet::{ethernet::EtherType, ip::IpNextProtocol};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::oneshot;

/// Packet capture options
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketCaptureOptions {
    /// Interface index
    pub interface_index: u32,
    /// Interface name
    #[allow(dead_code)]
    pub interface_name: String,
    /// Source IP addresses to filter. If empty, all source IP addresses will be captured
    pub src_ips: HashSet<IpAddr>,
    /// Destination IP addresses to filter. If empty, all destination IP addresses will be captured
    pub dst_ips: HashSet<IpAddr>,
    /// Source ports to filter. If empty, all source ports will be captured
    pub src_ports: HashSet<u16>,
    /// Destination ports to filter. If empty, all destination ports will be captured
    pub dst_ports: HashSet<u16>,
    /// Ether types to filter. If empty, all ether types will be captured
    pub ether_types: HashSet<EtherType>,
    /// IP protocols to filter. If empty, all IP protocols will be captured
    pub ip_protocols: HashSet<IpNextProtocol>,
    /// Capture duration limit
    pub capture_timeout: Duration,
    /// Read Timeout for read next packet (Linux, BPF only)
    pub read_timeout: Duration,
    /// Capture in promiscuous mode
    pub promiscuous: bool,
    /// Receive undefined packets
    pub receive_undefined: bool,
    /// Use TUN interface
    pub tunnel: bool,
    /// Loopback interface
    pub loopback: bool,
}

impl PacketCaptureOptions {
    pub fn from_default_interface() -> Result<PacketCaptureOptions, String> {
        let iface = netdev::get_default_interface()?;
        let options = PacketCaptureOptions {
            interface_index: iface.index,
            interface_name: iface.name.clone(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        };
        Ok(options)
    }
    pub fn from_interface_index(if_index: u32) -> Option<PacketCaptureOptions> {
        let iface = interface::get_interface_by_index(if_index)?;
        let options = PacketCaptureOptions {
            interface_index: if_index,
            interface_name: iface.name.clone(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        };
        Some(options)
    }
    pub fn from_interface_name(if_name: String) -> Option<PacketCaptureOptions> {
        let iface = interface::get_interface_by_name(if_name)?;
        let options = PacketCaptureOptions {
            interface_index: iface.index,
            interface_name: iface.name.clone(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        };
        Some(options)
    }
    pub fn from_interface(iface: &Interface) -> PacketCaptureOptions {
        PacketCaptureOptions {
            interface_index: iface.index,
            interface_name: iface.name.clone(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        }
    }
}

/// Start packet capture
pub async fn start_capture(
    rx: &mut Box<dyn AsyncRawReceiver>,
    capture_options: PacketCaptureOptions,
    ready_tx: oneshot::Sender<()>,
    stop_rx: &mut oneshot::Receiver<()>,
) -> anyhow::Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut captured_bytes = 0usize;
    let deadline = tokio::time::sleep(capture_options.capture_timeout);
    tokio::pin!(deadline);
    let _ = ready_tx.send(());
    loop {
        tokio::select! {
            _ = &mut *stop_rx => break,
            _ = &mut deadline => anyhow::bail!("packet capture deadline exceeded; reduce scan size or increase task timeout"),
            // Check if capture timeout is reached
            // Read next packet
            next_read = rx.next() => {
                match next_read {
                    Some(Ok(packet)) => {
                        let mut parse_option: ParseOption = ParseOption::default();
                        if capture_options.tunnel || (cfg!(any(target_os = "macos", target_os = "ios")) && capture_options.loopback) {
                            let payload_offset = if capture_options.loopback { 14 } else { 0 };
                            parse_option.from_ip_packet = true;
                            parse_option.offset = payload_offset;
                        }
                        match Frame::from_buf(&packet, parse_option) { Some(frame) => {
                            if filter_packet(&frame, &capture_options) {
                                captured_bytes = captured_bytes.saturating_add(packet.len());
                                anyhow::ensure!(captured_bytes <= 64 * 1024 * 1024 && frames.len() < 65_536,
                                    "capture buffer limit exceeded; split the scan");
                                frames.push(frame);
                            }
                        } _ => {
                            tracing::debug!("Ignoring an unparseable packet");
                        }}
                    }
                    Some(Err(e)) => {
                        return Err(e.into());
                    }
                    None => anyhow::bail!("packet capture stream ended unexpectedly")
                }
            }
        }
    }
    Ok(frames)
}

fn filter_packet(frame: &Frame, capture_options: &PacketCaptureOptions) -> bool {
    if !capture_options.ip_protocols.is_empty() && frame.ip.is_none() {
        return false;
    }
    if (!capture_options.src_ports.is_empty() || !capture_options.dst_ports.is_empty())
        && frame.transport.is_none()
    {
        return false;
    }
    if let Some(datalink) = &frame.datalink {
        if let Some(ethernet_header) = &datalink.ethernet
            && !filter_ether_type(ethernet_header.ethertype, capture_options)
        {
            return false;
        }
        if let Some(arp_header) = &datalink.arp
            && !filter_host(
                IpAddr::V4(arp_header.sender_proto_addr),
                IpAddr::V4(arp_header.target_proto_addr),
                capture_options,
            )
        {
            return false;
        }
    }
    if let Some(ip) = &frame.ip {
        if let Some(ipv4_header) = &ip.ipv4 {
            if !filter_host(
                IpAddr::V4(ipv4_header.source),
                IpAddr::V4(ipv4_header.destination),
                capture_options,
            ) {
                return false;
            }
            if !filter_ip_protocol(ipv4_header.next_level_protocol, capture_options) {
                return false;
            }
        }
        if let Some(ipv6_header) = &ip.ipv6 {
            if !filter_host(
                IpAddr::V6(ipv6_header.source),
                IpAddr::V6(ipv6_header.destination),
                capture_options,
            ) {
                return false;
            }
            if !filter_ip_protocol(ipv6_header.next_header, capture_options) {
                return false;
            }
        }
    }
    if let Some(transport) = &frame.transport {
        if let Some(tcp_header) = &transport.tcp
            && !filter_port(tcp_header.source, tcp_header.destination, capture_options)
        {
            return false;
        }
        if let Some(udp_header) = &transport.udp
            && !filter_port(udp_header.source, udp_header.destination, capture_options)
        {
            return false;
        }
    }
    true
}

fn filter_host(src_ip: IpAddr, dst_ip: IpAddr, capture_options: &PacketCaptureOptions) -> bool {
    (capture_options.src_ips.is_empty() || capture_options.src_ips.contains(&src_ip))
        && (capture_options.dst_ips.is_empty() || capture_options.dst_ips.contains(&dst_ip))
}

fn filter_port(src_port: u16, dst_port: u16, capture_options: &PacketCaptureOptions) -> bool {
    (capture_options.src_ports.is_empty() || capture_options.src_ports.contains(&src_port))
        && (capture_options.dst_ports.is_empty() || capture_options.dst_ports.contains(&dst_port))
}

fn filter_ether_type(ether_type: EtherType, capture_options: &PacketCaptureOptions) -> bool {
    capture_options.ether_types.is_empty() || capture_options.ether_types.contains(&ether_type)
}

fn filter_ip_protocol(protocol: IpNextProtocol, capture_options: &PacketCaptureOptions) -> bool {
    capture_options.ip_protocols.is_empty() || capture_options.ip_protocols.contains(&protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> PacketCaptureOptions {
        PacketCaptureOptions {
            interface_index: 0,
            interface_name: String::new(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::from_millis(10),
            read_timeout: Duration::from_millis(10),
            promiscuous: false,
            receive_undefined: false,
            tunnel: false,
            loopback: false,
        }
    }

    #[test]
    fn filters_require_both_source_and_destination() {
        let mut options = options();
        let src = "192.0.2.1".parse().unwrap();
        let dst = "192.0.2.2".parse().unwrap();
        options.src_ips.insert(src);
        options.dst_ips.insert(dst);
        options.src_ports.insert(443);
        options.dst_ports.insert(44322);
        assert!(filter_host(src, dst, &options));
        assert!(!filter_host(src, src, &options));
        assert!(!filter_host(dst, dst, &options));
        assert!(filter_port(443, 44322, &options));
        assert!(!filter_port(443, 80, &options));
        assert!(!filter_port(80, 44322, &options));
    }

    #[tokio::test]
    async fn idle_and_ended_receivers_terminate() {
        let (ready, _) = oneshot::channel();
        let (_stop, mut stop_rx) = oneshot::channel();
        let mut rx: Box<dyn AsyncRawReceiver> = Box::new(futures::stream::pending());
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            start_capture(&mut rx, options(), ready, &mut stop_rx),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("deadline"));
        let (ready, _) = oneshot::channel();
        let mut rx: Box<dyn AsyncRawReceiver> = Box::new(futures::stream::empty());
        let result = start_capture(&mut rx, options(), ready, &mut stop_rx).await;
        assert!(result.unwrap_err().to_string().contains("ended"));
    }
}
