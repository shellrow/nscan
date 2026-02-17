use netdev::MacAddr;
use std::time::Duration;
use termtree::Tree;

use crate::{ping::result::PingResult, probe::ProbeStatusKind, protocol::Protocol};

/// Format a Duration as milliseconds with three decimal places.
fn fmt_ms(d: &Duration) -> String {
    // milliseconds with three decimal places
    format!("{:.3} ms", (d.as_nanos() as f64) / 1_000_000.0)
}

/// Format a floating-point number as a percentage with one decimal place.
fn pct(loss: f64) -> String {
    format!("{:.1}%", loss)
}

/// Print the ping scan results in a tree structure.
pub fn print_ping_tree(res: &PingResult) {
    let s = &res.stat;

    let title = match &res.hostname {
        Some(hostname) => format!("{} ({})", res.ip_addr, hostname),
        None => format!("{}", res.ip_addr),
    };

    // Packet loss rate
    let sent = s.transmitted_count as f64;
    let recv = s.received_count as f64;
    let loss = if sent > 0.0 {
        ((sent - recv) / sent) * 100.0
    } else {
        0.0
    };

    let mut root = Tree::new(title);

    // summary
    let first_res = res.first_response();
    let mut summary = Tree::new("Summary".to_string());
    if let Some(r) = first_res {
        if r.mac_addr != MacAddr::zero() && !nex::net::ip::is_global_ip(&r.ip_addr) {
            summary.push(Tree::new(format!("MAC: {}", r.mac_addr)));
        }
    }
    summary.push(Tree::new(format!("IP: {}", res.ip_addr)));
    if let Some(hostname) = &res.hostname {
        summary.push(Tree::new(format!("Hostname: {}", hostname)));
    }
    summary.push(Tree::new(format!(
        "Protocol: {}",
        format!("{:?}", res.protocol).to_uppercase()
    )));
    match res.protocol {
        Protocol::Icmp => {}
        Protocol::Tcp => {
            if let Some(port) = res.port_number {
                summary.push(Tree::new(format!("Port: {}", port)));
            }
        }
        Protocol::Udp => {}
        _ => {}
    }
    summary.push(Tree::new(format!(
        "Received/Sent: {}/{}",
        s.received_count, s.transmitted_count
    )));
    summary.push(Tree::new(format!("Packet loss: {}", pct(loss))));
    summary.push(Tree::new(format!("Elapsed: {:?}", res.elapsed_time)));
    if let Some(min) = &s.min {
        let mut rtt = Tree::new("RTT".to_string());
        rtt.push(Tree::new(format!("MIN: {}", fmt_ms(min))));
        if let Some(avg) = &s.avg {
            rtt.push(Tree::new(format!("AVG: {}", fmt_ms(avg))));
        }
        if let Some(max) = &s.max {
            rtt.push(Tree::new(format!("MAX: {}", fmt_ms(max))));
        }
        summary.push(rtt);
    }
    root.push(summary);

    // replies
    if !s.responses.is_empty() {
        let mut replies = Tree::new("Replies".to_string());
        for r in &s.responses {
            match r.probe_status.kind {
                ProbeStatusKind::Done => {
                    let head = format!(
                        "#{} {} bytes from {}, RTT={}, TTL={}, HOP={}",
                        r.seq,
                        r.received_packet_size,
                        r.ip_addr,
                        fmt_ms(&r.rtt),
                        r.ttl,
                        r.hop
                    )
                    .trim()
                    .to_string();

                    let mut node = Tree::new(head);
                    if let Some(port) = &r.port_number {
                        node.push(Tree::new(format!("Port: {}", port)));
                    }
                    if let Some(state) = &r.port_status {
                        node.push(Tree::new(format!("State: {}", state.as_str())));
                    }
                    replies.push(node);
                }
                _ => {
                    let err_head = format!(
                        "#{} {}: {}",
                        r.seq,
                        r.probe_status.kind.name(),
                        r.probe_status.message,
                    )
                    .trim()
                    .to_string();
                    let node = Tree::new(err_head);
                    replies.push(node);
                }
            }
        }
        root.push(replies);
    }

    println!("{}", root);
}
