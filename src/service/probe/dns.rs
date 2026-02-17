use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
    endpoint::ServiceInfo,
    service::{
        build_regex, expand_cpe_templates,
        probe::{PortProbeResult, ProbeContext, ServiceProbe},
    },
};
use anyhow::Result;

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

/// Build a DNS query message for "version.bind" TXT record in CHAOS class.
fn build_version_bind_query() -> anyhow::Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(fastrand::u16(..));
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);

    let name = Name::from_ascii("version.bind.")?;
    let mut q = Query::query(name, RecordType::TXT);
    // CHAOS class for version.bind
    q.set_query_class(DNSClass::CH);
    msg.add_query(q);

    let mut bytes = Vec::with_capacity(64);
    let mut enc = BinEncoder::new(&mut bytes);
    msg.emit(&mut enc)?;
    Ok(bytes)
}

/// Perform a DNS version.bind query over UDP.
async fn run_dns_version_bind_udp(
    addr: std::net::SocketAddr,
    idle: std::time::Duration,
    _total: std::time::Duration,
    max_bytes: usize,
) -> anyhow::Result<(String, bool)> {
    let q = build_version_bind_query()?;
    let local = if addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let sock = UdpSocket::bind(local).await?;
    sock.connect(addr).await?;
    sock.send(&q).await?;

    // Receive response
    let mut buf = vec![0u8; max_bytes.min(4096)];
    let n = tokio::time::timeout(idle, sock.recv(&mut buf)).await??;
    buf.truncate(n);

    let msg = Message::from_vec(&buf)?;
    let truncated = msg.truncated();

    // Extract TXT record
    let mut txt = String::new();
    for ans in msg.answers() {
        if ans.record_type() == RecordType::TXT
            && ans.name().to_ascii().eq_ignore_ascii_case("version.bind.")
        {
            if ans.dns_class() == DNSClass::CH {
                if let hickory_proto::rr::RData::TXT(t) = ans.data() {
                    let joined = t
                        .txt_data()
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .collect::<Vec<_>>()
                        .join("");
                    txt = joined;
                    break;
                }
            }
        }
    }

    if txt.is_empty() {
        anyhow::bail!("no TXT answer for version.bind");
    }
    Ok((txt, truncated))
}

/// Perform a DNS version.bind query over TCP.
async fn run_dns_version_bind_tcp(
    addr: std::net::SocketAddr,
    idle: std::time::Duration,
    total: std::time::Duration,
    max_bytes: usize,
) -> anyhow::Result<String> {
    let mut stream = tokio::time::timeout(total, TcpStream::connect(addr)).await??;

    let q = build_version_bind_query()?;
    let mut framed = Vec::with_capacity(q.len() + 2);
    framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
    framed.extend_from_slice(&q);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    // Read the first 2 bytes for length
    let mut lenbuf = [0u8; 2];
    tokio::time::timeout(idle, stream.read_exact(&mut lenbuf)).await??;
    let want = u16::from_be_bytes(lenbuf) as usize;
    if want > max_bytes {
        anyhow::bail!("dns/tcp response exceeds max_bytes");
    }

    let mut buf = vec![0u8; want];
    tokio::time::timeout(idle, stream.read_exact(&mut buf)).await??;

    let msg = hickory_proto::op::Message::from_vec(&buf)?;
    // Extract TXT record
    for ans in msg.answers() {
        if ans.record_type() == RecordType::TXT
            && ans.name().to_ascii().eq_ignore_ascii_case("version.bind.")
        {
            if ans.dns_class() == DNSClass::CH {
                if let hickory_proto::rr::RData::TXT(t) = ans.data() {
                    let joined = t
                        .txt_data()
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .collect::<Vec<_>>()
                        .join("");
                    if !joined.is_empty() {
                        return Ok(joined);
                    }
                }
            }
        }
    }
    anyhow::bail!("no TXT answer for version.bind over TCP");
}

/// Match response text against known service signatures.
/// (service, cpes)
fn match_response_signatures(
    probe_id: &str,
    text: &str,
) -> anyhow::Result<Option<(String, Vec<String>)>> {
    let sigdb = crate::db::service::response_signatures_db();
    let mut best_service: String = String::new();
    let mut cpes: Vec<String> = Vec::new();
    for sig in sigdb {
        if !sig.probe_id.eq_ignore_ascii_case(probe_id) {
            continue;
        }

        let re = match build_regex(&sig.regex, "") {
            Ok(r) => r,
            Err(_) => build_regex(&sig.regex, "i")?,
        };
        if let Some(caps) = re.captures(text) {
            if best_service.is_empty() && !sig.service.is_empty() {
                best_service = sig.service.clone();
            }
            let cs = expand_cpe_templates(&sig.cpe, &caps);
            if !cs.is_empty() {
                cpes.extend(cs);
                // Generic CPEs can have multiple candidates, so it's okay to continue collecting
            }
        }
    }
    if best_service.is_empty() && cpes.is_empty() {
        Ok(None)
    } else {
        Ok(Some((best_service, cpes)))
    }
}

/// A DNS probe that performs version.bind queries to identify DNS services.
pub struct DnsProbe;

impl DnsProbe {
    /// Run the DNS probe with the given context.
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        let addr = std::net::SocketAddr::new(ctx.ip, ctx.probe.port);
        // Try UDP first
        if matches!(
            ctx.probe.probe_id,
            ServiceProbe::UdpDNSVersionBindReq | ServiceProbe::TcpDNSVersionBindReq
        ) {
            tracing::debug!(
                "DNS Version Bind Probe (UDP): {}:{}",
                ctx.ip,
                ctx.probe.port
            );
            match run_dns_version_bind_udp(addr, ctx.timeout, ctx.timeout, ctx.max_read_size).await
            {
                Ok((txt, truncated)) => {
                    let mut svc = ServiceInfo::default();
                    let udp_svc_db = crate::db::service::udp_service_db();
                    svc.name = udp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());
                    svc.banner = Some(txt.clone());
                    svc.raw = Some(txt.clone());
                    // Match (using UDP-side)
                    let hits = match_response_signatures("udp:dns_version_bind_req", &txt)?;
                    if let Some((best_service, cpes)) = hits {
                        svc.name = Some(best_service);
                        svc.cpes = cpes;
                    }
                    // If truncated, try TCP as well
                    if truncated {
                        if let Ok(txt2) = run_dns_version_bind_tcp(
                            addr,
                            ctx.timeout,
                            ctx.timeout,
                            ctx.max_read_size,
                        )
                        .await
                        {
                            svc.raw = Some(txt2.clone());
                            let hits2 =
                                match_response_signatures("tcp:dns_version_bind_req", &txt2)?;
                            if let Some((best_service, cpes)) = hits2 {
                                svc.name = Some(best_service);
                                svc.cpes = cpes;
                            }
                        }
                    }
                    let probe_result: PortProbeResult = PortProbeResult {
                        ip: ctx.ip,
                        hostname: ctx.hostname,
                        port: ctx.probe.port,
                        transport: ctx.probe.transport,
                        probe_id: ctx.probe.probe_id,
                        service_info: svc,
                    };
                    return Ok(probe_result);
                }
                Err(e) => {
                    tracing::debug!("DNS Version Bind Probe (UDP) failed: {}", e);
                    tracing::debug!(
                        "Attempting DNS Version Bind Probe (TCP): {}:{}",
                        ctx.ip,
                        ctx.probe.port
                    );
                    let mut svc = ServiceInfo::default();
                    let tcp_svc_db = crate::db::service::tcp_service_db();
                    svc.name = tcp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());
                    // If UDP failed, try TCP
                    if let Ok(txt) =
                        run_dns_version_bind_tcp(addr, ctx.timeout, ctx.timeout, ctx.max_read_size)
                            .await
                    {
                        svc.banner = Some(txt.clone());
                        svc.raw = Some(txt.clone());
                        let hits = match_response_signatures("tcp:dns_version_bind_req", &txt)?;
                        if let Some((best_service, cpes)) = hits {
                            svc.name = Some(best_service);
                            svc.cpes = cpes;
                        }
                    }
                    let probe_result: PortProbeResult = PortProbeResult {
                        ip: ctx.ip,
                        hostname: ctx.hostname,
                        port: ctx.probe.port,
                        transport: ctx.probe.transport,
                        probe_id: ctx.probe.probe_id,
                        service_info: svc,
                    };
                    return Ok(probe_result);
                }
            }
        }

        // If UDP not selected or failed, and TCP is selected
        if matches!(ctx.probe.probe_id, ServiceProbe::TcpDNSVersionBindReq) {
            tracing::debug!(
                "DNS Version Bind Probe (TCP): {}:{}",
                ctx.ip,
                ctx.probe.port
            );
            let txt =
                run_dns_version_bind_tcp(addr, ctx.timeout, ctx.timeout, ctx.max_read_size).await?;
            let mut svc = ServiceInfo::default();
            let tcp_svc_db = crate::db::service::tcp_service_db();
            svc.name = tcp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());
            svc.banner = Some(txt.clone());
            svc.raw = Some(txt.clone());
            let hits = match_response_signatures("tcp:dns_version_bind_req", &txt)?;
            if let Some((best_service, cpes)) = hits {
                svc.name = Some(best_service);
                svc.cpes = cpes;
            }
            let probe_result: PortProbeResult = PortProbeResult {
                ip: ctx.ip,
                hostname: ctx.hostname,
                port: ctx.probe.port,
                transport: ctx.probe.transport,
                probe_id: ctx.probe.probe_id,
                service_info: svc,
            };
            return Ok(probe_result);
        }
        anyhow::bail!("unsupported probe for dns version.bind")
    }
}
