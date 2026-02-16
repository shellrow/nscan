use std::{collections::HashMap, net::IpAddr, time::Duration};
use regex::{Regex, RegexBuilder};
use anyhow::{Result, bail};
use futures::stream::{self, StreamExt};
use tokio::{io::{AsyncRead, AsyncReadExt}, net::TcpStream, time::{timeout, Instant}};
use tracing_indicatif::span_ext::IndicatifSpanExt;

use crate::{endpoint::{Endpoint, Port}, service::probe::{PortProbe, PortProbeResult, ProbeContext, ProbePayload, ServiceProbe}};

pub mod probe;
mod payload;

/// Configuration for service probing
#[derive(Clone,Debug)]
pub struct ServiceProbeConfig {
    pub timeout: Duration,
    pub max_concurrency: usize,
    pub max_read_size: usize,
    pub sni: bool,
    pub skip_cert_verify: bool,
}

/// Result of service detection on multiple endpoints
pub struct ServiceDetectionResult {
    pub results: Vec<PortProbeResult>,
    pub scan_time: Duration,
}

/// Service detector that runs probes against endpoints
pub struct ServiceDetector {
    pub config: ServiceProbeConfig,
}

impl ServiceDetector {
    /// Create a new ServiceDetector with the given configuration
    pub fn new(config: ServiceProbeConfig) -> Self {
        ServiceDetector {
            config
        }
    }
    pub async fn run_service_detection(&self, targets: Vec<Endpoint>) -> Result<ServiceDetectionResult> {
        let max_concurrency = self.config.max_concurrency.max(1);
        let start_time = Instant::now();
        let mut work_items: Vec<(IpAddr, Option<String>, Port)> = Vec::new();

        for endpoint in targets {
            let ip = endpoint.ip;
            let hostname = endpoint.hostname;
            for port in endpoint.ports {
                work_items.push((ip, hostname.clone(), port));
            }
        }

        if work_items.is_empty() {
            return Ok(ServiceDetectionResult {
                results: Vec::new(),
                scan_time: start_time.elapsed(),
            });
        }

        let header_span = tracing::info_span!("detect_services");
        header_span.pb_set_style(&crate::output::progress::get_progress_style());
        header_span.pb_set_message("Service Probe");
        header_span.pb_set_length(work_items.len() as u64);
        header_span.pb_set_position(0);
        header_span.pb_start();

        let config = self.config.clone();
        let mut stream = stream::iter(work_items)
            .map(move |(ip, hostname, port)| {
                let config = config.clone();
                async move { run_probes_for_target_port(&config, ip, hostname, port).await }
            })
            .buffer_unordered(max_concurrency);

        let mut results: Vec<PortProbeResult> = Vec::new();
        while let Some(port_results) = stream.next().await {
            for res in port_results {
                match res {
                    Ok(r) => results.push(r),
                    Err(e) => tracing::error!("Probe failed: {}", e),
                }
            }
            header_span.pb_inc(1);
        }

        drop(header_span);
        Ok(ServiceDetectionResult {
            results,
            scan_time: start_time.elapsed(),
        })
    }
}

async fn run_probes_for_target_port(
    config: &ServiceProbeConfig,
    ip: IpAddr,
    hostname: Option<String>,
    port: Port,
) -> Vec<Result<PortProbeResult>> {
    let port_probe_db: &'static HashMap<Port, Vec<ServiceProbe>> = crate::db::service::port_probe_db();
    let service_probe_db: &'static HashMap<ServiceProbe, ProbePayload> = crate::db::service::service_probe_db();

    let mut results: Vec<Result<PortProbeResult>> = Vec::new();
    if let Some(probes) = port_probe_db.get(&port) {
        for probe in probes {
            let probe_payload = match service_probe_db.get(probe) {
                Some(payload) => payload,
                None => {
                    results.push(Err(anyhow::anyhow!("No payload for probe {:?}", probe)));
                    continue;
                }
            };
            let port_probe = PortProbe {
                probe_id: probe.clone(),
                probe_name: probe_payload.id.clone(),
                port: port.number,
                transport: port.transport,
                payload: probe_payload.payload.clone(),
                payload_encoding: probe_payload.payload_encoding,
            };
            let ctx = ProbeContext {
                ip,
                hostname: hostname.clone(),
                probe: port_probe,
                timeout: config.timeout,
                max_read_size: config.max_read_size,
                sni: config.sni,
                skip_cert_verify: config.skip_cert_verify,
            };

            let r = match probe {
                ServiceProbe::TcpHTTPGet
                | ServiceProbe::TcpHTTPSGet
                | ServiceProbe::TcpHTTPOptions => probe::http::HttpProbe::run(ctx).await,
                ServiceProbe::TcpTlsSession => probe::tls::TlsProbe::run(ctx).await,
                ServiceProbe::TcpGenericLines | ServiceProbe::TcpHelp => {
                    probe::generic::GenericProbe::run(ctx).await
                }
                ServiceProbe::UdpDNSVersionBindReq | ServiceProbe::TcpDNSVersionBindReq => {
                    probe::dns::DnsProbe::run(ctx).await
                }
                ServiceProbe::UdpQuic => probe::quic::QuicProbe::run(ctx).await,
                _ => probe::null::NullProbe::run(ctx).await,
            };
            results.push(r);
        }
    } else {
        let ctx = ProbeContext {
            ip,
            hostname,
            probe: PortProbe::null_probe(port.number, port.transport),
            timeout: config.timeout,
            max_read_size: config.max_read_size,
            sni: config.sni,
            skip_cert_verify: config.skip_cert_verify,
        };
        results.push(probe::null::NullProbe::run(ctx).await);
    }

    results
}

pub fn set_read_timeout(tcp_stream: TcpStream, timeout: Duration) -> std::io::Result<TcpStream> {
    // Convert to std::net::TcpStream
    let std_tcp_stream = tcp_stream.into_std()?;
    // Set read timeout
    std_tcp_stream.set_read_timeout(Some(timeout))?;
    // Convert back to tokio TcpStream
    let tokio_tcp_stream = TcpStream::from_std(std_tcp_stream)?;
    Ok(tokio_tcp_stream)
}

pub async fn read_timeout<S>(
    reader: &mut S,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_bytes: usize,
) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let start = Instant::now();
    let mut buf = [0u8; 4096];
    let mut out = Vec::new();

    loop {
        // Check total timeout
        let elapsed = start.elapsed();
        if elapsed >= total_timeout {
            break;
        }
        let remaining_total = total_timeout - elapsed;
        let wait = idle_timeout.min(remaining_total);

        match timeout(wait, reader.read(&mut buf)).await {
            // Closed by peer
            Ok(Ok(0)) => break,
            // Data read
            Ok(Ok(n)) => {
                if out.len().saturating_add(n) > max_bytes {
                    bail!(
                        "response exceeded max_bytes ({} + {} > {})",
                        out.len(),
                        n,
                        max_bytes
                    );
                }
                out.extend_from_slice(&buf[..n]);

                continue;
            }
            // Read error
            Ok(Err(e)) => bail!("error reading response: {e}"),
            // Idle timeout (no data received)
            Err(_elapsed) => break,
        }
    }

    if out.is_empty() {
        bail!("no response within time limits");
    }
    Ok(out)
}

// Build a regex with given pattern and flags
fn build_regex(pat: &str, flags: &str) -> anyhow::Result<Regex> {
    let mut b = RegexBuilder::new(pat);
    b.case_insensitive(flags.contains('i')).dot_matches_new_line(flags.contains('s'));
    //b.multi_line(true);
    Ok(b.build()?)
}

/// Build a regex for HTTP headers (multi-line, case-insensitive, dot matches new line)
fn build_http_regex(pat: &str) -> anyhow::Result<Regex> {
    Ok(RegexBuilder::new(pat)
        .multi_line(true)         
        .case_insensitive(true)   
        .dot_matches_new_line(true)
        .build()?)
}

/// Expand CPE templates with regex capture groups
fn expand_cpe_templates(cpe_list: &[String], caps: &regex::Captures) -> Vec<String> {
    let mut out = Vec::with_capacity(cpe_list.len());
    for t in cpe_list {
        let mut s = t.clone();
        // Replace $1, $2, ... $99 with corresponding capture groups
        for i in (1..=99).rev() {
            let needle = format!("${}", i);
            if s.contains(&needle) {
                let repl = caps.get(i).map(|m| m.as_str()).unwrap_or("");
                s = s.replace(&needle, repl);
            }
        }
        out.push(s);
    }
    out
}
