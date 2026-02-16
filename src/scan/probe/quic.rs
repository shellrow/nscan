use std::{collections::BTreeMap, net::{IpAddr, SocketAddr}};

use anyhow::Result;
use futures::stream::{self, StreamExt};
use tracing_indicatif::span_ext::IndicatifSpanExt;
use crate::{cli::PortScanMethod, endpoint::{EndpointResult, OsGuess, Port, PortResult, PortState, ServiceInfo, TransportProtocol}, output::ScanResult, scan::ProbeSetting, service::probe::quic::quic_client_config};

/// Run a QUIC connect scan based on the provided probe settings.
pub async fn run_connect_scan(
    setting: ProbeSetting,
) -> Result<ScanResult> {
    let concurrency = setting.port_concurrency.max(1);
    let connect_timeout = setting.connect_timeout;
    let start_time = std::time::Instant::now();
    let alpn: [&[u8]; 8] = [
            b"h3".as_slice(),
            b"h3-34".as_slice(), b"h3-33".as_slice(), b"h3-32".as_slice(), b"h3-31".as_slice(), b"h3-30".as_slice(), b"h3-29".as_slice(),
            b"hq-29".as_slice(),
        ];

    let mut endpoint_map: BTreeMap<IpAddr, EndpointResult> = BTreeMap::new();
    let mut work_items: Vec<(IpAddr, String, Port)> = Vec::new();
    for target in setting.target_endpoints {
        endpoint_map.insert(target.ip, EndpointResult {
            ip: target.ip,
            hostname: target.hostname.clone(),
            ports: BTreeMap::new(),
            mac_addr: target.mac_addr,
            vendor_name: None,
            os: OsGuess::default(),
            tags: target.tags,
            cpes: Vec::new(),
        });

        let hostname = target.hostname.unwrap_or_else(|| target.ip.to_string());
        for port in target.ports {
            work_items.push((target.ip, hostname.clone(), port));
        }
    }

    if work_items.is_empty() {
        let mut result = ScanResult::new();
        result.endpoints = endpoint_map.into_values().collect();
        result.scan_time = start_time.elapsed();
        result.fingerprints = Vec::new();
        return Ok(result);
    }

    let client_cfg = quic_client_config(true, &alpn)?;
    let header_span = tracing::info_span!("quic_connect_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message("QUIC PortScan");
    header_span.pb_set_length(work_items.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    let mut connect_stream = stream::iter(work_items)
        .map(move |(ip, hostname, port)| {
            let client_cfg = client_cfg.clone();
            async move {
                let socket_addr = SocketAddr::new(ip, port.number);
                let bind_addr: SocketAddr = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }
                    .parse()
                    .unwrap_or_else(|_| if ip.is_ipv6() { SocketAddr::from(([0u16; 8], 0)) } else { SocketAddr::from(([0, 0, 0, 0], 0)) });

                let mut port_result = PortResult {
                    port: Port::new(port.number, TransportProtocol::Quic),
                    state: PortState::Closed,
                    service: ServiceInfo::default(),
                    rtt_ms: None,
                };

                let mut endpoint = match quinn::Endpoint::client(bind_addr) {
                    Ok(ep) => ep,
                    Err(e) => {
                        tracing::error!("Failed to create QUIC endpoint: {}", e);
                        return (ip, port_result);
                    }
                };
                endpoint.set_default_client_config(client_cfg);

                let connect_fut = match endpoint.connect(socket_addr, hostname.as_str()) {
                    Ok(connecting) => connecting,
                    Err(e) => {
                        tracing::error!("Failed to connect to {}: {}", socket_addr, e);
                        return (ip, port_result);
                    }
                };

                match tokio::time::timeout(connect_timeout, connect_fut).await {
                    Ok(quinn_conn) => match quinn_conn {
                        Ok(conn) => {
                            port_result.state = PortState::Open;
                            conn.close(0u32.into(), b"Connection closed by client");
                        }
                        Err(e) => match e {
                            quinn::ConnectionError::VersionMismatch
                            | quinn::ConnectionError::TransportError(_)
                            | quinn::ConnectionError::ConnectionClosed(_)
                            | quinn::ConnectionError::ApplicationClosed(_)
                            | quinn::ConnectionError::Reset => {
                                port_result.state = PortState::Open;
                            }
                            _ => {}
                        },
                    },
                    Err(e) => {
                        tracing::error!("Failed to connect to {}: {}", socket_addr, e);
                    }
                }

                (ip, port_result)
            }
        })
        .buffer_unordered(concurrency);

    while let Some((ip, port_result)) = connect_stream.next().await {
        if let Some(endpoint) = endpoint_map.get_mut(&ip) {
            endpoint.upsert_port(port_result);
        }
        header_span.pb_inc(1);
    }

    drop(header_span);

    let mut result = ScanResult::new();
    result.endpoints = endpoint_map.into_values().collect();
    result.scan_time = start_time.elapsed();
    result.fingerprints = Vec::new();
    Ok(result)
}

/// Run a QUIC port scan using the specified probe settings and method.
pub async fn run_port_scan(
    setting: ProbeSetting,
    _method: PortScanMethod,
) -> Result<ScanResult> {
    run_connect_scan(setting).await
}
