use std::{collections::BTreeMap, time::Duration};

use anyhow::Result;
use futures::StreamExt;
use tokio::sync::mpsc;
use tracing_indicatif::span_ext::IndicatifSpanExt;
use crate::{cli::PortScanMethod, endpoint::{EndpointResult, OsGuess, Port, PortResult, PortState, ServiceInfo, TransportProtocol}, output::ScanResult, scan::ProbeSetting, service::probe::quic::quic_client_config};

/// Try to connect to the given ports on the target endpoint using QUIC protocol.
/// Concurrency specifies the number of concurrent connection attempts.
pub async fn try_connect_ports(
    target: crate::endpoint::Endpoint,
    concurrency: usize,
    timeout: Duration,
) -> Result<EndpointResult> {
    let alpn: [&[u8]; 8] = [
            b"h3".as_slice(),
            b"h3-34".as_slice(), b"h3-33".as_slice(), b"h3-32".as_slice(), b"h3-31".as_slice(), b"h3-30".as_slice(), b"h3-29".as_slice(),
            b"hq-29".as_slice(),
        ];
    let (ch_tx, mut ch_rx) = mpsc::unbounded_channel::<PortResult>();
    let header_span = tracing::info_span!("quic_connect_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message(&format!("QUIC PortScan ({})", target.ip));
    header_span.pb_set_length(target.ports.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    let span_rx = header_span.clone();
    let recv_task = tokio::spawn(async move {
        let mut open_ports: BTreeMap<Port, PortResult> = BTreeMap::new();
        while let Some(port_result) = ch_rx.recv().await {
            open_ports.insert(port_result.port.clone(), port_result);
            // Update progress bar
            span_rx.pb_inc(1);
        }
        open_ports
    });

    let hostname = target.hostname.clone().unwrap_or_else(|| target.ip.to_string());
    let prod = futures::stream::iter(target.socket_addrs(TransportProtocol::Quic)).for_each_concurrent(concurrency, move |socket_addr| {
        let ch_tx = ch_tx.clone();
        let hostname = hostname.clone();
        let client_cfg = quic_client_config(true, &alpn).unwrap();

        async move {
            let mut endpoint = match quinn::Endpoint::client((if target.ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).parse().unwrap()) {
                Ok(ep) => ep,
                Err(_) => return,
            };
            endpoint.set_default_client_config(client_cfg.clone());
            let connect_fut = match endpoint.connect(socket_addr, hostname.as_str()) {
                Ok(connecting) => {
                    connecting
                }
                Err(e) => {
                    tracing::error!("Failed to connect to {}: {}", socket_addr, e);
                    return;
                }
            };
            let mut port_result = PortResult {
                port: Port::new(socket_addr.port(), TransportProtocol::Udp),
                state: PortState::Closed,
                service: ServiceInfo::default(),
                rtt_ms: None,
            };
            match tokio::time::timeout(timeout, connect_fut).await {
                Ok(quinn_conn) => {
                    match quinn_conn {
                        Ok(conn) => {
                            // Connection succeeded
                            port_result.state = PortState::Open;
                            conn.close(0u32.into(), b"Connection closed by client");
                        }
                        Err(e) => {
                            match e {
                                quinn::ConnectionError::VersionMismatch 
                                | quinn::ConnectionError::TransportError(_) 
                                | quinn::ConnectionError::ConnectionClosed(_) 
                                | quinn::ConnectionError::ApplicationClosed(_)
                                | quinn::ConnectionError::Reset => {
                                    // Error, but QUIC service is still running
                                    // So we classify it as open
                                    port_result.state = PortState::Open;
                                },
                                _ => {},
                            }
                        }
                    }
                }
                Err(e) => {
                    // Timeout
                    tracing::error!("Failed to connect to {}: {}", socket_addr, e);
                }
            }
            let _ = ch_tx.send(port_result);
        }
    });

    let prod_task = tokio::spawn(prod);
    let (results_res, _prod_res) = tokio::join!(recv_task, prod_task);
    let open_ports = results_res?;
    // Finish header span
    drop(header_span);

    let ep = EndpointResult {
        ip: target.ip,
        hostname: target.hostname,
        ports: open_ports,
        mac_addr: target.mac_addr,
        vendor_name: None,
        os: OsGuess::default(),
        tags: target.tags,
        cpes: Vec::new(),
    };
    Ok(ep)
}

/// Run a QUIC connect scan based on the provided probe settings.
pub async fn run_connect_scan(
    setting: ProbeSetting,
) -> Result<ScanResult> {
    let start_time = std::time::Instant::now();
    let mut tasks = vec![];
    for target in setting.target_endpoints {
        tasks.push(tokio::spawn(async move {
            let host = try_connect_ports(
                target,
                setting.port_concurrency,
                setting.connect_timeout,
            )
            .await;
            host
        }));
    }
    let mut endpoints: Vec<EndpointResult> = vec![];
    for task in tasks {
        match task.await {
            Ok(endpoint) => {
                match endpoint {
                    Ok(ep) => endpoints.push(ep),
                    Err(e) => {
                        tracing::error!("Failed to connect to endpoint: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to join task: {}", e);
            }
        }
    }
    let mut result = ScanResult::new();
    result.endpoints = endpoints;
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
