use crate::{
    cli::PortScanMethod,
    endpoint::{EndpointResult, OsGuess, Port, PortResult, PortState, ServiceInfo},
    output::ScanResult,
    probe::ProbeSetting,
};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};
use tokio::net::TcpStream;

/// Run a TCP connect scan based on the provided probe settings.
pub async fn run_connect_scan(setting: ProbeSetting) -> Result<ScanResult> {
    let concurrency = setting.port_concurrency.max(1);
    let connect_timeout = setting.connect_timeout;
    let deadline = tokio::time::Instant::now() + setting.task_timeout;
    let start_time = std::time::Instant::now();
    let mut endpoint_map: BTreeMap<IpAddr, EndpointResult> = BTreeMap::new();
    let mut work_items: Vec<(IpAddr, Port)> = Vec::new();

    for target in setting.target_endpoints {
        endpoint_map.insert(
            target.ip,
            EndpointResult {
                ip: target.ip,
                hostname: target.hostname,
                ports: BTreeMap::new(),
                mac_addr: target.mac_addr,
                vendor_name: None,
                os: OsGuess::default(),
                tags: target.tags,
                cpes: Vec::new(),
            },
        );
        for port in target.ports {
            work_items.push((target.ip, port));
        }
    }

    if work_items.is_empty() {
        let mut result = ScanResult::new();
        result.endpoints = endpoint_map.into_values().collect();
        result.scan_time = start_time.elapsed();
        result.fingerprints = Vec::new();
        return Ok(result);
    }

    let mut connect_stream = stream::iter(work_items)
        .map(move |(ip, port)| async move {
            let socket_addr = SocketAddr::new(ip, port.number);
            let mut port_result = PortResult {
                port,
                state: PortState::Filtered,
                service: ServiceInfo::default(),
                rtt_ms: None,
            };

            let started = std::time::Instant::now();
            match tokio::time::timeout(connect_timeout, TcpStream::connect(socket_addr)).await {
                Ok(Ok(stream)) => {
                    port_result.state = PortState::Open;
                    port_result.rtt_ms =
                        Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32);
                    drop(stream);
                }
                Ok(Err(error)) => port_result.state = classify_connect_error(&error)?,
                Err(_) => {}
            }

            Ok::<_, anyhow::Error>((ip, port_result))
        })
        .buffer_unordered(concurrency);

    while let Some(item) = tokio::time::timeout_at(deadline, connect_stream.next())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "port scan deadline exceeded; split the scan or increase --task-timeout-ms"
            )
        })?
    {
        let (ip, port_result) = item?;
        if let Some(endpoint) = endpoint_map.get_mut(&ip) {
            endpoint.upsert_port(port_result);
        }
    }

    let mut result = ScanResult::new();
    result.endpoints = endpoint_map.into_values().collect();
    result.scan_time = start_time.elapsed();
    result.fingerprints = Vec::new();
    Ok(result)
}

/// Run a routed TCP SYN scan.
pub async fn run_syn_scan(setting: ProbeSetting) -> Result<ScanResult> {
    crate::scan::raw::run(setting, crate::scan::raw::Kind::Tcp, true).await
}

pub async fn run_port_scan(setting: ProbeSetting, method: PortScanMethod) -> Result<ScanResult> {
    match method {
        PortScanMethod::Connect => run_connect_scan(setting).await,
        PortScanMethod::Syn => run_syn_scan(setting).await,
    }
}

pub async fn run_host_scan(setting: ProbeSetting) -> Result<ScanResult> {
    crate::scan::raw::run(setting, crate::scan::raw::Kind::Tcp, false).await
}

/// Only an explicit refusal proves a TCP port is closed.
fn classify_connect_error(error: &std::io::Error) -> Result<PortState> {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::ConnectionRefused => Ok(PortState::Closed),
        ErrorKind::TimedOut
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::PermissionDenied => Ok(PortState::Filtered),
        _ => Err(anyhow::anyhow!("TCP connect failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::TransportProtocol;
    use std::{
        io::{Error, ErrorKind},
        time::Duration,
    };

    #[test]
    fn connection_errors_preserve_uncertainty() {
        assert_eq!(
            classify_connect_error(&Error::from(ErrorKind::ConnectionRefused)).unwrap(),
            PortState::Closed
        );
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
        ] {
            assert_eq!(
                classify_connect_error(&Error::from(kind)).unwrap(),
                PortState::Filtered
            );
        }
        assert!(classify_connect_error(&Error::from(ErrorKind::OutOfMemory)).is_err());
    }

    #[tokio::test]
    async fn connect_scan_reports_local_open_and_refused_ports() {
        let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        // macOS silently drops SYNs to bound, non-listening sockets.
        // Release the reservation before testing an actual connection refusal.
        let closed = tokio::net::TcpSocket::new_v4().unwrap();
        closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let open_port = Port::new(open.local_addr().unwrap().port(), TransportProtocol::Tcp);
        let closed_port = Port::new(closed.local_addr().unwrap().port(), TransportProtocol::Tcp);
        drop(closed);
        let mut endpoint = crate::endpoint::Endpoint::new("127.0.0.1".parse().unwrap());
        endpoint.upsert_port(open_port);
        endpoint.upsert_port(closed_port);
        let result = run_connect_scan(ProbeSetting {
            target_endpoints: vec![endpoint],
            if_index: 0,
            host_concurrency: 1,
            port_concurrency: 2,
            task_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            wait_time: Duration::ZERO,
            send_rate: Duration::ZERO,
        })
        .await
        .unwrap();
        assert_eq!(result.endpoints[0].ports[&open_port].state, PortState::Open);
        assert_eq!(
            result.endpoints[0].ports[&closed_port].state,
            PortState::Closed
        );
        assert!(result.endpoints[0].ports[&open_port].rtt_ms.is_some());
    }
}
