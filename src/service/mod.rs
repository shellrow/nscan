use anyhow::{Result, bail};
use futures::stream::{self, StreamExt};
use std::{net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{Instant, timeout},
};

use crate::{
    endpoint::{Endpoint, Port},
    service::probe::{PortProbe, PortProbeResult, ProbeContext, ProbeMode, ServiceProbe},
};

pub mod probe;

/// Configuration for service probing
#[derive(Clone, Debug)]
pub struct ServiceProbeConfig {
    /// Per-operation timeout; each complete probe is bounded by four times this value.
    pub timeout: Duration,
    pub max_concurrency: usize,
    pub max_read_size: usize,
    pub mode: ProbeMode,
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
        ServiceDetector { config }
    }
    pub async fn run_service_detection(
        &self,
        targets: Vec<Endpoint>,
    ) -> Result<ServiceDetectionResult> {
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
        }

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
    let selected = select_probe(config.mode, port);
    let probe_id = match selected {
        Ok(probe) => probe,
        Err(error) => return vec![Err(error)],
    };
    let ctx = ProbeContext {
        ip,
        hostname,
        probe: PortProbe {
            probe_id,
            port: port.number,
            transport: port.transport,
        },
        timeout: config.timeout,
        max_read_size: config.max_read_size,
        sni: config.sni,
        skip_cert_verify: config.skip_cert_verify,
    };
    vec![
        timeout(config.timeout.saturating_mul(4), async {
            match probe_id {
                ServiceProbe::TcpNull => probe::null::NullProbe::run(ctx).await,
                ServiceProbe::TcpHTTPGet | ServiceProbe::TcpHTTPSGet => {
                    probe::http::HttpProbe::run(ctx).await
                }
                ServiceProbe::TcpTlsSession => probe::tls::TlsProbe::run(ctx).await,
                ServiceProbe::UdpQuic => probe::quic::QuicProbe::run(ctx).await,
            }
        })
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("service probe timed out"))),
    ]
}

pub fn select_probe(mode: ProbeMode, port: Port) -> Result<ServiceProbe> {
    use crate::endpoint::TransportProtocol;
    if port.transport == TransportProtocol::Quic {
        anyhow::ensure!(
            matches!(mode, ProbeMode::Auto | ProbeMode::Quic),
            "TCP probe requested for QUIC"
        );
        return Ok(ServiceProbe::UdpQuic);
    }
    anyhow::ensure!(
        port.transport == TransportProtocol::Tcp,
        "built-in UDP service probing is unsupported"
    );
    Ok(match mode {
        ProbeMode::Auto => match port.number {
            80 | 8000 | 8080 => ServiceProbe::TcpHTTPGet,
            443 | 8443 => ServiceProbe::TcpHTTPSGet,
            465 | 636 | 853 | 993 | 995 => ServiceProbe::TcpTlsSession,
            _ => ServiceProbe::TcpNull,
        },
        ProbeMode::Banner => ServiceProbe::TcpNull,
        ProbeMode::Http => ServiceProbe::TcpHTTPGet,
        ProbeMode::Https => ServiceProbe::TcpHTTPSGet,
        ProbeMode::Tls => ServiceProbe::TcpTlsSession,
        ProbeMode::Quic => anyhow::bail!("QUIC probe requires QUIC transport"),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn bounded_reads_stop_on_idle_and_reject_oversized_responses() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tx.write_all(b"banner").await.unwrap();
        let data = read_timeout(
            &mut rx,
            Duration::from_millis(10),
            Duration::from_millis(100),
            64,
        )
        .await
        .unwrap();
        assert_eq!(data, b"banner");
        tx.write_all(b"too large").await.unwrap();
        assert!(
            read_timeout(
                &mut rx,
                Duration::from_millis(10),
                Duration::from_millis(100),
                2
            )
            .await
            .is_err()
        );
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::endpoint::TransportProtocol;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn service_detection_keeps_banner_when_peer_leaves_connection_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let config = ServiceProbeConfig {
            timeout: Duration::from_millis(50),
            max_concurrency: 1,
            max_read_size: 4096,
            mode: ProbeMode::Banner,
            sni: true,
            skip_cert_verify: true,
        };
        let results = run_probes_for_target_port(
            &config,
            "127.0.0.1".parse().unwrap(),
            None,
            Port::new(port, TransportProtocol::Tcp),
        )
        .await;
        server.abort();
        assert!(results.iter().any(|r| {
            r.as_ref()
                .is_ok_and(|r| r.service_info.banner.as_deref() == Some("SSH-2.0-OpenSSH_9.9"))
        }));
    }
}
