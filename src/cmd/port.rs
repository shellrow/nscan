use crate::cmd::common::{
    build_endpoints, derive_connect_timeout, derive_wait_time, merge_endpoints,
    normalize_concurrency, resolve_interface,
};
use crate::{
    cli::PortScanArgs,
    endpoint::{Host, Port, PortState, TransportProtocol},
    output::{
        ScanResult,
        port::{ScanReport, print_report_tree},
    },
    probe::ProbeSetting,
    scan::PortScanner,
    service::{ServiceDetector, ServiceProbeConfig},
    util::json::{JsonStyle, save_json_output},
};
use anyhow::Result;
use rand::seq::SliceRandom;
use std::{path::PathBuf, time::Duration};

/// Run port scan
pub async fn run(args: PortScanArgs, no_stdout: bool, output: Option<PathBuf>) -> Result<()> {
    if args.method == crate::cli::PortScanMethod::Syn
        && args.proto != crate::cli::PortScanTransport::Tcp
    {
        anyhow::bail!("SYN scanning is supported only for TCP");
    }
    if args.nmap || args.os_detect {
        anyhow::ensure!(
            args.proto == crate::cli::PortScanTransport::Tcp,
            "Nmap identification currently supports TCP scans only"
        );
    }
    if args.service_detect {
        crate::service::select_probe(args.service_probe, Port::new(1, args.proto.to_transport()))?;
        if args.quic {
            crate::service::select_probe(
                args.service_probe,
                Port::new(1, TransportProtocol::Quic),
            )?;
        }
    }
    let mut rep = ScanReport::new();
    // Parse target hosts
    let target_hosts: Vec<Host> = crate::cli::host::parse_target_hosts(&args.target).await?;
    if target_hosts.is_empty() {
        anyhow::bail!("no targets resolved");
    }
    let first_host = target_hosts[0].clone();
    // Parse transport protocol
    let transport: TransportProtocol = args.proto.to_transport();
    // Parse ports
    let mut ports: Vec<Port> = crate::cli::port::parse_ports(&args.ports, transport)?;
    if ports.is_empty() {
        anyhow::bail!("no ports to scan");
    }

    if !args.ordered {
        // Randomize the order of ports
        let mut rng = rand::rng();
        ports.shuffle(&mut rng);
    }

    // Create target endpoints from hosts and ports
    let mut target_endpoints = build_endpoints(target_hosts, &ports)?;
    if let Some(name) = &args.sni {
        for endpoint in &mut target_endpoints {
            endpoint.hostname = Some(name.clone());
        }
    }

    // Get network interface
    let uses_raw = args.method == crate::cli::PortScanMethod::Syn;
    anyhow::ensure!(
        uses_raw || args.interface.is_none(),
        "--interface applies to raw SYN probes; connect scans use OS routing"
    );
    let interface = if uses_raw {
        let interface = resolve_interface(args.interface.as_deref())?;
        crate::cmd::common::validate_raw_targets(&interface, &target_endpoints)?;
        Some(interface)
    } else {
        None
    };
    let concurrency = normalize_concurrency(args.concurrency);

    // Initial ping to check reachability and measure latency
    let initial_rtt = if args.no_ping || interface.is_none() {
        Duration::from_millis(200)
    } else {
        match crate::ping::initial_ping(
            interface
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("raw interface unavailable"))?,
            &first_host,
            Some(ports[0].number),
        )
        .await
        {
            Ok(rtt) => rtt,
            Err(e) => {
                tracing::warn!("Initial ping failed: {}. Proceeding with default RTT.", e);
                Duration::from_millis(200) // Default RTT if ping fails
            }
        }
    };

    let mut conn_timeout = derive_connect_timeout(initial_rtt, args.connect_timeout_ms);
    // Windows can take roughly two seconds to report a refused TCP connection.
    // Allow that notification to arrive before classifying the port as filtered.
    if cfg!(windows)
        && !uses_raw
        && transport == TransportProtocol::Tcp
        && args.connect_timeout_ms.is_none()
    {
        conn_timeout = conn_timeout.max(Duration::from_secs(3));
    }
    let wait_time = derive_wait_time(initial_rtt, args.wait_ms);

    // Create probe setting
    let probe_setting = ProbeSetting {
        if_index: interface.as_ref().map_or(0, |iface| iface.index),
        target_endpoints,
        host_concurrency: concurrency,
        port_concurrency: concurrency,
        task_timeout: Duration::from_millis(args.task_timeout_ms),
        connect_timeout: conn_timeout,
        wait_time,
        send_rate: Duration::from_millis(1),
    };

    if !probe_setting.target_endpoints.is_empty() {
        tracing::info!(
            "Starting {} port scan on {} host(s), {} port(s)",
            args.proto.as_str().to_uppercase(),
            probe_setting.target_endpoints.len(),
            probe_setting.target_endpoints[0].ports.len()
        );
    }

    // Run port scan
    let port_scanner = PortScanner::new(probe_setting.clone(), transport, args.method);
    let portscan_result: ScanResult = port_scanner.run().await?;
    tracing::info!(
        "{} Port scan completed in {:?}",
        args.proto.as_str().to_uppercase(),
        portscan_result.scan_time
    );
    let mut endpoint_results = portscan_result.endpoints.clone();

    let mut active_endpoints = portscan_result.get_active_endpoints();

    if active_endpoints.is_empty() {
        tracing::info!("No open ports found");
    }

    rep.apply_port_scan(portscan_result);

    if transport != TransportProtocol::Quic && args.quic {
        let port_scanner =
            PortScanner::new(probe_setting.clone(), TransportProtocol::Quic, args.method);
        let quic_portscan_result = port_scanner.run().await?;
        endpoint_results.extend(quic_portscan_result.endpoints.clone());
        let active_quic_endpoints = quic_portscan_result.get_active_endpoints();
        // Merge active QUIC endpoints with active TCP endpoints
        active_endpoints.extend(active_quic_endpoints);
        active_endpoints = merge_endpoints(active_endpoints);

        rep.apply_port_scan(quic_portscan_result);
    }

    for endpoint in &endpoint_results {
        let mut open_ports: Vec<u16> = Vec::new();
        for (port, port_result) in &endpoint.ports {
            if port_result.state == PortState::Open {
                open_ports.push(port.number);
            }
        }
        tracing::info!("{}: Open ports: {:?}", endpoint.ip, open_ports);
    }

    if args.service_detect {
        // service detection
        let service_probe_setting = ServiceProbeConfig {
            timeout: Duration::from_millis(args.read_timeout_ms.unwrap_or(2_000)),
            max_concurrency: concurrency,
            max_read_size: 1024 * 1024,
            mode: args.service_probe,
            sni: true,
            skip_cert_verify: true,
        };

        let service_detector = ServiceDetector::new(service_probe_setting);
        let service_targets = if let Some(sni_hostname) = &args.sni {
            active_endpoints
                .into_iter()
                .map(|mut ep| {
                    ep.hostname = Some(sni_hostname.clone());
                    ep
                })
                .collect()
        } else {
            active_endpoints
        };
        if !service_targets.is_empty() {
            tracing::info!(
                "Starting service detection on {} host(s), {} port(s)",
                service_targets.len(),
                service_targets[0].ports.len()
            );
        }

        let service_result = service_detector
            .run_service_detection(service_targets)
            .await?;
        tracing::info!(
            "Service detection completed in {:?}",
            service_result.scan_time
        );

        service_result.results.iter().for_each(|result| {
            tracing::debug!(
                "[SERVICE] {}:{} {} {} {:?} {:?}",
                result.ip,
                result.port,
                result.transport.as_str().to_uppercase(),
                result.probe_id.as_str(),
                result.service_info.banner,
                result.service_info.cpes
            );
        });

        rep.apply_service_detection(service_result);
    }

    if args.nmap || args.os_detect {
        let targets = rep
            .endpoints
            .values()
            .filter(|ep| {
                ep.get_open_ports()
                    .iter()
                    .any(|port| port.transport == TransportProtocol::Tcp)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !targets.is_empty() {
            let budget = Duration::from_millis(args.nmap_timeout_ms);
            let deadline = tokio::time::Instant::now() + budget;
            let details = match crate::nmap::Nmap::preflight(&args.nmap_path, budget).await {
                Ok(nmap) => {
                    nmap.identify(
                        &targets,
                        args.nmap,
                        args.os_detect,
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await
                }
                Err(error) => crate::nmap::Identification {
                    source: "nmap".into(),
                    version: String::new(),
                    complete: false,
                    error: Some(format!("{error:#}")),
                    warnings: Vec::new(),
                    hosts: Vec::new(),
                },
            };
            if !details.complete {
                tracing::warn!(
                    "Optional identification incomplete; scan results and available details retained: {}",
                    details.error.as_deref().unwrap_or("unknown error")
                );
            }
            rep.apply_identification(details);
        }
    }
    rep.finish();

    if !no_stdout {
        print_report_tree(&rep);
    }
    if let Some(path) = &output {
        save_json_output(&rep, path, JsonStyle::Pretty)?;
        tracing::info!("JSON output saved to {}", path.display());
    }
    Ok(())
}
