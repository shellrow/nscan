use std::{path::PathBuf, time::Duration};
use rand::seq::SliceRandom;
use rand::thread_rng;
use anyhow::Result;
use crate::{cli::{HostScanArgs, HostScanProto}, endpoint::{Endpoint, Host, Port, TransportProtocol}, output::ScanResult, scan::HostScanner, util::json::{save_json_output, JsonStyle}};
use crate::probe::ProbeSetting;

/// Run host scan
pub async fn run(args: HostScanArgs, no_stdout: bool, output: Option<PathBuf>) -> Result<()> {
    let mut target_hosts: Vec<Host> = crate::cli::host::parse_target_hosts(&args.target).await?;
    if target_hosts.is_empty() { anyhow::bail!("no targets resolved"); }

    let mut ports: Vec<Port> = Vec::new();
    match args.proto {
        HostScanProto::Tcp => {
            ports = crate::cli::port::parse_ports(&args.ports, TransportProtocol::Tcp)?;
        }
        _ => {}
    }

    if !args.ordered {
        // Randomize the order of targets and ports
        target_hosts.shuffle(&mut thread_rng());
        ports.shuffle(&mut thread_rng());
    }

    let mut target_endpoints: Vec<Endpoint> = Vec::new();

    for host in target_hosts {
        let mut endpoint = Endpoint::new(host.ip);
        endpoint.hostname = host.hostname;
        for port in &ports {
            endpoint.upsert_port(port.clone());
        }
        target_endpoints.push(endpoint);
    }

    let interface: netdev::Interface = if let Some(if_name) = args.interface {
        match crate::interface::get_interface_by_name(if_name.to_string()) {
            Some(iface) => iface,
            None => anyhow::bail!("interface not found"),
        }
    } else {
        match netdev::get_default_interface() {
            Ok(iface) => iface,
            Err(_) => anyhow::bail!("failed to get default interface"),
        }
    };

    let probe_setting = ProbeSetting {
        if_index: interface.index,
        target_endpoints: target_endpoints,
        host_concurrency: args.concurrency,
        port_concurrency: args.concurrency,
        task_timeout: Duration::from_secs(30),
        connect_timeout: Duration::from_millis(args.timeout_ms),
        wait_time: Duration::from_millis(args.wait_ms),
        send_rate: Duration::from_millis(1),
    };

    let host_scanner = HostScanner::new(probe_setting.clone(), args.proto);
    if !probe_setting.target_endpoints.is_empty() {
        tracing::info!("Starting {} host scan. Target: {} host(s), {} port(s)", args.proto.as_str().to_uppercase(), probe_setting.target_endpoints.len(), probe_setting.target_endpoints[0].ports.len());
    }
    let mut hostscan_result: ScanResult = host_scanner.run().await?;
    hostscan_result.sort_endpoints();
    tracing::info!("{} Host scan completed in {:?}", args.proto.as_str().to_uppercase(), hostscan_result.scan_time);

    // Print result as a tree
    if !no_stdout {
        crate::output::host::print_report_tree(&hostscan_result);
    }
    if let Some(path) = &output {
        match save_json_output(&hostscan_result, path, JsonStyle::Pretty) {
            Ok(_) => {
                if !no_stdout {
                    tracing::info!("JSON output saved to {}", path.display());
                }
            },
            Err(e) => tracing::error!("Failed to save JSON output: {}", e),
        }
    }
    Ok(())
}
