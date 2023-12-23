use crate::json_models::{JsonHostScanResult, JsonPortScanResult};
use crate::{define, output};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use crate::option;
use crate::scan;
use crate::result::{PortScanResult, HostScanResult};
use crate::sys;

pub async fn handle_port_scan(opt: option::PortScanOption) {
    let probe_opt: option::PortScanOption = opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move || {
        async_io::block_on(async { scan::run_service_scan(probe_opt, &msg_tx).await })
    });
    let mut pb = output::get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_PORTSCAN => {
                    pb.set_message("Scanning ports ...");
                }
                define::MESSAGE_END_PORTSCAN => {
                    pb.finish_with_message("Port scan");
                    pb = output::get_spinner();
                }
                define::MESSAGE_START_SERVICEDETECTION => {
                    pb.set_message("Detecting services ...");
                }
                define::MESSAGE_END_SERVICEDETECTION => {
                    pb.finish_with_message("Service detection");
                    pb = output::get_spinner();
                }
                define::MESSAGE_START_OSDETECTION => {
                    pb.set_message("Detecting OS ...");
                }
                define::MESSAGE_END_OSDETECTION => {
                    pb.finish_with_message("OS detection");
                    pb = output::get_spinner();
                }
                _ => {}
            }
        }
    }
    pb.finish_and_clear();
    let result: PortScanResult = handle.join().unwrap();
    let json_result: JsonPortScanResult =
        JsonPortScanResult::from_result(sys::get_probe_id(), result.clone());
    if opt.json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error"))
        );
    } else {
        output::show_portscan_result(result.clone());
    }

    if !opt.save_file_path.is_empty() {
        output::save_json(
            serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error")),
            opt.save_file_path.clone(),
        );
        println!("Probe result saved to: {}", opt.save_file_path);
    }
}

pub async fn handle_host_scan(opt: option::HostScanOption) {
    let probe_opt: option::HostScanOption = opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move || {
        async_io::block_on(async { scan::run_node_scan(probe_opt, &msg_tx).await })
    });
    let mut pb = output::get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_HOSTSCAN => {
                    pb.set_message("Scanning hosts ...");
                }
                define::MESSAGE_END_HOSTSCAN => {
                    pb.finish_with_message("Host scan");
                    pb = output::get_spinner();
                }
                define::MESSAGE_START_LOOKUP => {
                    pb.set_message("Lookup ...");
                }
                define::MESSAGE_END_LOOKUP => {
                    pb.finish_with_message("Lookup");
                    pb = output::get_spinner();
                }
                _ => {}
            }
        }
    }
    pb.finish_and_clear();
    let result: HostScanResult = handle.join().unwrap();
    let json_result: JsonHostScanResult =
        JsonHostScanResult::from_result(sys::get_probe_id(), result.clone());
    if opt.json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error"))
        );
    } else {
        output::show_hostscan_result(result.clone());
    }

    if !opt.save_file_path.is_empty() {
        output::save_json(
            serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error")),
            opt.save_file_path.clone(),
        );
        println!("Probe result saved to: {}", opt.save_file_path);
    }
}

pub fn list_interfaces(json_output: bool) {
    let interfaces = xenet::net::interface::get_interfaces();
    if json_output {
        output::show_interfaces_json(interfaces);
    }else {
        output::show_interfaces(interfaces);
    }
}
