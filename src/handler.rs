use crate::json_models::{JsonPortScanResult, JsonHostScanResult};
use crate::{db, define, option, result, scan, sys, output};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

pub async fn handle_port_scan(opt: option::ScanOption) {
    let probe_opt: option::ScanOption = opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move || {
        async_io::block_on(async { scan::run_service_scan(probe_opt, &msg_tx).await })
    });
    let pb = output::get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_PORTSCAN => {
                    pb.set_message("Scanning ports ...");
                }
                define::MESSAGE_START_SERVICEDETECTION => {
                    pb.set_message("Detecting services ...");
                }
                define::MESSAGE_START_OSDETECTION => {
                    pb.set_message("Detecting OS ...");
                }
                _ => {}
            }
        }
    }
    pb.finish_and_clear();
    let result: result::PortScanResult = handle.join().unwrap();
    let json_result: JsonPortScanResult = JsonPortScanResult::from_result(sys::get_probe_id(), result.clone());
    println!();
    println!("[Result]");
    println!("────────────────────────────────────────");
    println!("{}",serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error")));

    if !opt.save_file_path.is_empty() {
        output::save_json(
            serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error")),
            opt.save_file_path.clone(),
        );
        println!("Probe result saved to: {}", opt.save_file_path);
    }
}

pub async fn handle_host_scan(opt: option::ScanOption) {
    let mut probe_opt: option::ScanOption = opt.clone();
    probe_opt.oui_map = db::get_oui_detail_map();
    probe_opt.ttl_map = db::get_os_ttl_map();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move || {
        async_io::block_on(async { scan::run_node_scan(probe_opt, &msg_tx).await })
    });
    let pb = output::get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_HOSTSCAN => {
                    pb.set_message("Scanning hosts ...");
                }
                define::MESSAGE_START_LOOKUP => {
                    pb.set_message("Lookup ...");
                }
                _ => {}
            }
        }
    }
    pb.finish_and_clear();
    let result: result::HostScanResult = handle.join().unwrap();
    let json_result: JsonHostScanResult = JsonHostScanResult::from_result(sys::get_probe_id(), result.clone());
    println!();
    println!("[Result]");
    println!("────────────────────────────────────────");
    println!("{}",serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error")));

    if !opt.save_file_path.is_empty() {
        output::save_json(
            serde_json::to_string_pretty(&json_result).unwrap_or(String::from("Serialize Error")),
            opt.save_file_path.clone(),
        );
        println!("Probe result saved to: {}", opt.save_file_path);
    }
}
