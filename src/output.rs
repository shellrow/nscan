use crate::option::{CommandType, ScanOption};
use std::fs;
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};

use indicatif::{ProgressBar, ProgressStyle};

pub fn get_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    let ps: ProgressStyle = ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]);
    pb.set_style(ps);
    pb
}

pub fn show_options(opt: ScanOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Options]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Type", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.command_type.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Interface Name", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Source IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.src_ip, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Timeout(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.timeout.as_millis(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("WaitTime(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.wait_time.as_millis(), 1, Alignment::Left),
    ]));
    match opt.command_type {
        CommandType::PortScan => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Scan Type", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.port_scan_type.name(), 1, Alignment::Left),
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Async", 1, Alignment::Left),
                if opt.async_scan {
                    TableCell::new_with_alignment("True", 1, Alignment::Left)
                } else {
                    TableCell::new_with_alignment("False", 1, Alignment::Left)
                },
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Send Rate(ms)", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left),
            ]));
            println!("{}", table.render());
            let mut table = Table::new();
            table.max_column_width = 60;
            table.separate_rows = false;
            table.style = TableStyle::blank();
            println!("[Target]");
            println!("────────────────────────────────────────");
            for target in opt.targets {
                if target.ip_addr.to_string() == target.host_name || target.host_name.is_empty() {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
                        TableCell::new_with_alignment(target.ip_addr, 1, Alignment::Left),
                    ]));
                } else {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
                        TableCell::new_with_alignment(target.ip_addr, 1, Alignment::Left),
                    ]));
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
                        TableCell::new_with_alignment(target.host_name, 1, Alignment::Left),
                    ]));
                }
                if target.ports.len() > 10 {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("Port", 1, Alignment::Left),
                        TableCell::new_with_alignment(
                            format!("{} port(s)", target.ports.len()),
                            1,
                            Alignment::Left,
                        ),
                    ]));
                } else {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("Port", 1, Alignment::Left),
                        TableCell::new_with_alignment(
                            format!("{:?} port(s)", target.ports),
                            1,
                            Alignment::Left,
                        ),
                    ]));
                }
            }
            println!("{}", table.render());
        }
        CommandType::HostScan => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Scan Type", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.host_scan_type.name(), 1, Alignment::Left),
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Async", 1, Alignment::Left),
                if opt.async_scan {
                    TableCell::new_with_alignment("True", 1, Alignment::Left)
                } else {
                    TableCell::new_with_alignment("False", 1, Alignment::Left)
                },
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Send Rate(ms)", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left),
            ]));
            println!("{}", table.render());
            let mut table = Table::new();
            table.max_column_width = 60;
            table.separate_rows = false;
            table.style = TableStyle::blank();
            println!("[Target]");
            println!("────────────────────────────────────────");
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Host", 1, Alignment::Left),
                TableCell::new_with_alignment(
                    format!("{} host(s)", opt.targets.len()),
                    1,
                    Alignment::Left,
                ),
            ]));
            println!("{}", table.render());
        }
    }
}

pub fn save_json(json: String, file_path: String) -> bool {
    match fs::write(file_path, json) {
        Ok(_) => true,
        Err(_) => false,
    }
}
