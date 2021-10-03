use term_table::{Table, TableStyle};
use term_table::table_cell::{TableCell,Alignment};
use term_table::row::Row;
use crossterm::style::Colorize;
use netscan::PortScanType;
use std::time::Duration;
use crate::result::{PortResult, HostResult};
use crate::option::{PortOption, HostOption};

pub fn print_port_option(port_option: PortOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Options".cyan(), 1, Alignment::Left)
    ]));
    if !port_option.dst_host_name.is_empty() {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Target Host:", 1, Alignment::Left),
            TableCell::new_with_alignment(port_option.dst_host_name, 1, Alignment::Left)
        ]));
    }else{
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Target Host:", 1, Alignment::Left),
            TableCell::new_with_alignment(port_option.dst_ip_addr, 1, Alignment::Left)
        ]));
    }
    if port_option.default_scan {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Target Port:", 1, Alignment::Left),
            TableCell::new_with_alignment("Default 1005 ports", 1, Alignment::Left)
        ]));
    } else {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Target Port:", 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{} ports", port_option.dst_ports.len()), 1, Alignment::Left)
        ]));
    }
    match port_option.scan_type {
        PortScanType::SynScan => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Scan Type:", 1, Alignment::Left),
                TableCell::new_with_alignment("TCP SYN Scan", 1, Alignment::Left)
            ]));
        },
        PortScanType::ConnectScan => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Scan Type:", 1, Alignment::Left),
                TableCell::new_with_alignment("TCP Connect Scan", 1, Alignment::Left)
            ]));
        },
    }
    if port_option.include_detail {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Service Probe:", 1, Alignment::Left),
            TableCell::new_with_alignment("True", 1, Alignment::Left)
        ]));
    } else {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Service Probe:", 1, Alignment::Left),
            TableCell::new_with_alignment("False", 1, Alignment::Left)
        ]));
    }
    println!("{}", table.render());
}

pub fn print_host_option(host_option: HostOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Options".cyan(), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Target:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{} IPs", host_option.dst_hosts.len()), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Type:", 1, Alignment::Left),
        TableCell::new_with_alignment("ICMP Scan", 1, Alignment::Left)
    ]));
    println!("{}", table.render());
}

pub fn print_port_result(port_result: PortResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Results".cyan(), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Port Number", 1, Alignment::Left),
        TableCell::new_with_alignment("Detail", 1, Alignment::Left)
    ]));
    for port_info in port_result.ports {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(port_info.port_number, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("Status:", 1, Alignment::Left),
            TableCell::new_with_alignment(port_info.port_status, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("Service Name:", 1, Alignment::Left),
            TableCell::new_with_alignment(port_info.service_name, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("Service Version:", 1, Alignment::Left),
            TableCell::new_with_alignment(port_info.service_version, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("Remark:", 1, Alignment::Left),
            TableCell::new_with_alignment(port_info.remark, 1, Alignment::Left)
        ]));
    }

    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Performance".cyan(), 2, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Port Scan:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", port_result.port_scan_time), 1, Alignment::Left)
    ]));
    if port_result.probe_time == Duration::from_nanos(0) {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Probe:", 1, Alignment::Left),
            TableCell::new_with_alignment("(Skipped)", 1, Alignment::Left)
        ]));
    }else{
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Probe:", 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", port_result.probe_time), 1, Alignment::Left)
        ]));
    }
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Total:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", port_result.total_scan_time), 1, Alignment::Left)
    ]));  
    println!("{}", table.render());
}

pub fn print_host_result(host_result: HostResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Results".cyan(), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Detail", 1, Alignment::Left)
    ]));
    for host_info in host_result.hosts {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(host_info.ip_addr, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("MAC Address:", 1, Alignment::Left),
            TableCell::new_with_alignment(host_info.mac_addr, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("Vendor:", 1, Alignment::Left),
            TableCell::new_with_alignment(host_info.vendor_info, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("Host Name:", 1, Alignment::Left),
            TableCell::new_with_alignment(host_info.host_name, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("OS Name:", 1, Alignment::Left),
            TableCell::new_with_alignment(host_info.os_name, 1, Alignment::Left)
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("OS Version:", 1, Alignment::Left),
            TableCell::new_with_alignment(host_info.os_version, 1, Alignment::Left)
        ]));
    }
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Performance".cyan(), 2, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Port Scan:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", host_result.host_scan_time), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", host_result.probe_time), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Total:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", host_result.total_scan_time), 1, Alignment::Left)
    ]));  
    println!("{}", table.render());
}

pub fn save_port_result(port_result: PortResult) {
    println!("{:?}", port_result);
}

pub fn save_host_result(host_result: HostResult) {
    println!("{:?}", host_result);
}
