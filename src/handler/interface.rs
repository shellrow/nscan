use std::path::PathBuf;

use clap::ArgMatches;
use netdev::mac::MacAddr;
use netdev::Interface;
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};

use crate::output;

pub fn show_default_interface(args: &ArgMatches) {
    let iface: Interface = match netdev::get_default_interface() {
        Ok(interface) => interface,
        Err(_) => {
            println!("Failed to get default interface");
            return;
        }
    };
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&iface).unwrap();
        println!("{}", json_result);
    }else {
        show_interface_table(&iface);
    }
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&iface).unwrap()) {
                Ok(_) => {
                    output::log_with_time(&format!("Saved to {}", file_path.to_string_lossy()), "INFO");
                },
                Err(e) => {
                    output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                },
            }
        },
        None => {},
    }
}

pub fn show_interfaces(args: &ArgMatches) {
    let interfaces: Vec<Interface> = netdev::get_interfaces();
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&interfaces).unwrap();
        println!("{}", json_result);
    }else {
        show_interfaces_table(&interfaces);
    }
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&interfaces).unwrap()) {
                Ok(_) => {
                    output::log_with_time(&format!("Saved to {}", file_path.to_string_lossy()), "INFO");
                },
                Err(e) => {
                    output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                },
            }
        },
        None => {},
    }
}

pub fn show_interface_table(iface: &Interface) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.has_top_boarder = false;
    table.has_bottom_boarder = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Default Inteface]");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment(&iface.index, 1, Alignment::Left),
        TableCell::new_with_alignment("Name", 1, Alignment::Left),
        TableCell::new_with_alignment(&iface.name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("", 1, Alignment::Left),
        TableCell::new_with_alignment("MAC", 1, Alignment::Left),
        TableCell::new_with_alignment(&iface.mac_addr.unwrap_or(MacAddr::zero()), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("", 1, Alignment::Left),
        TableCell::new_with_alignment("IPv4", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}",&iface.ipv4), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("", 1, Alignment::Left),
        TableCell::new_with_alignment("IPv6", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}",&iface.ipv6), 1, Alignment::Left),
    ]));
    if let Some(gateway) = &iface.gateway {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("Gateway", 1, Alignment::Left),
            TableCell::new_with_alignment("", 1, Alignment::Left),
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Right),
            TableCell::new_with_alignment("IPv4", 1, Alignment::Right),
            TableCell::new_with_alignment(format!("{:?}",&gateway.ipv4), 1, Alignment::Left),
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Right),
            TableCell::new_with_alignment("IPv6", 1, Alignment::Right),
            TableCell::new_with_alignment(format!("{:?}",&gateway.ipv6), 1, Alignment::Left),
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Right),
            TableCell::new_with_alignment("MAC", 1, Alignment::Right),
            TableCell::new_with_alignment(format!("{}",&gateway.mac_addr), 1, Alignment::Left),
        ]));
    };
    println!("{}", table.render());
}

pub fn show_interfaces_table(interfaces: &Vec<Interface>) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.has_top_boarder = false;
    table.has_bottom_boarder = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Intefaces]");
    for iface in interfaces {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(&iface.index, 1, Alignment::Left),
            TableCell::new_with_alignment("Name", 1, Alignment::Left),
            TableCell::new_with_alignment(&iface.name, 1, Alignment::Left),
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("MAC", 1, Alignment::Left),
            TableCell::new_with_alignment(&iface.mac_addr.unwrap_or(MacAddr::zero()), 1, Alignment::Left),
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("IPv4", 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}",&iface.ipv4), 1, Alignment::Left),
        ]));
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("", 1, Alignment::Left),
            TableCell::new_with_alignment("IPv6", 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}",&iface.ipv6), 1, Alignment::Left),
        ]));
        if let Some(gateway) = &iface.gateway {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("", 1, Alignment::Left),
                TableCell::new_with_alignment("Gateway", 1, Alignment::Left),
                TableCell::new_with_alignment("", 1, Alignment::Left),
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("", 1, Alignment::Right),
                TableCell::new_with_alignment("IPv4", 1, Alignment::Right),
                TableCell::new_with_alignment(format!("{:?}",&gateway.ipv4), 1, Alignment::Left),
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("", 1, Alignment::Right),
                TableCell::new_with_alignment("IPv6", 1, Alignment::Right),
                TableCell::new_with_alignment(format!("{:?}",&gateway.ipv6), 1, Alignment::Left),
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("", 1, Alignment::Right),
                TableCell::new_with_alignment("MAC", 1, Alignment::Right),
                TableCell::new_with_alignment(format!("{}",&gateway.mac_addr), 1, Alignment::Left),
            ]));
        };
    }
    println!("{}", table.render());
}
