use std::path::PathBuf;

use crate::output;
use crate::util::tree::node_label;
use clap::ArgMatches;
use netdev::mac::MacAddr;
use netdev::Interface;
use termtree::Tree;

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
    } else {
        show_interface_tree(&iface);
    }
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&iface).unwrap()) {
                Ok(_) => {
                    output::log_with_time(
                        &format!("Saved to {}", file_path.to_string_lossy()),
                        "INFO",
                    );
                }
                Err(e) => {
                    output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                }
            }
        }
        None => {}
    }
}

pub fn show_interfaces(args: &ArgMatches) {
    let interfaces: Vec<Interface> = netdev::get_interfaces();
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&interfaces).unwrap();
        println!("{}", json_result);
    } else {
        show_interfaces_tree(&interfaces);
    }
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(
                file_path,
                serde_json::to_string_pretty(&interfaces).unwrap(),
            ) {
                Ok(_) => {
                    output::log_with_time(
                        &format!("Saved to {}", file_path.to_string_lossy()),
                        "INFO",
                    );
                }
                Err(e) => {
                    output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                }
            }
        }
        None => {}
    }
}

pub fn show_interface_tree(iface: &Interface) {
    let mut tree = Tree::new(node_label("Interface", None, None));
    tree.push(node_label("Index", Some(&iface.index.to_string()), None));
    tree.push(node_label("Name", Some(&iface.name), None));
    if let Some(friendly_name) = &iface.friendly_name {
        tree.push(node_label("Friendly Name", Some(friendly_name), None));
    }
    if let Some(desc) = &iface.description {
        tree.push(node_label("Description", Some(desc), None));
    }
    tree.push(node_label("Type", Some(&iface.if_type.name()), None));
    tree.push(node_label(
        "MAC",
        Some(&iface.mac_addr.unwrap_or(MacAddr::zero()).to_string()),
        None,
    ));
    let mut ipv4_tree = Tree::new(node_label("IPv4 Addresses", None, None));
    for ipv4 in &iface.ipv4 {
        ipv4_tree.push(node_label(&ipv4.addr.to_string(), None, None));
    }
    tree.push(ipv4_tree);

    let mut ipv6_tree = Tree::new(node_label("IPv6 Addresses", None, None));
    for ipv6 in &iface.ipv6 {
        ipv6_tree.push(node_label(&ipv6.addr.to_string(), None, None));
    }
    tree.push(ipv6_tree);

    if let Some(gateway) = &iface.gateway {
        let mut gateway_tree = Tree::new(node_label("Gateway", None, None));
        gateway_tree.push(node_label("MAC", Some(&gateway.mac_addr.to_string()), None));
        let mut ipv4_tree = Tree::new(node_label("IPv4 Addresses", None, None));
        for ipv4 in &gateway.ipv4 {
            ipv4_tree.push(node_label(&ipv4.to_string(), None, None));
        }
        gateway_tree.push(ipv4_tree);
        let mut ipv6_tree = Tree::new(node_label("IPv6 Addresses", None, None));
        for ipv6 in &gateway.ipv6 {
            ipv6_tree.push(node_label(&ipv6.to_string(), None, None));
        }
        gateway_tree.push(ipv6_tree);
        tree.push(gateway_tree);
    }
    if iface.dns_servers.len() > 0 {
        let mut dns_tree = Tree::new(node_label("DNS Servers", None, None));
        for server_addr in &iface.dns_servers {
            dns_tree.push(node_label(&server_addr.to_string(), None, None));
        }
        tree.push(dns_tree);
    }

    println!("{}", tree);
}

pub fn show_interfaces_tree(interfaces: &Vec<Interface>) {
    let mut tree = Tree::new(node_label("Interfaces", None, None));
    for iface in interfaces {
        let mut iface_tree = Tree::new(node_label(&iface.name, None, None));
        iface_tree.push(node_label("Index", Some(&iface.index.to_string()), None));
        iface_tree.push(node_label("Name", Some(&iface.name), None));
        if let Some(friendly_name) = &iface.friendly_name {
            iface_tree.push(node_label("Friendly Name", Some(friendly_name), None));
        }
        if let Some(desc) = &iface.description {
            iface_tree.push(node_label("Description", Some(desc), None));
        }
        iface_tree.push(node_label("Type", Some(&iface.if_type.name()), None));
        iface_tree.push(node_label(
            "MAC",
            Some(&iface.mac_addr.unwrap_or(MacAddr::zero()).to_string()),
            None,
        ));
        let mut ipv4_tree = Tree::new(node_label("IPv4 Addresses", None, None));
        for ipv4 in &iface.ipv4 {
            ipv4_tree.push(node_label(&ipv4.addr.to_string(), None, None));
        }
        iface_tree.push(ipv4_tree);

        let mut ipv6_tree = Tree::new(node_label("IPv6 Addresses", None, None));
        for ipv6 in &iface.ipv6 {
            ipv6_tree.push(node_label(&ipv6.addr.to_string(), None, None));
        }
        iface_tree.push(ipv6_tree);

        if let Some(gateway) = &iface.gateway {
            let mut gateway_tree = Tree::new(node_label("Gateway", None, None));
            gateway_tree.push(node_label("MAC", Some(&gateway.mac_addr.to_string()), None));
            let mut ipv4_tree = Tree::new(node_label("IPv4 Addresses", None, None));
            for ipv4 in &gateway.ipv4 {
                ipv4_tree.push(node_label(&ipv4.to_string(), None, None));
            }
            gateway_tree.push(ipv4_tree);
            let mut ipv6_tree = Tree::new(node_label("IPv6 Addresses", None, None));
            for ipv6 in &gateway.ipv6 {
                ipv6_tree.push(node_label(&ipv6.to_string(), None, None));
            }
            gateway_tree.push(ipv6_tree);
            iface_tree.push(gateway_tree);
        }

        if iface.dns_servers.len() > 0 {
            let mut dns_tree = Tree::new(node_label("DNS Servers", None, None));
            for server_addr in &iface.dns_servers {
                dns_tree.push(node_label(&server_addr.to_string(), None, None));
            }
            iface_tree.push(dns_tree);
        }
        tree.push(iface_tree);
    }
    println!("{}", tree);
}
