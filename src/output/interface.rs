use termtree::Tree;
use netdev::Interface;

use crate::output::tree_label;

/// Print the network interfaces in a tree structure.
pub fn print_interface_tree(ifaces: &[Interface]) {
    let mut root = Tree::new(tree_label("Interfaces"));
    for iface in ifaces {
        let mut node = Tree::new(format!(
            "{}{}",
            iface.name,
            if iface.default { " (default)" } else { "" }
        ));
        
        node.push(Tree::new(format!("index: {}", iface.index)));

        if let Some(fn_name) = &iface.friendly_name {
            node.push(Tree::new(format!("friendly_name: {}", fn_name)));
        }
        if let Some(desc) = &iface.description {
            node.push(Tree::new(format!("description: {}", desc)));
        }

        node.push(Tree::new(format!("type: {:?}", iface.if_type)));
        node.push(Tree::new(format!("state: {:?}", iface.oper_state)));
        if let Some(mac) = &iface.mac_addr {
            node.push(Tree::new(format!("mac: {}", mac)));
        }
        if let Some(mtu) = iface.mtu {
            node.push(Tree::new(format!("mtu: {}", mtu)));
        }

        if !iface.ipv4.is_empty() {
            let mut ipv4_tree = Tree::new(tree_label("IPv4"));
            for net in &iface.ipv4 {
                ipv4_tree.push(Tree::new(net.to_string()));
            }
            node.push(ipv4_tree);
        }

        if !iface.ipv6.is_empty() {
            let mut ipv6_tree = Tree::new(tree_label("IPv6"));
            for (i, net) in iface.ipv6.iter().enumerate() {
                let mut label = net.to_string();
                if let Some(scope) = iface.ipv6_scope_ids.get(i) {
                    label.push_str(&format!(" (scope_id={})", scope));
                }
                ipv6_tree.push(Tree::new(label));
            }
            node.push(ipv6_tree);
        }

        if !iface.dns_servers.is_empty() {
            let mut dns_tree = Tree::new(tree_label("DNS"));
            for dns in &iface.dns_servers {
                dns_tree.push(Tree::new(dns.to_string()));
            }
            node.push(dns_tree);
        }

        if let Some(gw) = &iface.gateway {
            let mut gw_node = Tree::new(tree_label("Gateway"));
            // GW MAC
            gw_node.push(Tree::new(format!("MAC: {}", gw.mac_addr)));
            // GW IPv4/IPv6
            if !gw.ipv4.is_empty() {
                let mut gw_tree = Tree::new(tree_label("IPv4"));
                for ip in &gw.ipv4 {
                    gw_tree.push(Tree::new(ip.to_string()));
                }
                gw_node.push(gw_tree);
            }
            if !gw.ipv6.is_empty() {
                let mut gw_tree = Tree::new(tree_label("IPv6"));
                for ip in &gw.ipv6 {
                    gw_tree.push(Tree::new(ip.to_string()));
                }
                gw_node.push(gw_tree);
            }
            node.push(gw_node);
        }

        root.push(node);
    }
    println!("{}", root);
}
