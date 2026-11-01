use crate::output::{ScanResult, tree_label};
use termtree::Tree;

/// Print the scan report results in a tree structure.
pub fn print_report_tree(result: &ScanResult) {
    let mut root = Tree::new(tree_label("Scan report(s)"));

    // Create a tree for each endpoint
    for ep in &result.endpoints {
        // Endpoint title
        let title = if let Some(hn) = &ep.hostname {
            format!("{} ({})", ep.ip, hn)
        } else {
            ep.ip.to_string()
        };
        let mut ep_root = Tree::new(title);

        // Link-layer info
        if ep.mac_addr.is_some() && !nex::net::ip::is_global_ip(&ep.ip) {
            let mut mac_node = Tree::new(tree_label("link"));
            if let Some(mac) = ep.mac_addr {
                mac_node.push(Tree::new(tree_label(format!("mac: {}", mac))));
            }
            if let Some(vendor) = &ep.vendor_name {
                mac_node.push(Tree::new(tree_label(format!("vendor: {}", vendor))));
            }
            ep_root.push(mac_node);
        }

        if let Some(ttl) = ep.os.ttl_observed {
            ep_root.push(Tree::new(format!("observed TTL: {ttl}")));
        }

        // Port information
        if !ep.ports.is_empty() {
            for (port, pr) in &ep.ports {
                let mut pnode = Tree::new(tree_label(format!(
                    "{}/{}",
                    port.number,
                    port.transport.as_str().to_uppercase()
                )));
                pnode.push(Tree::new(tree_label(format!("state: {:?}", pr.state))));
                if let Some(name) = &pr.service.name {
                    pnode.push(Tree::new(tree_label(format!("service: {}", name))));
                }
                if let Some(banner) = &pr.service.banner {
                    pnode.push(Tree::new(tree_label(format!("banner: {}", banner))));
                }
                if let Some(prod) = &pr.service.product {
                    pnode.push(Tree::new(tree_label(format!("product: {}", prod))));
                }
                if !pr.service.cpes.is_empty() {
                    let mut c = Tree::new(tree_label("cpes"));
                    for cp in &pr.service.cpes {
                        c.push(Tree::new(cp.clone()));
                    }
                    pnode.push(c);
                }
                ep_root.push(pnode);
            }
        }
        root.push(ep_root);
    }
    println!("{}", crate::output::terminal_text(&root.to_string()));
}
