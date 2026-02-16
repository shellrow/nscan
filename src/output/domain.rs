use termtree::Tree;
use std::net::IpAddr;
use crate::{dns::{Domain, DomainScanResult}, output::tree_label};

/// Print the domain scan results in a tree structure.
pub fn print_domain_tree(base_domain: &Domain, res: &DomainScanResult) {
    // Create the root of the tree
    let mut root = Tree::new(format!(
        "Subdomains of {} - found: {} (elapsed: {:?})",
        base_domain.name,
        res.domains.len(),
        res.scan_time
    ));

    // base domain node
    let mut base_node = Tree::new(tree_label(&base_domain.name));

    if !base_domain.ips.is_empty() {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in &base_domain.ips {
            match ip {
                IpAddr::V4(x) => v4.push(x),
                IpAddr::V6(x) => v6.push(x),
            }
        }
        if !v4.is_empty() {
            let mut a = Tree::new(tree_label("A"));
            for ip in v4 {
                a.push(Tree::new(ip.to_string()));
            }
            base_node.push(a);
        }
        if !v6.is_empty() {
            let mut aaaa = Tree::new(tree_label("AAAA"));
            for ip in v6 {
                aaaa.push(Tree::new(ip.to_string()));
            }
            base_node.push(aaaa);
        }
    }

    // Add subdomains under the base domain
    let mut doms = res.domains.clone();
    doms.sort_by(|a, b| a.name.cmp(&b.name));

    for d in doms {
        let mut node = Tree::new(d.name);

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in d.ips {
            match ip {
                IpAddr::V4(x) => v4.push(x),
                IpAddr::V6(x) => v6.push(x),
            }
        }

        if !v4.is_empty() {
            let mut a = Tree::new(tree_label("A"));
            for ip in v4 {
                a.push(Tree::new(ip.to_string()));
            }
            node.push(a);
        }
        if !v6.is_empty() {
            let mut aaaa = Tree::new(tree_label("AAAA"));
            for ip in v6 {
                aaaa.push(Tree::new(ip.to_string()));
            }
            node.push(aaaa);
        }

        base_node.push(node);
    }
    
    root.push(base_node);

    println!("Scan report(s)");
    println!("{}", root);
}
