use std::net::IpAddr;
use xenet::net::interface::Interface;

pub(crate) fn get_interface_by_ip(ip_addr: IpAddr) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        for ip in iface.ipv4.clone() {
            if ip.addr == ip_addr {
                return Some(iface);
            }
        }
        for ip in iface.ipv6.clone() {
            if ip.addr == ip_addr {
                return Some(iface);
            }
        }
    }
    return None;
}

pub(crate) fn get_interface_by_name(name: String) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        if iface.name == name {
            return Some(iface);
        }
    }
    return None;
}
