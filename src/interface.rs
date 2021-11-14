use std::net::IpAddr;

#[allow(dead_code)]
pub fn get_interface_index_by_name(if_name: String) -> Option<u32> {
    for iface in pnet_datalink::interfaces() {
        if iface.name == if_name {
            return Some(iface.index)
        }
    }
    return None;
}

pub fn get_interface_index_by_ip(ip_addr: IpAddr) -> Option<u32> {
    for iface in pnet_datalink::interfaces() {
        for ip in iface.ips {
            if ip.ip() == ip_addr {
                return Some(iface.index);
            }
        }   
    }
    return None;
}
