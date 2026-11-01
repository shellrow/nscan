use anyhow::{Context, Result, ensure};
use netdev::Interface;
use netroute::{RouteEntry, RouteFlag};
use std::net::{IpAddr, SocketAddr, SocketAddrV6, UdpSocket};

#[derive(Clone, Debug)]
pub(crate) struct Route {
    pub interface: Interface,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub next_hop: IpAddr,
}

pub(crate) struct Routes {
    interfaces: Vec<Interface>,
    entries: Vec<RouteEntry>,
}

impl Routes {
    pub fn load() -> Result<Self> {
        let entries = netroute::list_routes().context("read routing table")?;
        #[cfg(target_os = "macos")]
        let entries = entries.into_iter().map(normalize_darwin_route).collect();
        Ok(Self {
            interfaces: netdev::get_interfaces(),
            entries,
        })
    }

    pub fn resolve(&self, destination: IpAddr, interface_index: u32) -> Result<Route> {
        ensure!(
            !destination.is_loopback(),
            "raw scans on loopback are unsupported; use a TCP connect scan"
        );
        ensure!(
            is_unicast(destination),
            "raw probes require a unicast target: {destination}"
        );
        ensure!(
            !self
                .interfaces
                .iter()
                .any(|iface| iface.ip_addrs().contains(&destination)),
            "raw scans of local addresses are unsupported; use a TCP connect scan"
        );
        ensure!(
            !matches!(destination, IpAddr::V6(ip) if ip.is_unicast_link_local())
                || interface_index != 0,
            "link-local IPv6 targets require --interface"
        );
        let entry = select_route(&self.entries, destination, interface_index)?;
        let index = entry
            .ifindex
            .context("route has no usable output interface")?;
        let interface = self
            .interfaces
            .iter()
            .find(|iface| iface.index == index)
            .context("route interface is unavailable")?
            .clone();
        ensure!(
            !interface.is_loopback(),
            "raw scans on loopback are unsupported; use a TCP connect scan"
        );
        ensure!(interface.is_up(), "interface {} is down", interface.name);
        ensure!(
            !interface.is_tun() && interface.mac_addr.is_some_and(super::packet::unicast_mac),
            "raw scans require an Ethernet interface; {} is unsupported",
            interface.name
        );
        ensure!(
            !matches!(destination, IpAddr::V4(ip) if interface.ipv4.iter().any(|net|
                net.prefix_len() < 31 && (ip == net.broadcast() || ip == net.network()))),
            "raw probes require a host address, not a subnet or broadcast address"
        );
        let next_hop = entry
            .gateway
            .filter(|ip| !ip.is_unspecified())
            .unwrap_or(destination);
        ensure!(
            next_hop.is_ipv4() == destination.is_ipv4() && is_unicast(next_hop),
            "invalid route next hop"
        );
        // A connected UDP socket asks the OS to select a source without sending packets.
        // It also detects reject/unreachable routes that table enumeration may omit.
        let kernel_source = kernel_source(destination, index);
        let source = if interface_index == 0 {
            let source = kernel_source.context("OS route/source selection failed")?;
            ensure!(
                interface.ip_addrs().contains(&source),
                "OS policy route differs from the routing-table selection for {destination}; specify --interface"
            );
            ensure!(
                usable_source(&interface, source, destination),
                "OS selected an unusable source address"
            );
            source
        } else if let Ok(source) = kernel_source
            && usable_source(&interface, source, destination)
        {
            source
        } else {
            select_source(&interface, destination)
                .context("interface has no usable source address")?
        };
        Ok(Route {
            interface,
            source,
            destination,
            next_hop,
        })
    }
}

// Darwin embeds the interface index in bytes 2..4 of link-local route
// addresses. The route's ifindex carries the scope; wire addresses must not.
#[cfg(any(target_os = "macos", test))]
fn normalize_darwin_route(mut entry: RouteEntry) -> RouteEntry {
    fn address(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                let mut bytes = ip.octets();
                bytes[2..4].fill(0);
                std::net::Ipv6Addr::from(bytes).into()
            }
            ip => ip,
        }
    }
    entry.destination.addr = address(entry.destination.addr);
    entry.gateway = entry.gateway.map(address);
    entry
}

fn kernel_source(destination: IpAddr, index: u32) -> std::io::Result<IpAddr> {
    let target = match destination {
        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
            ip,
            9,
            0,
            if ip.is_unicast_link_local() { index } else { 0 },
        )),
        IpAddr::V4(ip) => SocketAddr::new(ip.into(), 9),
    };
    let socket = UdpSocket::bind(if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.connect(target)?;
    Ok(socket.local_addr()?.ip())
}

fn select_route(entries: &[RouteEntry], destination: IpAddr, index: u32) -> Result<&RouteEntry> {
    // Refuse ambiguous policy routes even when a main-table route has a longer
    // prefix: rule priority is independent of destination prefix length.
    ensure!(
        !cfg!(target_os = "linux")
            || !entries.iter().any(|entry| {
                entry.table.is_some_and(|table| !matches!(table, 253..=255))
                    && ipnet::IpNet::new(entry.destination.addr, entry.destination.prefix_len)
                        .is_ok_and(|net| net.contains(&destination))
            }),
        "raw scans through policy-routing tables are unsupported"
    );
    let route = entries
        .iter()
        .filter(|entry| {
            (index == 0 || entry.ifindex.is_none() || entry.ifindex == Some(index))
                && ipnet::IpNet::new(entry.destination.addr, entry.destination.prefix_len)
                    .is_ok_and(|net| net.contains(&destination))
        })
        .min_by_key(|entry| {
            (
                std::cmp::Reverse(entry.destination.prefix_len),
                entry.metric.unwrap_or(0),
            )
        })
        .context("no route to target on the selected interface")?;
    ensure!(
        !route.flags.contains(&RouteFlag::Reject),
        "route rejects target {destination}"
    );
    ensure!(
        route.ifindex.is_some(),
        "route to {destination} has no output interface (unreachable or unsupported route)"
    );
    // A routing-table snapshot cannot evaluate Linux policy-routing rules.
    ensure!(
        !cfg!(target_os = "linux") || route.table.is_none_or(|table| matches!(table, 254 | 255)),
        "raw scans through policy-routing tables are unsupported"
    );
    Ok(route)
}

fn is_unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

fn usable_source(iface: &Interface, source: IpAddr, destination: IpAddr) -> bool {
    if source.is_ipv4() != destination.is_ipv4() || !is_unicast(source) {
        return false;
    }
    match source {
        IpAddr::V4(ip) => iface.ipv4.iter().any(|net| net.addr() == ip),
        IpAddr::V6(ip) => iface.ipv6.iter().enumerate().any(|(index, net)| {
            net.addr() == ip
                && ip.is_unicast_link_local()
                    == matches!(destination, IpAddr::V6(dst) if dst.is_unicast_link_local())
                && iface
                    .ipv6_addr_flags
                    .get(index)
                    .is_none_or(|flags| !flags.tentative && !flags.duplicated)
        }),
    }
}

fn select_source(iface: &Interface, destination: IpAddr) -> Option<IpAddr> {
    iface.ip_addrs().into_iter().filter(|source| usable_source(iface, *source, destination))
        .max_by_key(|source| {
            let deprecated = iface.ipv6.iter().position(|net| IpAddr::V6(net.addr()) == *source)
                .and_then(|i| iface.ipv6_addr_flags.get(i)).is_some_and(|flags| flags.deprecated);
            let same_label = matches!((*source, destination), (IpAddr::V6(a), IpAddr::V6(b)) if a.is_unique_local() == b.is_unique_local());
            (!deprecated, same_label, common_prefix(*source, destination))
        })
}

fn common_prefix(a: IpAddr, b: IpAddr) -> u32 {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) ^ u32::from(b)).leading_zeros(),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a) ^ u128::from(b)).leading_zeros(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(network: &str, gateway: Option<&str>, index: u32, metric: u32) -> RouteEntry {
        let net: ipnet::IpNet = network.parse().unwrap();
        RouteEntry {
            family: if net.addr().is_ipv4() {
                netroute::RouteFamily::Ipv4
            } else {
                netroute::RouteFamily::Ipv6
            },
            destination: netroute::RouteDestination::new(net.addr(), net.prefix_len()),
            gateway: gateway.map(|ip| ip.parse().unwrap()),
            on_link: gateway.is_none(),
            ifindex: Some(index),
            ifname: None,
            metric: Some(metric),
            flags: vec![RouteFlag::Up],
            protocol: None,
            scope: None,
            table: Some(254),
            lifetime_ms: None,
        }
    }
    #[test]
    fn longest_prefix_metric_and_explicit_interface() {
        let routes = vec![
            entry("0.0.0.0/0", Some("192.0.2.1"), 1, 10),
            entry("192.0.2.0/24", None, 1, 100),
            entry("198.51.100.0/24", Some("192.0.2.254"), 1, 20),
            entry("198.51.100.0/24", Some("203.0.113.1"), 2, 5),
        ];
        assert!(
            select_route(&routes, "192.0.2.2".parse().unwrap(), 0)
                .unwrap()
                .gateway
                .is_none()
        );
        assert_eq!(
            select_route(&routes, "198.51.100.5".parse().unwrap(), 0)
                .unwrap()
                .ifindex,
            Some(2)
        );
        assert_eq!(
            select_route(&routes, "198.51.100.5".parse().unwrap(), 1)
                .unwrap()
                .gateway,
            Some("192.0.2.254".parse().unwrap())
        );
        assert!(select_route(&routes, "2001:db8::1".parse().unwrap(), 1).is_err());
        let mut rejected = routes;
        rejected[2].flags.push(RouteFlag::Reject);
        assert!(select_route(&rejected, "198.51.100.5".parse().unwrap(), 1).is_err());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn policy_route_is_not_overridden_by_a_longer_main_table_prefix() {
        let mut policy = entry("0.0.0.0/0", Some("192.0.2.254"), 1, 100);
        policy.table = Some(100);
        let entries = vec![entry("192.0.2.0/24", None, 1, 0), policy];
        assert!(select_route(&entries, "192.0.2.2".parse().unwrap(), 0).is_err());
    }

    #[test]
    fn darwin_link_local_routes_keep_scope_out_of_wire_addresses() {
        let direct = normalize_darwin_route(entry("fe80:7::/64", None, 7, 0));
        let gateway = normalize_darwin_route(entry("::/0", Some("fe80:7::1"), 7, 0));
        assert_eq!(gateway.gateway, Some("fe80::1".parse().unwrap()));
        let routes = vec![gateway, direct];
        let selected = select_route(&routes, "fe80::2".parse().unwrap(), 7).unwrap();
        assert_eq!(
            selected.destination.addr,
            "fe80::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(selected.ifindex, Some(7));
        assert!(selected.gateway.is_none());
        assert!(select_route(&routes, "fe80::2".parse().unwrap(), 8).is_err());
        let global = normalize_darwin_route(entry("2001:db8::/32", None, 7, 0));
        assert_eq!(
            global.destination.addr,
            "2001:db8::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn source_scope_prefix_and_address_state() {
        let mut iface = Interface::dummy();
        iface.ipv4 = vec![
            "192.0.2.1/24".parse().unwrap(),
            "198.51.100.1/24".parse().unwrap(),
        ];
        iface.ipv6 = ["fe80::1/64", "2001:db8::1/64", "fd00::1/64"]
            .map(|ip| ip.parse().unwrap())
            .to_vec();
        for (target, expected) in [
            ("198.51.100.2", "198.51.100.1"),
            ("fd00::2", "fd00::1"),
            ("fe80::2", "fe80::1"),
            ("2001:db8::2", "2001:db8::1"),
        ] {
            assert_eq!(
                select_source(&iface, target.parse().unwrap()),
                Some(expected.parse().unwrap())
            );
        }
        iface.ipv6_addr_flags = vec![Default::default(); 3];
        iface.ipv6_addr_flags[0].tentative = true;
        assert!(select_source(&iface, "fe80::2".parse().unwrap()).is_none());
        assert!(select_source(&Interface::dummy(), "192.0.2.2".parse().unwrap()).is_none());
    }
}
