use super::route::Route;
use crate::endpoint::PortState;
use anyhow::{Result, bail};
use bytes::Bytes;
use netdev::MacAddr;
use nex::packet::{
    arp::{ArpHardwareType, ArpOperation},
    builder::{
        arp::ArpPacketBuilder, ethernet::EthernetPacketBuilder, icmp::IcmpPacketBuilder,
        icmpv6::Icmpv6PacketBuilder, ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
        tcp::TcpPacketBuilder, udp::UdpPacketBuilder,
    },
    ethernet::EtherType,
    frame::Frame,
    icmp::IcmpType,
    icmpv6::{Icmpv6Code, Icmpv6Packet, Icmpv6Type},
    ip::IpNextProtocol,
    ipv4::Ipv4Flags,
    packet::Packet,
    tcp::TcpFlags,
};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Icmp,
    Tcp,
    Udp,
}

#[derive(Clone)]
pub(crate) struct Probe {
    pub route: std::sync::Arc<Route>,
    pub kind: Kind,
    pub port: u16,
    pub local_port: u16,
    pub nonce: u128,
    pub hop_limit: u8,
}

impl Probe {
    pub fn packet(&self, destination_mac: MacAddr) -> Result<Vec<u8>> {
        let (source, destination) = (self.route.source, self.route.destination);
        let (protocol, payload) = match self.kind {
            Kind::Tcp => (
                IpNextProtocol::Tcp,
                TcpPacketBuilder::new(source, destination)
                    .source(self.local_port)
                    .destination(self.port)
                    .sequence(self.nonce as u32)
                    .flags(TcpFlags::SYN)
                    .window(65535)
                    .build()?
                    .to_bytes(),
            ),
            Kind::Udp => (IpNextProtocol::Udp, self.udp_packet()?),
            Kind::Icmp => match (source, destination) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => (
                    IpNextProtocol::Icmp,
                    IcmpPacketBuilder::new(src, dst)
                        .icmp_type(IcmpType::EchoRequest)
                        .payload(Bytes::copy_from_slice(&self.nonce.to_be_bytes()))
                        .echo_fields((self.nonce >> 16) as u16, self.nonce as u16)
                        .build()?
                        .to_bytes(),
                ),
                (IpAddr::V6(src), IpAddr::V6(dst)) => (
                    IpNextProtocol::Icmpv6,
                    Icmpv6PacketBuilder::new(src, dst)
                        .icmpv6_type(Icmpv6Type::EchoRequest)
                        .payload(Bytes::copy_from_slice(&self.nonce.to_be_bytes()))
                        .echo_fields((self.nonce >> 16) as u16, self.nonce as u16)
                        .build()?
                        .to_bytes(),
                ),
                _ => bail!("probe IP family mismatch"),
            },
        };
        let ip = match (source, destination) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
                .source(src)
                .destination(dst)
                .protocol(protocol)
                .ttl(self.hop_limit)
                .identification((self.nonce >> 32) as u16)
                .flags(Ipv4Flags::DontFragment)
                .payload(payload)
                .build()?
                .to_bytes(),
            (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
                .source(src)
                .destination(dst)
                .next_header(protocol)
                .hop_limit(self.hop_limit)
                .flow_label(((self.nonce >> 32) as u32) & 0xfffff)
                .payload(payload)
                .build()?
                .to_bytes(),
            _ => bail!("probe IP family mismatch"),
        };
        Ok(ethernet(
            self.route.interface.mac_addr.unwrap(),
            destination_mac,
            if destination.is_ipv4() {
                EtherType::Ipv4
            } else {
                EtherType::Ipv6
            },
            ip,
        ))
    }

    fn udp_packet(&self) -> Result<Bytes> {
        Ok(
            UdpPacketBuilder::new(self.route.source, self.route.destination)
                .source(self.local_port)
                .destination(self.port)
                .payload(Bytes::copy_from_slice(&self.nonce.to_be_bytes()))
                .build()?
                .to_bytes(),
        )
    }

    pub fn matches(&self, frame: &Frame) -> Option<PortState> {
        let (source, destination, _) = addresses(frame)?;
        if source != self.route.destination || destination != self.route.source {
            return None;
        }
        let ethernet = frame.datalink.as_ref()?.ethernet.as_ref()?;
        if Some(ethernet.destination) != self.route.interface.mac_addr {
            return None;
        }
        match self.kind {
            Kind::Tcp => {
                let tcp = frame.transport.as_ref()?.tcp.as_ref()?;
                if tcp.source != self.port
                    || tcp.destination != self.local_port
                    || tcp.acknowledgement != (self.nonce as u32).wrapping_add(1)
                    || tcp.flags & TcpFlags::ACK == 0
                {
                    return None;
                }
                if tcp.flags & TcpFlags::RST != 0 {
                    Some(PortState::Closed)
                } else if tcp.flags & TcpFlags::SYN != 0 {
                    Some(PortState::Open)
                } else {
                    None
                }
            }
            Kind::Icmp => {
                let ip = frame.ip.as_ref()?;
                let echo = ip
                    .icmp
                    .as_ref()
                    .is_some_and(|h| h.icmp_type == IcmpType::EchoReply && h.icmp_code.0 == 0)
                    || ip.icmpv6.as_ref().is_some_and(|h| {
                        h.icmpv6_type == Icmpv6Type::EchoReply && h.icmpv6_code.0 == 0
                    });
                let mut expected = Vec::from(((self.nonce >> 16) as u16).to_be_bytes());
                expected.extend_from_slice(&(self.nonce as u16).to_be_bytes());
                expected.extend_from_slice(&self.nonce.to_be_bytes());
                (echo && frame.payload.as_ref() == expected).then_some(PortState::Open)
            }
            Kind::Udp => {
                if let Some(udp) = frame.transport.as_ref().and_then(|t| t.udp.as_ref()) {
                    return (udp.source == self.port && udp.destination == self.local_port)
                        .then_some(PortState::Open);
                }
                let (quoted, offset) = udp_quote(frame)?;
                let expected = self.udp_packet().ok()?;
                let ip_matches = match self.route.source {
                    IpAddr::V4(src) => {
                        quoted.first()? >> 4 == 4
                            && quoted[12..16] == src.octets()
                            && quoted[4..6] == ((self.nonce >> 32) as u16).to_be_bytes()
                    }
                    IpAddr::V6(src) => {
                        quoted.first()? >> 4 == 6
                            && quoted[8..24] == src.octets()
                            && u32::from_be_bytes(quoted[..4].try_into().ok()?) & 0xfffff
                                == ((self.nonce >> 32) as u32) & 0xfffff
                    }
                };
                (ip_matches && quoted.get(offset..offset + 8)? == &expected[..8])
                    .then_some(PortState::Closed)
            }
        }
    }
}

pub(crate) fn addresses(frame: &Frame) -> Option<(IpAddr, IpAddr, u8)> {
    let ip = frame.ip.as_ref()?;
    if let Some(v4) = &ip.ipv4 {
        if v4.fragment_offset != 0 || v4.flags & Ipv4Flags::MoreFragments != 0 {
            return None;
        }
        Some((v4.source.into(), v4.destination.into(), v4.ttl))
    } else {
        let v6 = ip.ipv6.as_ref()?;
        Some((v6.source.into(), v6.destination.into(), v6.hop_limit))
    }
}

/// Identify the pending probe without iterating over all active requests.
pub(crate) fn response_key(frame: &Frame, kind: Kind) -> Option<(IpAddr, u16)> {
    let (source, _, _) = addresses(frame)?;
    let port = match kind {
        Kind::Icmp => 0,
        Kind::Tcp => frame.transport.as_ref()?.tcp.as_ref()?.source,
        Kind::Udp => {
            if let Some(udp) = frame.transport.as_ref().and_then(|t| t.udp.as_ref()) {
                udp.source
            } else {
                let (quoted, offset) = udp_quote(frame)?;
                u16::from_be_bytes(quoted.get(offset + 2..offset + 4)?.try_into().ok()?)
            }
        }
    };
    Some((source, port))
}

fn udp_quote(frame: &Frame) -> Option<(&[u8], usize)> {
    let ip = frame.ip.as_ref()?;
    let unreachable = ip
        .icmp
        .as_ref()
        .is_some_and(|h| h.icmp_type == IcmpType::DestinationUnreachable && h.icmp_code.0 == 3)
        || ip.icmpv6.as_ref().is_some_and(|h| {
            h.icmpv6_type == Icmpv6Type::DestinationUnreachable && h.icmpv6_code.0 == 4
        });
    if !unreachable {
        return None;
    }
    let q = frame.payload.get(4..)?;
    let offset = match q.first()? >> 4 {
        4 if q.len() >= 28 => {
            let outer = ip.ipv4.as_ref()?;
            let offset = usize::from(q[0] & 15) * 4;
            if offset < 20
                || q[9] != 17
                || u16::from_be_bytes([q[6], q[7]]) & 0x3fff != 0
                || q[12..16] != outer.destination.octets()
                || q[16..20] != outer.source.octets()
            {
                return None;
            }
            offset
        }
        6 if q.len() >= 48 => {
            let outer = ip.ipv6.as_ref()?;
            if q[6] != 17
                || q[8..24] != outer.destination.octets()
                || q[24..40] != outer.source.octets()
            {
                return None;
            }
            40
        }
        _ => return None,
    };
    q.get(offset..offset + 8)?;
    Some((q, offset))
}

pub(crate) fn unicast_mac(mac: MacAddr) -> bool {
    mac != MacAddr::zero() && mac.octets()[0] & 1 == 0
}

fn ethernet(
    source: MacAddr,
    destination: MacAddr,
    ether_type: EtherType,
    payload: Bytes,
) -> Vec<u8> {
    EthernetPacketBuilder::new()
        .source(source)
        .destination(destination)
        .ethertype(ether_type)
        .payload(payload)
        .build()
        .to_bytes()
        .to_vec()
}

pub(crate) fn neighbor_request(route: &Route) -> Result<Vec<u8>> {
    let mac = route.interface.mac_addr.unwrap();
    match (route.source, route.next_hop) {
        (IpAddr::V4(source), IpAddr::V4(target)) => Ok(ethernet(
            mac,
            MacAddr::broadcast(),
            EtherType::Arp,
            ArpPacketBuilder::new(mac, source, target)
                .operation(ArpOperation::Request)
                .build()?
                .to_bytes(),
        )),
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let octets = target.octets();
            let group = Ipv6Addr::new(
                0xff02,
                0,
                0,
                0,
                0,
                1,
                0xff00 | u16::from(octets[13]),
                u16::from_be_bytes([octets[14], octets[15]]),
            );
            let group_mac = MacAddr::new(0x33, 0x33, 0xff, octets[13], octets[14], octets[15]);
            let mut payload = vec![0; 4];
            payload.extend_from_slice(&octets);
            payload.extend_from_slice(&[1, 1]);
            payload.extend_from_slice(&mac.octets());
            // The checksum uses the solicited-node multicast destination, not the target.
            let icmp = Icmpv6PacketBuilder::new(source, group)
                .icmpv6_type(Icmpv6Type::NeighborSolicitation)
                .icmpv6_code(Icmpv6Code(0))
                .payload(payload.into())
                .build()?;
            let ip = Ipv6PacketBuilder::new()
                .source(source)
                .destination(group)
                .next_header(IpNextProtocol::Icmpv6)
                .hop_limit(255)
                .payload(icmp.to_bytes())
                .build()?;
            Ok(ethernet(mac, group_mac, EtherType::Ipv6, ip.to_bytes()))
        }
        _ => bail!("neighbor IP family mismatch"),
    }
}

pub(crate) fn neighbor_key(frame: &Frame) -> Option<IpAddr> {
    if let Some(arp) = frame.datalink.as_ref().and_then(|d| d.arp.as_ref()) {
        return Some(arp.sender_proto_addr.into());
    }
    let ip = frame.ip.as_ref()?;
    if ip.icmpv6.as_ref()?.icmpv6_type != Icmpv6Type::NeighborAdvertisement {
        return None;
    }
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(frame.payload.get(4..20)?).ok()?).into())
}

pub(crate) fn neighbor_reply(frame: &Frame, route: &Route) -> Option<MacAddr> {
    let eth = frame.datalink.as_ref()?.ethernet.as_ref()?;
    let local = route.interface.mac_addr?;
    if eth.destination != local {
        return None;
    }
    match (route.source, route.next_hop) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            let arp = frame.datalink.as_ref()?.arp.as_ref()?;
            (arp.operation == ArpOperation::Reply
                && arp.hardware_type == ArpHardwareType::Ethernet
                && arp.protocol_type == EtherType::Ipv4
                && arp.hw_addr_len == 6
                && arp.proto_addr_len == 4
                && arp.sender_proto_addr == target
                && arp.target_proto_addr == source
                && arp.target_hw_addr == local
                && arp.sender_hw_addr == eth.source
                && unicast_mac(arp.sender_hw_addr))
            .then_some(arp.sender_hw_addr)
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let ip = frame.ip.as_ref()?;
            let v6 = ip.ipv6.as_ref()?;
            let header = ip.icmpv6.as_ref()?;
            if v6.destination != source
                || v6.hop_limit != 255
                || header.icmpv6_type != Icmpv6Type::NeighborAdvertisement
                || header.icmpv6_code.0 != 0
                || frame.payload.get(4..20)? != target.octets()
                || frame.payload.first()? & 0x40 == 0
            {
                return None;
            }
            let packet = Icmpv6Packet {
                header: header.clone(),
                payload: frame.payload.clone(),
            };
            if nex::packet::icmpv6::checksum(&packet, &v6.source, &v6.destination)
                != header.checksum
            {
                return None;
            }
            let mut options = frame.payload.get(20..)?;
            let mut result = None;
            while !options.is_empty() {
                let size = usize::from(*options.get(1)?) * 8;
                if size == 0 || options.len() < size {
                    return None;
                }
                if options[0] == 2 {
                    if size != 8 || result.is_some() {
                        return None;
                    }
                    let mac = MacAddr::new(
                        options[2], options[3], options[4], options[5], options[6], options[7],
                    );
                    if !unicast_mac(mac) || mac != eth.source {
                        return None;
                    }
                    result = Some(mac);
                }
                options = &options[size..];
            }
            result
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nex::packet::{frame::ParseOption, icmp::IcmpCode};
    use std::sync::Arc;

    pub(crate) fn route(v6: bool) -> Arc<Route> {
        let mut interface = netdev::Interface::dummy();
        interface.index = 7;
        interface.mac_addr = Some(MacAddr::new(2, 0, 0, 0, 0, 1));
        let (source, target) = if v6 {
            ("fd00::1", "fd00::2")
        } else {
            ("192.0.2.1", "192.0.2.2")
        };
        Arc::new(Route {
            interface,
            source: source.parse().unwrap(),
            destination: target.parse().unwrap(),
            next_hop: target.parse().unwrap(),
        })
    }

    pub(crate) fn probe(v6: bool, kind: Kind) -> Probe {
        Probe {
            route: route(v6),
            kind,
            port: if kind == Kind::Icmp { 0 } else { 443 },
            local_port: 54321,
            nonce: 0x112233445566778899aabbccddeeff00,
            hop_limit: 64,
        }
    }

    fn incoming(route: &Route, protocol: IpNextProtocol, payload: Bytes) -> Frame {
        let ip = match (route.destination, route.source) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => Ipv4PacketBuilder::new()
                .source(source)
                .destination(destination)
                .protocol(protocol)
                .payload(payload)
                .build()
                .unwrap()
                .to_bytes(),
            (IpAddr::V6(source), IpAddr::V6(destination)) => Ipv6PacketBuilder::new()
                .source(source)
                .destination(destination)
                .next_header(protocol)
                .hop_limit(255)
                .payload(payload)
                .build()
                .unwrap()
                .to_bytes(),
            _ => unreachable!(),
        };
        let bytes = ethernet(
            MacAddr::new(2, 0, 0, 0, 0, 2),
            route.interface.mac_addr.unwrap(),
            if route.source.is_ipv4() {
                EtherType::Ipv4
            } else {
                EtherType::Ipv6
            },
            ip,
        );
        Frame::from_buf(&bytes, ParseOption::default()).unwrap()
    }

    pub(crate) fn reply(probe: &Probe) -> Frame {
        let route = &probe.route;
        let (protocol, bytes) = match probe.kind {
            Kind::Tcp => (
                IpNextProtocol::Tcp,
                TcpPacketBuilder::new(route.destination, route.source)
                    .source(probe.port)
                    .destination(probe.local_port)
                    .acknowledgement((probe.nonce as u32).wrapping_add(1))
                    .flags(TcpFlags::SYN | TcpFlags::ACK)
                    .build()
                    .unwrap()
                    .to_bytes(),
            ),
            kind => {
                let echo = kind == Kind::Icmp;
                let payload = if echo {
                    Bytes::copy_from_slice(&probe.nonce.to_be_bytes())
                } else {
                    // An ICMPv4 error is allowed to quote only the original IP and UDP headers.
                    let outgoing = probe.packet(MacAddr::new(2, 0, 0, 0, 0, 2)).unwrap();
                    Bytes::copy_from_slice(
                        &outgoing[14..14 + if route.source.is_ipv4() { 28 } else { 48 }],
                    )
                };
                match (route.destination, route.source) {
                    (IpAddr::V4(source), IpAddr::V4(destination)) => (
                        IpNextProtocol::Icmp,
                        IcmpPacketBuilder::new(source, destination)
                            .icmp_type(if echo {
                                IcmpType::EchoReply
                            } else {
                                IcmpType::DestinationUnreachable
                            })
                            .icmp_code(IcmpCode(if echo { 0 } else { 3 }))
                            .payload(payload)
                            .echo_fields(
                                if echo { (probe.nonce >> 16) as u16 } else { 0 },
                                if echo { probe.nonce as u16 } else { 0 },
                            )
                            .build()
                            .unwrap()
                            .to_bytes(),
                    ),
                    (IpAddr::V6(source), IpAddr::V6(destination)) => (
                        IpNextProtocol::Icmpv6,
                        Icmpv6PacketBuilder::new(source, destination)
                            .icmpv6_type(if echo {
                                Icmpv6Type::EchoReply
                            } else {
                                Icmpv6Type::DestinationUnreachable
                            })
                            .icmpv6_code(Icmpv6Code(if echo { 0 } else { 4 }))
                            .payload(payload)
                            .echo_fields(
                                if echo { (probe.nonce >> 16) as u16 } else { 0 },
                                if echo { probe.nonce as u16 } else { 0 },
                            )
                            .build()
                            .unwrap()
                            .to_bytes(),
                    ),
                    _ => unreachable!(),
                }
            }
        };
        incoming(route, protocol, bytes)
    }

    #[test]
    fn probes_match_both_ip_families_and_reject_other_sessions() {
        for v6 in [false, true] {
            for kind in [Kind::Icmp, Kind::Tcp, Kind::Udp] {
                let probe = probe(v6, kind);
                let frame = reply(&probe);
                assert!(probe.matches(&frame).is_some(), "{kind:?} {v6}");
                assert_eq!(
                    response_key(&frame, kind),
                    Some((probe.route.destination, probe.port))
                );
                let mut other = probe.clone();
                other.nonce += 1;
                assert!(other.matches(&frame).is_none(), "{kind:?} {v6}");
                if kind != Kind::Icmp {
                    other = probe.clone();
                    other.local_port += 1;
                    assert!(other.matches(&frame).is_none());
                    other = probe.clone();
                    other.port += 1;
                    assert!(other.matches(&frame).is_none());
                }
                let mut wrong_address = frame.clone();
                if let Some(v4) = wrong_address.ip.as_mut().unwrap().ipv4.as_mut() {
                    v4.destination = "192.0.2.99".parse().unwrap();
                }
                if let Some(v6) = wrong_address.ip.as_mut().unwrap().ipv6.as_mut() {
                    v6.destination = "fd00::99".parse().unwrap();
                }
                assert!(probe.matches(&wrong_address).is_none());
                if kind == Kind::Udp {
                    for len in 0..frame.payload.len() {
                        let mut truncated = frame.clone();
                        truncated.payload.truncate(len);
                        assert!(probe.matches(&truncated).is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn arp_requests_and_replies_use_the_next_hop() {
        let mut route = (*route(false)).clone();
        route.destination = "198.51.100.5".parse().unwrap();
        let request =
            Frame::from_buf(&neighbor_request(&route).unwrap(), ParseOption::default()).unwrap();
        let arp = request.datalink.as_ref().unwrap().arp.as_ref().unwrap();
        assert_eq!(IpAddr::V4(arp.target_proto_addr), route.next_hop);
        assert_eq!(
            request
                .datalink
                .as_ref()
                .unwrap()
                .ethernet
                .as_ref()
                .unwrap()
                .destination,
            MacAddr::broadcast()
        );
        let mut response = request;
        let dl = response.datalink.as_mut().unwrap();
        let arp = dl.arp.as_mut().unwrap();
        std::mem::swap(&mut arp.target_proto_addr, &mut arp.sender_proto_addr);
        arp.operation = ArpOperation::Reply;
        arp.target_hw_addr = route.interface.mac_addr.unwrap();
        arp.sender_hw_addr = MacAddr::new(2, 0, 0, 0, 0, 2);
        dl.ethernet.as_mut().unwrap().source = arp.sender_hw_addr;
        dl.ethernet.as_mut().unwrap().destination = arp.target_hw_addr;
        assert_eq!(
            neighbor_reply(&response, &route),
            Some(MacAddr::new(2, 0, 0, 0, 0, 2))
        );
        response
            .datalink
            .as_mut()
            .unwrap()
            .arp
            .as_mut()
            .unwrap()
            .sender_proto_addr = "192.0.2.99".parse().unwrap();
        assert!(neighbor_reply(&response, &route).is_none());
    }

    #[test]
    fn ndp_multicast_checksum_and_advertisement_validation() {
        let route = route(true);
        let request =
            Frame::from_buf(&neighbor_request(&route).unwrap(), ParseOption::default()).unwrap();
        let layer = request.ip.as_ref().unwrap();
        let ip = layer.ipv6.as_ref().unwrap();
        assert_eq!(
            ip.destination,
            "ff02::1:ff00:2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ip.hop_limit, 255);
        let header = layer.icmpv6.as_ref().unwrap();
        let packet = Icmpv6Packet {
            header: header.clone(),
            payload: request.payload.clone(),
        };
        assert_eq!(
            header.checksum,
            nex::packet::icmpv6::checksum(&packet, &ip.source, &ip.destination)
        );
        assert_eq!(
            &request.payload[4..20],
            &"fd00::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        let mut payload = vec![0x60, 0, 0, 0];
        payload.extend_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        payload.extend_from_slice(&[2, 1, 2, 0, 0, 0, 0, 2]);
        let bytes =
            Icmpv6PacketBuilder::new("fd00::2".parse().unwrap(), "fd00::1".parse().unwrap())
                .icmpv6_type(Icmpv6Type::NeighborAdvertisement)
                .payload(payload.into())
                .build()
                .unwrap()
                .to_bytes();
        let response = incoming(&route, IpNextProtocol::Icmpv6, bytes);
        assert_eq!(
            neighbor_reply(&response, &route),
            Some(MacAddr::new(2, 0, 0, 0, 0, 2))
        );
        for len in 0..response.payload.len() {
            let mut truncated = response.clone();
            truncated.payload.truncate(len);
            assert!(neighbor_reply(&truncated, &route).is_none());
        }
        let mut wrong = response.clone();
        wrong.ip.as_mut().unwrap().ipv6.as_mut().unwrap().hop_limit = 64;
        assert!(neighbor_reply(&wrong, &route).is_none());
        let mut wrong = response;
        wrong.ip.as_mut().unwrap().icmpv6.as_mut().unwrap().checksum ^= 1;
        assert!(neighbor_reply(&wrong, &route).is_none());
    }
}
