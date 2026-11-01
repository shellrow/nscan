//! Routed raw probes with bounded work and request-specific response matching.
mod packet;
mod route;

use crate::{
    endpoint::{EndpointResult, Port, PortResult, PortState, ServiceInfo, TransportProtocol},
    output::ScanResult,
    probe::ProbeSetting,
};
use anyhow::{Context, Result, ensure};
use futures::{
    future::poll_fn,
    stream::{self, StreamExt},
};
use netdev::MacAddr;
use nex::{
    datalink::async_io::{AsyncChannel, AsyncRawSender, async_channel},
    packet::frame::{Frame, ParseOption},
};
pub(crate) use packet::Kind;
use packet::Probe;
use route::{Route, Routes};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, OnceCell, oneshot},
    task::JoinSet,
    time::Instant,
};

type ProbeKey = (u32, IpAddr, u16);
type NeighborKey = (u32, IpAddr);
type ProbeWaiters = Arc<Mutex<HashMap<ProbeKey, (Probe, oneshot::Sender<Frame>)>>>;
type NeighborWaiters = Arc<Mutex<HashMap<NeighborKey, (Arc<Route>, oneshot::Sender<MacAddr>)>>>;

/// Removes registrations on success, error, timeout, or cancellation.
struct Registration<K: Eq + std::hash::Hash, V> {
    key: K,
    map: Arc<Mutex<HashMap<K, V>>>,
}
impl<K: Eq + std::hash::Hash, V> Drop for Registration<K, V> {
    fn drop(&mut self) {
        self.map.lock().unwrap().remove(&self.key);
    }
}

struct Sender {
    raw: Box<dyn AsyncRawSender>,
    next_send: Instant,
    interval: Duration,
}
impl Sender {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        tokio::time::sleep_until(self.next_send).await;
        poll_fn(|cx| self.raw.poll_send(cx, bytes)).await?;
        self.next_send = Instant::now() + self.interval;
        Ok(())
    }
}

struct Network {
    senders: HashMap<u32, AsyncMutex<Sender>>,
    probes: ProbeWaiters,
    neighbors: NeighborWaiters,
    cache: HashMap<NeighborKey, OnceCell<Option<MacAddr>>>,
}
impl Network {
    async fn send(&self, index: u32, bytes: &[u8]) -> Result<()> {
        self.senders
            .get(&index)
            .context("raw sender unavailable")?
            .lock()
            .await
            .send(bytes)
            .await
    }

    async fn neighbor(&self, route: &Arc<Route>, timeout: Duration) -> Result<Option<MacAddr>> {
        let key = (route.interface.index, route.next_hop);
        let cell = self
            .cache
            .get(&key)
            .context("neighbor cache entry unavailable")?;
        let mac = cell
            .get_or_try_init(|| async {
                let (tx, rx) = oneshot::channel();
                self.neighbors
                    .lock()
                    .unwrap()
                    .insert(key, (route.clone(), tx));
                let _registration = Registration {
                    key,
                    map: self.neighbors.clone(),
                };
                let request = packet::neighbor_request(route)?;
                self.send(key.0, &request).await?;
                match tokio::time::timeout(timeout, rx).await {
                    Ok(reply) => {
                        Ok::<_, anyhow::Error>(Some(reply.context("neighbor receiver stopped")?))
                    }
                    Err(_) => Ok(None),
                }
            })
            .await?;
        ensure!(
            mac.is_some() || route.next_hop == route.destination,
            "cannot resolve gateway {} on {}",
            route.next_hop,
            route.interface.name
        );
        Ok(*mac)
    }

    async fn probe(
        &self,
        probe: Probe,
        timeout: Duration,
        wait: Duration,
    ) -> Result<Option<(Frame, Duration)>> {
        let Some(mac) = self.neighbor(&probe.route, timeout).await? else {
            return Ok(None);
        };
        let key = (
            probe.route.interface.index,
            probe.route.destination,
            probe.port,
        );
        let bytes = probe.packet(mac)?;
        let (tx, rx) = oneshot::channel();
        self.probes.lock().unwrap().insert(key, (probe, tx));
        let _registration = Registration {
            key,
            map: self.probes.clone(),
        };
        // Start the RTT clock when the paced sender can actually transmit.
        let mut sender = self
            .senders
            .get(&key.0)
            .context("raw sender unavailable")?
            .lock()
            .await;
        tokio::time::sleep_until(sender.next_send).await;
        let started = Instant::now();
        sender.send(&bytes).await?;
        drop(sender);
        match tokio::time::timeout(timeout.max(wait), rx).await {
            Ok(reply) => Ok(Some((
                reply.context("probe receiver stopped")?,
                started.elapsed(),
            ))),
            Err(_) => Ok(None),
        }
    }
}

fn dispatch(
    frame: Frame,
    index: u32,
    kind: Kind,
    probes: &ProbeWaiters,
    neighbors: &NeighborWaiters,
) {
    if let Some(next_hop) = packet::neighbor_key(&frame) {
        let key = (index, next_hop);
        let mut pending = neighbors.lock().unwrap();
        if let Some((route, _)) = pending.get(&key)
            && let Some(mac) = packet::neighbor_reply(&frame, route)
            && let Some((_, sender)) = pending.remove(&key)
        {
            let _ = sender.send(mac);
        }
        return;
    }
    if let Some((target, port)) = packet::response_key(&frame, kind) {
        let key = (index, target, port);
        let mut pending = probes.lock().unwrap();
        if pending
            .get(&key)
            .is_some_and(|(probe, _)| probe.matches(&frame).is_some())
            && let Some((_, sender)) = pending.remove(&key)
        {
            let _ = sender.send(frame);
        }
    }
}

struct Reservation {
    port: u16,
    _tcp: Option<tokio::net::TcpSocket>,
    _udp: Option<std::net::UdpSocket>,
}
impl Reservation {
    fn new(route: &Route, kind: Kind) -> Result<Self> {
        let address = match route.source {
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
                ip,
                0,
                0,
                if ip.is_unicast_link_local() {
                    route.interface.index
                } else {
                    0
                },
            )),
            ip => SocketAddr::new(ip, 0),
        };
        let mut result = Self {
            port: 0,
            _tcp: None,
            _udp: None,
        };
        match kind {
            Kind::Tcp => {
                let socket = if address.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                socket.bind(address)?;
                result.port = socket.local_addr()?.port();
                result._tcp = Some(socket);
            }
            Kind::Udp => {
                let socket = std::net::UdpSocket::bind(address)?;
                result.port = socket.local_addr()?.port();
                result._udp = Some(socket);
            }
            Kind::Icmp => {}
        }
        Ok(result)
    }
}

pub(crate) async fn run(setting: ProbeSetting, kind: Kind, port_scan: bool) -> Result<ScanResult> {
    let budget = setting.task_timeout;
    tokio::time::timeout(budget, run_inner(setting, kind, port_scan, 64))
        .await
        .context("raw scan deadline exceeded; reduce scan size or increase task timeout")?
        .map(|(report, _)| report)
}

async fn run_inner(
    setting: ProbeSetting,
    kind: Kind,
    port_scan: bool,
    hop_limit: u8,
) -> Result<(ScanResult, Vec<(Duration, usize)>)> {
    ensure!(
        !setting.connect_timeout.is_zero(),
        "raw probe timeout must be positive"
    );
    let start = Instant::now();
    let routes = tokio::task::spawn_blocking(Routes::load).await??;
    let mut network = Network {
        senders: HashMap::new(),
        probes: Arc::default(),
        neighbors: Arc::default(),
        cache: HashMap::new(),
    };
    // JoinSet aborts every capture task when this scan is cancelled or returns.
    let mut receivers: JoinSet<Result<()>> = JoinSet::new();
    let mut reservations = HashMap::new();
    let mut work = Vec::new();
    let mut endpoints = BTreeMap::new();
    for target in &setting.target_endpoints {
        tokio::task::yield_now().await;
        let route = Arc::new(
            routes
                .resolve(target.ip, setting.if_index)
                .with_context(|| format!("route to {}", target.ip))?,
        );
        let index = route.interface.index;
        if let std::collections::hash_map::Entry::Vacant(entry) = network.senders.entry(index) {
            let mut config = nex::datalink::Config::default();
            config.read_buffer_size = 65536;
            config.write_buffer_size = 4096;
            config.promiscuous = false;
            let AsyncChannel::Ethernet(tx, mut rx) =
                async_channel(&route.interface.clone().into(), config)?
            else {
                anyhow::bail!("unsupported datalink channel");
            };
            entry.insert(AsyncMutex::new(Sender {
                raw: tx,
                next_send: Instant::now(),
                interval: setting.send_rate,
            }));
            let probes = network.probes.clone();
            let neighbors = network.neighbors.clone();
            receivers.spawn(async move {
                while let Some(packet) = rx.next().await {
                    let packet = packet?;
                    if let Some(frame) = Frame::from_buf(&packet, ParseOption::default()) {
                        dispatch(frame, index, kind, &probes, &neighbors);
                    }
                }
                anyhow::bail!("raw capture stream ended unexpectedly")
            });
        }
        network.cache.entry((index, route.next_hop)).or_default();
        let reservation = match reservations.entry((index, route.source)) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Reservation::new(&route, kind)?)
            }
        };
        let ports = if kind == Kind::Icmp {
            vec![0]
        } else {
            target.ports.iter().map(|p| p.number).collect()
        };
        ensure!(!ports.is_empty(), "raw TCP/UDP probes require target ports");
        for port in ports {
            work.push(Probe {
                route: route.clone(),
                kind,
                port,
                local_port: reservation.port,
                nonce: rand::random(),
                hop_limit,
            });
        }
        let mut endpoint = EndpointResult::new(target.ip);
        endpoint.hostname = target.hostname.clone();
        endpoints.insert(target.ip, endpoint);
    }
    let concurrency = if port_scan {
        setting.port_concurrency
    } else {
        setting.host_concurrency
    }
    .max(1);
    let network = &network;
    let mut results = stream::iter(work)
        .map(|probe| async move {
            let result = network
                .probe(probe.clone(), setting.connect_timeout, setting.wait_time)
                .await?;
            Ok::<_, anyhow::Error>((probe, result))
        })
        .buffer_unordered(concurrency);
    let mut frames = Vec::new();
    let mut timings = Vec::new();
    let mut bytes = 0usize;
    let mut alive = std::collections::HashSet::new();
    loop {
        let next = tokio::select! {
            result = results.next() => result,
            failed = receivers.join_next(), if !receivers.is_empty() => {
                failed.context("raw receiver disappeared")??.context("raw receiver failed")?;
                anyhow::bail!("raw receiver stopped");
            }
        };
        let Some(result) = next else { break };
        let (probe, reply) = result?;
        let endpoint = endpoints
            .get_mut(&probe.route.destination)
            .context("missing result endpoint")?;
        let mut state = PortState::Filtered;
        let mut rtt_ms = None;
        if let Some((frame, rtt)) = reply {
            state = probe
                .matches(&frame)
                .context("response no longer matches probe")?;
            rtt_ms = Some(rtt.as_millis().min(u32::MAX as u128) as u32);
            alive.insert(endpoint.ip);
            endpoint.os.ttl_observed = packet::addresses(&frame).map(|(_, _, ttl)| ttl);
            // A routed Ethernet source is the next-hop router, not the remote host.
            if probe.route.next_hop == endpoint.ip {
                endpoint.mac_addr = frame
                    .datalink
                    .as_ref()
                    .and_then(|d| d.ethernet.as_ref())
                    .map(|eth| eth.source);
                endpoint.vendor_name = endpoint
                    .mac_addr
                    .as_ref()
                    .and_then(crate::db::oui::lookup_vendor_name);
            }
            bytes = bytes.saturating_add(frame.packet_len);
            ensure!(
                bytes <= 64 * 1024 * 1024 && frames.len() < 65_536,
                "capture buffer limit exceeded; split the scan"
            );
            timings.push((rtt, probe.packet(MacAddr::zero())?.len()));
            frames.push(frame);
        }
        if kind == Kind::Tcp || kind == Kind::Udp {
            let port = Port::new(
                probe.port,
                if kind == Kind::Tcp {
                    TransportProtocol::Tcp
                } else {
                    TransportProtocol::Udp
                },
            );
            endpoint.upsert_port(PortResult {
                port,
                state,
                service: ServiceInfo::default(),
                rtt_ms,
            });
        }
    }
    Ok((
        ScanResult {
            endpoints: endpoints
                .into_values()
                .filter(|ep| port_scan || alive.contains(&ep.ip))
                .collect(),
            scan_time: start.elapsed(),
            fingerprints: frames,
        },
        timings,
    ))
}

pub(crate) async fn interface_for_target(ip: IpAddr) -> Result<netdev::Interface> {
    let routes = tokio::task::spawn_blocking(Routes::load).await??;
    Ok(routes.resolve(ip, 0)?.interface)
}

pub(crate) async fn ping(
    setting: &crate::ping::setting::PingSetting,
    kind: Kind,
) -> Result<crate::ping::result::PingResult> {
    use crate::{
        endpoint::{Endpoint, NodeType},
        ping::result::PingStat,
        probe::{ProbeResult, ProbeStatus},
    };
    let start = Instant::now();
    let mut responses = Vec::new();
    for seq in 1..=setting.count {
        let mut endpoint = Endpoint::with_hostname(
            setting.dst_ip,
            setting.dst_hostname.clone().unwrap_or_default(),
        );
        if kind != Kind::Icmp {
            endpoint.ports.push(Port::new(
                setting.dst_port.unwrap_or(80),
                if kind == Kind::Tcp {
                    TransportProtocol::Tcp
                } else {
                    TransportProtocol::Udp
                },
            ));
        }
        let (scan, timings) = run_inner(
            ProbeSetting {
                target_endpoints: vec![endpoint],
                if_index: setting.if_index,
                host_concurrency: 1,
                port_concurrency: 1,
                task_timeout: setting.probe_timeout,
                connect_timeout: setting.receive_timeout,
                wait_time: Duration::ZERO,
                send_rate: Duration::ZERO,
            },
            kind,
            false,
            setting.hop_limit,
        )
        .await?;
        if let Some((frame, (rtt, sent_size))) = scan.fingerprints.first().zip(timings.first()) {
            let ttl = packet::addresses(frame)
                .context("response IP header unavailable")?
                .2;
            let ep = &scan.endpoints[0];
            responses.push(ProbeResult {
                seq,
                mac_addr: ep.mac_addr.unwrap_or(MacAddr::zero()),
                ip_addr: setting.dst_ip,
                host_name: setting.dst_hostname.clone(),
                port_number: setting.dst_port,
                port_status: ep.ports.values().next().map(|p| p.state),
                ttl,
                hop: crate::util::ip::initial_ttl(ttl) - ttl,
                rtt: *rtt,
                probe_status: ProbeStatus::new(),
                protocol: setting.protocol,
                node_type: NodeType::Destination,
                sent_packet_size: *sent_size,
                received_packet_size: frame.packet_len,
            });
        } else {
            responses.push(ProbeResult::timeout(
                seq,
                setting.dst_ip,
                setting.dst_hostname.clone(),
                setting.protocol,
                0,
            ));
        }
        if seq < setting.count {
            tokio::time::sleep(setting.send_rate).await;
        }
    }
    let times: Vec<_> = responses
        .iter()
        .filter(|r| r.probe_status.kind == crate::probe::ProbeStatusKind::Done)
        .map(|r| r.rtt)
        .collect();
    let elapsed = start.elapsed();
    Ok(crate::ping::result::PingResult {
        stat: PingStat {
            received_count: times.len(),
            transmitted_count: setting.count as usize,
            min: times.iter().copied().min(),
            max: times.iter().copied().max(),
            avg: (!times.is_empty())
                .then(|| times.iter().copied().sum::<Duration>() / times.len() as u32),
            responses,
            probe_time: elapsed,
        },
        probe_status: ProbeStatus::new(),
        elapsed_time: elapsed,
        ip_addr: setting.dst_ip,
        hostname: setting.dst_hostname.clone(),
        port_number: setting.dst_port,
        protocol: setting.protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_removes_pending_registration() {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let pending = map.clone();
        let (ready, started) = oneshot::channel();
        let task = tokio::spawn(async move {
            pending.lock().unwrap().insert(1, ());
            let _registration = Registration {
                key: 1,
                map: pending,
            };
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        assert_eq!(map.lock().unwrap().len(), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(map.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_scans_reserve_distinct_source_ports() {
        for source in ["127.0.0.1", "::1"] {
            let route = Route {
                interface: netdev::Interface::dummy(),
                source: source.parse().unwrap(),
                destination: source.parse().unwrap(),
                next_hop: source.parse().unwrap(),
            };
            for kind in [Kind::Tcp, Kind::Udp] {
                let reservations: Vec<_> = (0..16)
                    .map(|_| Reservation::new(&route, kind).unwrap())
                    .collect();
                let ports: std::collections::HashSet<_> =
                    reservations.iter().map(|r| r.port).collect();
                assert_eq!(ports.len(), reservations.len());
                assert!(!ports.contains(&0));
            }
        }
    }
}
