//! Optional detailed identification through Nmap's XML interface.
use crate::endpoint::{EndpointResult, TransportProtocol};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

const MAX_XML: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Identification {
    pub source: String,
    pub version: String,
    pub complete: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostDetails {
    pub ip: IpAddr,
    pub ports: Vec<PortDetails>,
    pub os_matches: Vec<OsMatch>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortDetails {
    #[serde(alias = "@portid")]
    pub port: u16,
    #[serde(alias = "@protocol")]
    pub protocol: String,
    pub state: State,
    pub service: Option<Service>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    #[serde(alias = "@state")]
    pub state: String,
    #[serde(alias = "@reason")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    #[serde(alias = "@name")]
    pub name: Option<String>,
    #[serde(alias = "@product")]
    pub product: Option<String>,
    #[serde(alias = "@version")]
    pub version: Option<String>,
    #[serde(alias = "@extrainfo")]
    pub extra_info: Option<String>,
    #[serde(alias = "@method")]
    pub method: Option<String>,
    #[serde(alias = "@conf")]
    pub confidence: Option<u8>,
    #[serde(alias = "cpe", default)]
    pub cpes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsMatch {
    #[serde(alias = "@name")]
    pub name: String,
    #[serde(alias = "@accuracy")]
    pub accuracy: u8,
    #[serde(alias = "osclass", default)]
    pub classes: Vec<OsClass>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsClass {
    #[serde(alias = "@vendor")]
    pub vendor: Option<String>,
    #[serde(alias = "@osfamily")]
    pub family: Option<String>,
    #[serde(alias = "@osgen")]
    pub generation: Option<String>,
    #[serde(alias = "@type")]
    pub device_type: Option<String>,
    #[serde(alias = "cpe", default)]
    pub cpes: Vec<String>,
}

#[derive(Deserialize)]
struct Run {
    #[serde(rename = "@scanner")]
    scanner: String,
    #[serde(rename = "@version")]
    version: String,
    #[serde(rename = "host", default)]
    hosts: Vec<Host>,
    runstats: RunStats,
}
#[derive(Deserialize)]
struct RunStats {
    finished: Finished,
}
#[derive(Deserialize)]
struct Finished {
    #[serde(rename = "@exit")]
    exit: String,
}
#[derive(Deserialize)]
struct Host {
    #[serde(rename = "@timedout", default)]
    timed_out: bool,
    #[serde(rename = "address", default)]
    addresses: Vec<Address>,
    #[serde(default)]
    ports: Ports,
    #[serde(default)]
    os: Os,
}
#[derive(Deserialize)]
struct Address {
    #[serde(rename = "@addr")]
    addr: String,
}
#[derive(Default, Deserialize)]
struct Ports {
    #[serde(rename = "port", default)]
    ports: Vec<PortDetails>,
}
#[derive(Default, Deserialize)]
struct Os {
    #[serde(rename = "osmatch", default)]
    matches: Vec<OsMatch>,
}

pub struct Nmap {
    executable: PathBuf,
    version: String,
}

impl Nmap {
    /// Check availability only when external identification was requested.
    pub async fn preflight(path: &Path) -> Result<Self> {
        let (stdout, _) = execute(path, &["--version".into()], Duration::from_secs(5))
            .await
            .with_context(|| {
                format!(
                    "Nmap unavailable at {}; install Nmap or set --nmap-path",
                    path.display()
                )
            })?;
        let text = std::str::from_utf8(&stdout)?;
        let version = text
            .lines()
            .find_map(|line| line.strip_prefix("Nmap version "))
            .and_then(|line| line.split_whitespace().next())
            .context("unexpected Nmap version output")?;
        Ok(Self {
            executable: path.to_path_buf(),
            version: version.to_string(),
        })
    }

    /// Supplement native observations only for TCP ports already observed as open.
    /// Retain successful host results if a later invocation fails or times out.
    pub async fn identify(
        &self,
        targets: &[EndpointResult],
        services: bool,
        os: bool,
        budget: Duration,
    ) -> Identification {
        let mut result = Identification {
            source: "nmap".into(),
            version: self.version.clone(),
            complete: false,
            error: None,
            warnings: Vec::new(),
            hosts: Vec::new(),
        };
        let deadline = tokio::time::Instant::now() + budget;
        for target in targets {
            let ports: Vec<u16> = target
                .get_open_ports()
                .into_iter()
                .filter(|p| p.transport == TransportProtocol::Tcp)
                .map(|p| p.number)
                .collect();
            if ports.is_empty() {
                continue;
            }
            let arguments = arguments(target.ip, &ports, services, os);
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tracing::info!(
                "{}: Starting identification on {} open TCP port(s), timeout {:.1}s",
                target.ip,
                ports.len(),
                remaining.as_secs_f64()
            );
            let started = tokio::time::Instant::now();
            let outcome = async {
                ensure!(
                    !remaining.is_zero(),
                    "Nmap identification deadline exceeded"
                );
                let execution = execute(&self.executable, &arguments, remaining);
                tokio::pin!(execution);
                let (xml, stderr) = loop {
                    tokio::select! {
                        result = &mut execution => break result?,
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {
                            tracing::info!(
                                "{}: Identification in progress ({:.0}s elapsed, {:.0}s remaining)",
                                target.ip, started.elapsed().as_secs_f64(),
                                deadline.saturating_duration_since(tokio::time::Instant::now()).as_secs_f64()
                            );
                        }
                    }
                };
                let (version, host) = parse(&xml, target.ip, &ports)?;
                ensure!(
                    version == self.version,
                    "Nmap version changed during identification"
                );
                Ok::<_, anyhow::Error>((host, stderr))
            }
            .await;
            match outcome {
                Ok((host, stderr)) => {
                    tracing::info!(
                        "{}: Identification completed in {:?}",
                        target.ip,
                        started.elapsed()
                    );
                    result.hosts.push(host);
                    if !stderr.is_empty() {
                        result.warnings.push(crate::output::terminal_text(
                            &String::from_utf8_lossy(&stderr),
                        ));
                    }
                }
                Err(error) => {
                    result.error = Some(format!("{}: {error:#}", target.ip));
                    return result;
                }
            }
        }
        result.complete = true;
        result
    }
}

fn arguments(ip: IpAddr, ports: &[u16], services: bool, os: bool) -> Vec<String> {
    let mut args: Vec<String> = ["-n", "-Pn", "-sT", "-oX", "-", "-p"]
        .map(str::to_string)
        .into();
    args.push(port_spec(ports));
    if ip.is_ipv6() {
        args.push("-6".into());
    }
    if services {
        args.push("-sV".into());
    }
    if os {
        args.push("-O".into());
    }
    args.push(ip.to_string());
    args
}

fn port_spec(ports: &[u16]) -> String {
    let mut ports = ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < ports.len() {
        let start = ports[index];
        let mut end = start;
        index += 1;
        while index < ports.len() && end.checked_add(1) == Some(ports[index]) {
            end = ports[index];
            index += 1;
        }
        ranges.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    ranges.join(",")
}

async fn read_bounded(reader: impl AsyncRead + Unpin, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.take(limit + 1).read_to_end(&mut data).await?;
    ensure!(data.len() as u64 <= limit, "Nmap output exceeds size limit");
    Ok(data)
}

async fn execute(path: &Path, args: &[String], budget: Duration) -> Result<(Vec<u8>, Vec<u8>)> {
    tokio::time::timeout(budget, async {
        let mut child = Command::new(path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdout = child.stdout.take().context("missing Nmap stdout")?;
        let stderr = child.stderr.take().context("missing Nmap stderr")?;
        let (stdout, stderr, status) = tokio::try_join!(
            read_bounded(stdout, MAX_XML),
            read_bounded(stderr, 1024 * 1024),
            async { Ok::<_, anyhow::Error>(child.wait().await?) }
        )?;
        ensure!(
            status.success(),
            "Nmap exited with {status}: {}",
            crate::output::terminal_text(&String::from_utf8_lossy(&stderr))
        );
        Ok((stdout, stderr))
    })
    .await
    .context("Nmap identification timed out")?
}

fn parse(xml: &[u8], ip: IpAddr, requested_ports: &[u16]) -> Result<(String, HostDetails)> {
    // Nmap emits a DOCTYPE declaration; no external DTD or entity is loaded.
    let run: Run = quick_xml::de::from_reader(xml).context("invalid Nmap XML output")?;
    ensure!(
        run.scanner == "nmap" && run.runstats.finished.exit == "success",
        "incomplete Nmap scan"
    );
    let mut hosts = run.hosts.into_iter().filter(|host| {
        host.addresses
            .iter()
            .any(|addr| addr.addr.parse::<IpAddr>().ok() == Some(ip))
    });
    let host = hosts
        .next()
        .context("Nmap output does not contain the requested address")?;
    ensure!(hosts.next().is_none(), "duplicate host in Nmap output");
    ensure!(!host.timed_out, "Nmap host scan timed out");
    let ports = host
        .ports
        .ports
        .into_iter()
        .filter(|port| port.protocol == "tcp" && requested_ports.contains(&port.port))
        .collect();
    Ok((
        run.version,
        HostDetails {
            ip,
            ports,
            os_matches: host.os.matches,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    const XML: &str = r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.99"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.9" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.9</cpe></service></port></ports><os><osmatch name="Linux" accuracy="95"><osclass vendor="Linux" osfamily="Linux"><cpe>cpe:/o:linux:linux_kernel</cpe></osclass></osmatch></os></host><runstats><finished exit="success"/></runstats></nmaprun>"#;
    #[test]
    fn xml_preserves_external_evidence_and_checks_identity() {
        let (version, host) = parse(XML.as_bytes(), "127.0.0.1".parse().unwrap(), &[22]).unwrap();
        assert_eq!(version, "7.99");
        assert_eq!(
            host.ports[0].service.as_ref().unwrap().product.as_deref(),
            Some("OpenSSH")
        );
        assert_eq!(host.os_matches[0].accuracy, 95);
        assert!(parse(XML.as_bytes(), "192.0.2.1".parse().unwrap(), &[22]).is_err());
        assert!(
            parse(
                XML.replace("exit=\"success\"", "exit=\"error\"").as_bytes(),
                host.ip,
                &[22]
            )
            .is_err()
        );
        assert!(parse(b"<nmaprun", host.ip, &[22]).is_err());
        assert!(
            parse(XML.as_bytes(), host.ip, &[80])
                .unwrap()
                .1
                .ports
                .is_empty()
        );
    }
    #[test]
    fn host_timeouts_and_json_roundtrip() {
        let ip = "127.0.0.1".parse().unwrap();
        assert!(
            parse(
                XML.replace("<host>", "<host timedout=\"true\">").as_bytes(),
                ip,
                &[22]
            )
            .is_err()
        );
        let (_, host) = parse(XML.as_bytes(), ip, &[22]).unwrap();
        let json = serde_json::to_string(&host).unwrap();
        let decoded: HostDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ports[0].port, 22);
        assert_eq!(decoded.os_matches[0].name, "Linux");
        assert_eq!(port_spec(&(1..=65535).collect::<Vec<_>>()), "1-65535");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn identification_only_requests_open_tcp_ports() {
        use crate::endpoint::{Port, PortResult, PortState};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-nmap");
        std::fs::write(&path, format!(
            "#!/bin/sh\nwhile [ \"$1\" != \"-p\" ]; do shift; done\n[ \"$2\" = \"22\" ] || exit 1\ncat <<'XML'\n{XML}\nXML\n"
        )).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let nmap = Nmap {
            executable: path,
            version: "7.99".into(),
        };
        let mut ep = EndpointResult::new("127.0.0.1".parse().unwrap());
        for (number, transport, state) in [
            (22, TransportProtocol::Tcp, PortState::Open),
            (80, TransportProtocol::Tcp, PortState::Closed),
            (443, TransportProtocol::Tcp, PortState::Filtered),
            (53, TransportProtocol::Udp, PortState::Open),
        ] {
            ep.upsert_port(PortResult {
                port: Port::new(number, transport),
                state,
                rtt_ms: None,
                service: Default::default(),
            });
        }
        let mut failing_host = ep.clone();
        failing_host.ip = "127.0.0.2".parse().unwrap();
        let partial = nmap
            .identify(
                &[ep.clone(), failing_host],
                true,
                true,
                Duration::from_secs(2),
            )
            .await;
        assert!(!partial.complete);
        assert!(partial.error.is_some());
        assert_eq!(partial.hosts.len(), 1);
        let mut report = crate::output::port::ScanReport::new();
        report.endpoints.insert(ep.ip, ep.clone());
        report.apply_identification(partial);
        assert_eq!(
            report.endpoints[&ep.ip].ports[&Port::new(22, TransportProtocol::Tcp)]
                .service
                .product
                .as_deref(),
            Some("OpenSSH")
        );
        let result = nmap
            .identify(&[ep], true, true, Duration::from_secs(2))
            .await;
        assert!(result.complete, "{:?}", result.error);
        assert_eq!(result.hosts.len(), 1);
        let empty = EndpointResult::new("127.0.0.1".parse().unwrap());
        let result = nmap.identify(&[empty], true, true, Duration::ZERO).await;
        assert!(result.complete);
        assert!(result.hosts.is_empty());
    }

    #[test]
    fn service_identification_uses_exactly_the_discovered_ports() {
        let args = arguments(
            "192.168.10.50".parse().unwrap(),
            &[22, 80, 139, 443, 445, 9999],
            true,
            false,
        );
        assert_eq!(
            args,
            [
                "-n",
                "-Pn",
                "-sT",
                "-oX",
                "-",
                "-p",
                "22,80,139,443,445,9999",
                "-sV",
                "192.168.10.50",
            ]
        );
    }

    #[test]
    fn arguments_are_scoped_and_ipv6_aware() {
        let args = arguments("::1".parse().unwrap(), &[22, 443], true, false);
        assert!(args.contains(&"-6".into()));
        assert!(args.contains(&"22,443".into()));
        assert!(!args.contains(&"-O".into()));
        assert_eq!(args.last().unwrap(), "::1");
    }
    #[tokio::test]
    async fn bounded_output_rejects_oversize() {
        assert!(read_bounded(&b"12345"[..], 4).await.is_err());
    }
}
