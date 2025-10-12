use std::{collections::HashMap, net::SocketAddr};

use anyhow::Result;
use rustls_pki_types::ServerName;
use tokio::{io::{AsyncWriteExt}, net::TcpStream, time::timeout};
use tokio_rustls::{TlsConnector, rustls::{ClientConfig, RootCertStore}};
use std::sync::Arc;

use crate::{endpoint::ServiceInfo, service::{build_http_regex, expand_cpe_templates, payload::{PayloadBuilder, PayloadContext}, probe::{PortProbeResult, ProbeContext, ServiceProbe}, read_timeout}};
use super::tls::SkipServerVerification;

/// A lightweight representation of an HTTP response for analysis.
#[derive(Debug, Default, Clone)]
pub struct HttpResponseLite {
    pub status_line: Option<String>,
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub header_text: String,
    pub body: Vec<u8>,
    pub raw_text: String,
}

/// Parse raw bytes into an HttpResponseLite structure.
fn parse_http_response(bytes: &[u8], body_limit: usize) -> HttpResponseLite {
    const HDR_MAX: usize = 64 * 1024;
    let mut res = HttpResponseLite::default();

    // Find the end of headers in the byte array (prefer \r\n\r\n, else try \n\n)
    let hdr_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| bytes.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
        .unwrap_or_else(|| bytes.len().min(HDR_MAX));

    let header_bytes = &bytes[..hdr_end.min(bytes.len())];
    let body_bytes   = if hdr_end < bytes.len() { &bytes[hdr_end..] } else { &[][..] };

    // Convert header bytes to a lossy UTF-8 string
    let header_text = String::from_utf8_lossy(header_bytes);
    res.header_text = header_text.to_string();

    // Parse status line and headers into the structure. Try \r\n first, then \n if not found.
    let mut lines = header_text.split("\r\n");
    if header_text.find("\r\n").is_none() {
        lines = header_text.split("\n");
    }

    if let Some(first) = lines.next() {
        let line = first.trim().to_string();
        res.status_line = Some(line.clone());
        if let Some(code) = line.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()) {
            res.status_code = Some(code);
        }
    }
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            res.headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // Limit body size to body_limit
    let take = body_bytes.len().min(body_limit);
    res.body.extend_from_slice(&body_bytes[..take]);

    // Construct raw_text as "headers + CRLFCRLF + first N bytes of body"
    // for easier and safer regex matching later
    let mut raw = header_text.into_owned();
    raw.push_str("\r\n\r\n");
    raw.push_str(&String::from_utf8_lossy(&body_bytes[..take]));
    res.raw_text = raw;

    res
}

/// Match HTTP response against known service signatures.
/// Returns matched CPEs if any.
fn match_http_signatures(
    service_keys: &[&str],
    _probe_id: &str,
    http_res: &HttpResponseLite,
) -> anyhow::Result<Vec<String>> {
    let sigdb = crate::db::service::response_signatures_db();
    let mut hits = Vec::new();

    'outer: for sig in sigdb {
        if !service_keys.iter().any(|k| sig.service.eq_ignore_ascii_case(k)) {
            continue;
        }
        
        /* if !sig.probe_id.is_empty() && !sig.probe_id.eq_ignore_ascii_case(probe_id) {
            continue;
        } */

        let re = build_http_regex(&sig.regex)?;

        if let Some(caps) = re.captures(&http_res.header_text) {
            let cpes = expand_cpe_templates(&sig.cpe, &caps);
            if !cpes.is_empty() {
                hits.extend(cpes);
                break 'outer;
            }
        }
    }
    Ok(hits)
}

/// An HTTP probe that can send HTTP/HTTPS requests and analyze responses.
pub struct HttpProbe;

impl HttpProbe {
    /// Run the HTTP probe with the given context.
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        let addr: SocketAddr = SocketAddr::new(ctx.ip, ctx.probe.port);
        let hostname = ctx.hostname.clone().unwrap_or_else(|| ctx.ip.to_string());
        let mut tcp_stream = timeout(ctx.timeout, TcpStream::connect(addr)).await??;
        let payload_builder = PayloadBuilder::new(ctx.probe.clone());
        let tcp_svc_db = crate::db::service::tcp_service_db();
        match ctx.probe.probe_id {
            ServiceProbe::TcpHTTPGet => {
                tracing::debug!("HTTP Probe: {}:{} - Sending HTTP GET", ctx.ip, ctx.probe.port);
                let payload: Vec<u8> = payload_builder.payload(PayloadContext::default())?;
                timeout(ctx.timeout, tcp_stream.write_all(&payload)).await??;
                tcp_stream.flush().await?;
                let res: Vec<u8> = read_timeout(&mut tcp_stream, ctx.timeout, ctx.timeout, ctx.max_read_size).await?;
                let http_res = parse_http_response(&res, 64 * 1024);
                tracing::debug!("HTTP Probe: {}:{} - Header: {:?}", ctx.ip, ctx.probe.port, http_res.header_text);
                let mut svc = ServiceInfo::default();
                svc.name = tcp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());
                svc.banner = http_res.status_line.clone();
                svc.product = http_res.headers.get("server").cloned();
                svc.raw = Some(http_res.raw_text.clone());

                tracing::debug!("HTTP Probe: {}:{} - Banner: {:?}, Server {:?}", ctx.ip, ctx.probe.port, svc.banner, svc.product);

                // Match signatures
                let cpes = match_http_signatures(
                    &["http"],
                    "tcp:http_get",
                    &http_res,
                )?;
                if !cpes.is_empty() {
                    svc.cpes = cpes;
                }
                let probe_result: PortProbeResult = PortProbeResult {
                    ip: ctx.ip,
                    hostname: ctx.hostname,
                    port: ctx.probe.port,
                    transport: ctx.probe.transport,
                    probe_id: ctx.probe.probe_id,
                    service_info: svc,
                };
                tracing::debug!("HTTP Probe Result: {:?}", probe_result);
                return Ok(probe_result);
            },
            ServiceProbe::TcpHTTPSGet => {
                tracing::debug!("HTTP Probe: {}:{} - Sending HTTPS GET", ctx.ip, ctx.probe.port);
                let payload_ctx = PayloadContext {
                    hostname: ctx.hostname.as_deref(),
                    path: Some("/".into()),
                };
                let payload: Vec<u8> = payload_builder.payload(payload_ctx)?;

                // rustls config
                let mut roots = RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs()? { let _ = roots.add(cert); }
                let mut config = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();

                // Set ALPN protocols
                //config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
                config.alpn_protocols = vec!["http/1.1".into()];

                if ctx.skip_cert_verify {
                    config.dangerous().set_certificate_verifier(SkipServerVerification::new());
                }

                let connector = TlsConnector::from(Arc::new(config));
                let sni_name = if ctx.sni {
                    ServerName::try_from(hostname)?
                } else {
                    ServerName::try_from("localhost")?
                };

                let mut tls_stream = timeout(ctx.timeout, connector.connect(sni_name, tcp_stream)).await??;
                // server connection
                let conn = tls_stream.get_ref().1;

                let mut svc = ServiceInfo::default();
                svc.name = tcp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());

                svc.tls_info = super::tls::extract_tls_info(&ctx, &conn);

                tls_stream.write_all(&payload).await?;
                tls_stream.flush().await?;
                let res: Vec<u8> = read_timeout(&mut tls_stream, ctx.timeout, ctx.timeout, ctx.max_read_size).await?;
                let http_res = parse_http_response(&res, 64 * 1024);
                tracing::debug!("HTTP Probe: {}:{} - Header: {:?}", ctx.ip, ctx.probe.port, http_res.header_text);
                svc.banner = http_res.status_line.clone();
                svc.product = http_res.headers.get("server").cloned();
                svc.raw = Some(http_res.raw_text.clone());

                tracing::debug!("HTTPS Probe: {}:{} - Banner: {:?}, Server {:?}", ctx.ip, ctx.probe.port, svc.banner, svc.product);
                tracing::debug!("RAW: {:?}", svc.raw);

                // Match signatures
                let cpes = match_http_signatures(
                    &["http"],
                    "tcp:https_get",
                    &http_res,
                )?;
                if !cpes.is_empty() {
                    svc.cpes = cpes;
                }
                let probe_result: PortProbeResult = PortProbeResult {
                    ip: ctx.ip,
                    hostname: ctx.hostname,
                    port: ctx.probe.port,
                    transport: ctx.probe.transport,
                    probe_id: ctx.probe.probe_id,
                    service_info: svc,
                };
                tracing::debug!("HTTP Probe Result: {:?}", probe_result);
                return Ok(probe_result);
            },
            ServiceProbe::TcpHTTPOptions => {
                tracing::debug!("HTTP Probe: {}:{} - Sending HTTP OPTIONS", ctx.ip, ctx.probe.port);
                let payload: Vec<u8> = payload_builder.payload(PayloadContext::default())?;
                timeout(ctx.timeout, tcp_stream.write_all(&payload)).await??;
                tcp_stream.flush().await?;
                let res: Vec<u8> = read_timeout(&mut tcp_stream, ctx.timeout, ctx.timeout, ctx.max_read_size).await?;
                let http_res = parse_http_response(&res, 64 * 1024);
                tracing::debug!("HTTP Probe: {}:{} - Header: {:?}", ctx.ip, ctx.probe.port, http_res.header_text);
                let mut svc = ServiceInfo::default();
                svc.name = tcp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());
                svc.banner = http_res.status_line.clone();
                svc.product = http_res.headers.get("server").cloned();
                svc.raw = Some(http_res.raw_text.clone());

                tracing::debug!("HTTP Probe: {}:{} - Banner: {:?}, Server {:?}", ctx.ip, ctx.probe.port, svc.banner, svc.product);

                // Match signatures
                let cpes = match_http_signatures(
                    &["http"],
                    "tcp:http_options",
                    &http_res,
                )?;
                if !cpes.is_empty() {
                    svc.cpes = cpes;
                }
                let probe_result: PortProbeResult = PortProbeResult {
                    ip: ctx.ip,
                    hostname: ctx.hostname,
                    port: ctx.probe.port,
                    transport: ctx.probe.transport,
                    probe_id: ctx.probe.probe_id,
                    service_info: svc,
                };
                tracing::debug!("HTTP Probe Result: {:?}", probe_result);
                return Ok(probe_result);
            }
            _ => {},
        }
        Err(anyhow::anyhow!("Failed to probe HTTP service at {}", addr))
    }
}
