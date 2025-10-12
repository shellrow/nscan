use std::net::SocketAddr;
use anyhow::Result;
use tokio::{io::{AsyncWriteExt}, net::TcpStream, time::timeout};

use crate::{
    endpoint::ServiceInfo,
    service::{
        build_regex, expand_cpe_templates, payload::{PayloadBuilder, PayloadContext}, probe::{PortProbeResult, ProbeContext}, read_timeout
    },
};

#[derive(Debug, Default, Clone)]
struct BannerLite {
    first_line: Option<String>,
    raw_text: String,
}

/// First line (terminated by \r\n or \n) is treated as banner.
fn parse_banner(bytes: &[u8], max_preview: usize) -> BannerLite {
    let raw = String::from_utf8_lossy(bytes);
    let mut out = BannerLite::default();
    out.raw_text = if raw.len() > max_preview {
        raw[..max_preview].to_string()
    } else {
        raw.to_string()
    };
    let first = out.raw_text.split(|c| c == '\n').next().unwrap_or("").trim_end_matches('\r');
    if !first.is_empty() {
        out.first_line = Some(first.to_string());
    }
    out
}

/// Match response text against known service signatures.
/// (service, cpes)
fn match_signatures(
    probe_id: &str,
    text: &str,
) -> anyhow::Result<Option<(String, Vec<String>)>> {
    let sigdb = crate::db::service::response_signatures_db();
    let mut best_service: String = String::new();
    let mut cpes: Vec<String> = Vec::new();
    for sig in sigdb {
        if !sig.probe_id.eq_ignore_ascii_case(probe_id) {
            continue;
        }

        let re = match build_regex(&sig.regex, "") {
            Ok(r) => r,
            Err(_) => build_regex(&sig.regex, "i")?,
        };
        if let Some(caps) = re.captures(text) {
            if best_service.is_empty() && !sig.service.is_empty() {
                best_service = sig.service.clone();
            }
            let cs = expand_cpe_templates(&sig.cpe, &caps);
            if !cs.is_empty() {
                cpes.extend(cs);
                // Generic CPEs can have multiple candidates, so it's okay to continue collecting
            }
        }
    }
    Ok(Some((best_service, cpes)))
}

/// A generic probe that connects to a TCP port, optionally sends a payload, and reads the response.
pub struct GenericProbe;

impl GenericProbe {
    /// Run the generic probe with the given context.
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        tracing::debug!("Generic Probe: {}:{} - Connecting", ctx.ip, ctx.probe.port);
        let addr: SocketAddr = SocketAddr::new(ctx.ip, ctx.probe.port);
        let mut stream = timeout(ctx.timeout, TcpStream::connect(addr)).await??;

        tracing::debug!("Generic Probe: {}:{} - Connected", ctx.ip, ctx.probe.port);

        // If payload is present, send it
        let payload = PayloadBuilder::new(ctx.probe.clone())
            .payload(PayloadContext::default()) 
            .unwrap_or_default();
        if !payload.is_empty() {
            timeout(ctx.timeout, stream.write_all(&payload)).await??;
            stream.flush().await?;
        }

        // Apply idle/total timeout + max byte limit for reading
        let idle = ctx.timeout;
        let total = ctx.timeout;
        tracing::debug!("Generic Probe: {}:{} - Reading response(timeout: {})", ctx.ip, ctx.probe.port, total.as_millis());
        let bytes = read_timeout(&mut stream, idle, total, ctx.max_read_size).await?;

        // Extract banner
        let banner = parse_banner(&bytes, 64 * 1024);

        tracing::debug!("Generic Probe: {}:{} - Banner: {:?}", ctx.ip, ctx.probe.port, banner.first_line);

        // Match signatures
        let hit = match_signatures(ctx.probe.probe_id.as_str(), &banner.raw_text)?;

        // Build result
        let mut svc = ServiceInfo::default();
        if let Some((service_name, cpes)) = hit {
            svc.name = Some(service_name);
            if !cpes.is_empty() {
                svc.cpes = cpes;
            }
        }
        // If name is still empty, keep banner
        svc.banner = banner.first_line.clone();
        svc.raw = Some(banner.raw_text);
        let probe_result: PortProbeResult = PortProbeResult {
            ip: ctx.ip,
            hostname: ctx.hostname,
            port: ctx.probe.port,
            transport: ctx.probe.transport,
            probe_id: ctx.probe.probe_id,
            service_info: svc,
        };
        Ok(probe_result)
    }
}
