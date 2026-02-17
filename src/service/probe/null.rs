use anyhow::{Result, bail};
use std::net::SocketAddr;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};

use crate::{
    endpoint::ServiceInfo,
    service::{
        build_regex, expand_cpe_templates,
        payload::{PayloadBuilder, PayloadContext},
        probe::{PortProbeResult, ProbeContext, ServiceProbe},
        read_timeout,
    },
};

/// Lightweight representation of a service banner
#[derive(Debug, Default, Clone)]
struct BannerLite {
    first_line: Option<String>,
    raw_text: String,
}

/// Determine if a string looks like a text line
fn looks_like_text_line(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return false;
    }
    // ASCII printable characters and whitespace ratio
    let printable = t
        .chars()
        .filter(|&c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    let ratio = printable as f32 / t.len() as f32;
    ratio >= 0.6
}

/// Extract banner:
/// 1. If the first line looks like text, use it
/// 2. If not, use the second line if it exists
/// 3. If neither exists, use the first line (raw)
fn parse_banner(bytes: &[u8], max_preview: usize) -> BannerLite {
    let raw = String::from_utf8_lossy(bytes);
    let mut out = BannerLite::default();

    out.raw_text = if raw.len() > max_preview {
        raw[..max_preview].to_string()
    } else {
        raw.to_string()
    };

    let mut lines = out
        .raw_text
        .split(|c| c == '\n')
        .map(|l| l.trim_end_matches('\r'));

    let first = lines.next().unwrap_or("");
    let second = lines.next().unwrap_or("");

    if looks_like_text_line(first) {
        out.first_line = Some(first.to_string());
    } else if !second.is_empty() {
        out.first_line = Some(second.to_string());
    } else if !first.is_empty() {
        out.first_line = Some(first.to_string());
    }
    out
}

/// Match response text against known service signatures for tcp:NULL probes.
/// (service, cpes)
fn match_null_signatures(
    probe_id: &str,
    text: &str,
) -> anyhow::Result<Option<(String, Vec<String>)>> {
    let sigdb = crate::db::service::response_signatures_db();
    for sig in sigdb {
        if !sig.probe_id.eq_ignore_ascii_case(probe_id) {
            continue;
        }
        let re = match build_regex(&sig.regex, "") {
            Ok(r) => r,
            Err(_) => build_regex(&sig.regex, "i")?,
        };
        if let Some(caps) = re.captures(text) {
            let cpes = expand_cpe_templates(&sig.cpe, &caps);
            return Ok(Some((sig.service.clone(), cpes)));
        }
    }
    Ok(None)
}

/// Probe implementation for tcp:null (no payload)
pub struct NullProbe;

impl NullProbe {
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        // Pre-check
        if ctx.probe.probe_id != ServiceProbe::TcpNull {
            bail!(
                "NullProbe invoked with non-tcp:null probe_id: {:?}",
                ctx.probe.probe_id
            );
        }

        tracing::debug!("Null Probe: {}:{} - Connecting", ctx.ip, ctx.probe.port);
        let addr: SocketAddr = SocketAddr::new(ctx.ip, ctx.probe.port);
        let mut stream = timeout(ctx.timeout, TcpStream::connect(addr)).await??;

        tracing::debug!("Null Probe: {}:{} - Connected", ctx.ip, ctx.probe.port);

        // if payload is present, send it (should not happen for tcp:null, but just in case)
        let payload = PayloadBuilder::new(ctx.probe.clone())
            .payload(PayloadContext::default())
            .unwrap_or_default();
        if !payload.is_empty() {
            timeout(ctx.timeout, stream.write_all(&payload)).await??;
            stream.flush().await?;
        }

        // Apply idle/total timeout and max byte limit for reading
        let idle = ctx.timeout;
        let total = ctx.timeout;
        tracing::debug!(
            "Null Probe: {}:{} - Reading response(timeout: {})",
            ctx.ip,
            ctx.probe.port,
            total.as_millis()
        );
        let bytes = read_timeout(&mut stream, idle, total, ctx.max_read_size).await?;

        // Parse banner from response
        let banner = parse_banner(&bytes, 64 * 1024);

        tracing::debug!(
            "TCP NULL Probe: {}:{} - Banner: {:?}",
            ctx.ip,
            ctx.probe.port,
            banner.first_line
        );

        // Match signatures (tcp:NULL)
        let hit = match_null_signatures("tcp:NULL", &banner.raw_text)?;

        // Construct service info
        let mut svc = ServiceInfo::default();
        let tcp_svc_db = crate::db::service::tcp_service_db();
        svc.name = tcp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());
        if let Some((_service_name, cpes)) = hit {
            if !cpes.is_empty() {
                svc.cpes = cpes;
            }
        }
        // Even if name is still unknown, keep the banner
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
