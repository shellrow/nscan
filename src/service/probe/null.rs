use crate::{
    endpoint::ServiceInfo,
    service::{
        probe::{PortProbeResult, ProbeContext},
        read_timeout,
    },
};
use anyhow::Result;
use tokio::{net::TcpStream, time::timeout};

/// Read a server greeting without sending application data.
pub struct NullProbe;
impl NullProbe {
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        let mut stream =
            timeout(ctx.timeout, TcpStream::connect((ctx.ip, ctx.probe.port))).await??;
        let bytes = read_timeout(&mut stream, ctx.timeout, ctx.timeout, ctx.max_read_size).await?;
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        let banner = raw.lines().next().unwrap_or("").to_string();
        let name = if banner.starts_with("SSH-2.0-") || banner.starts_with("SSH-1.99-") {
            Some("ssh".into())
        } else {
            None
        };
        Ok(ctx.result(ServiceInfo {
            name,
            banner: Some(banner),
            raw: Some(raw),
            ..Default::default()
        }))
    }
}
