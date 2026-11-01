use crate::ping::{result::PingResult, setting::PingSetting};
use anyhow::Result;

/// Run routed, correlated raw ping probes.
pub async fn run_tcp_ping(setting: &PingSetting) -> Result<PingResult> {
    crate::scan::raw::ping(setting, crate::scan::raw::Kind::Tcp).await
}
