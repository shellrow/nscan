use crate::{output::ScanResult, probe::ProbeSetting};
use anyhow::Result;

/// Discover hosts using routed raw probes.
pub async fn run_host_scan(setting: ProbeSetting) -> Result<ScanResult> {
    crate::scan::raw::run(setting, crate::scan::raw::Kind::Icmp, false).await
}
