use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use crate::service::probe::{PayloadEncoding, PortProbe};

/// Context for building payloads
#[derive(Default, Clone)]
pub struct PayloadContext<'a> {
    pub hostname: Option<&'a str>,
    pub path: Option<&'a str>,
}

/// Payload builder for service detection
pub struct PayloadBuilder {
    pub probe: PortProbe,
}

impl PayloadBuilder {
    pub fn new(probe: PortProbe) -> Self {
        PayloadBuilder { probe }
    }

    /// Decode payload bytes (raw/base64). Returns error on decode failure.
    pub fn payload(&self, ctx: PayloadContext) -> Result<Vec<u8>> {
        match self.probe.payload_encoding {
            PayloadEncoding::Raw => {
                let mut s = self.probe.payload.clone();

                if s.contains("$HOST") {
                    let host = ctx.hostname.ok_or_else(|| {
                        anyhow::anyhow!("probe {} requires hostname (found $HOST in payload)", self.probe.probe_id.as_str())
                    })?;
                    s = s.replace("$HOST", host);
                }
                if s.contains("$PATH") {
                    let path = ctx.path.unwrap_or("/");
                    s = s.replace("$PATH", path);
                }

                Ok(s.into_bytes())
            }
            PayloadEncoding::Base64 => {
                general_purpose::STANDARD
                    .decode(&self.probe.payload)
                    .map_err(|e| anyhow::anyhow!("base64 decode failed for {}: {}", self.probe.probe_id.as_str(), e))
            }
        }
    }
}
