use crate::{
    endpoint::ServiceInfo,
    service::{
        probe::{
            PortProbeResult, ProbeContext, ServiceProbe,
            tls::{SkipServerVerification, extract_tls_info},
        },
        read_timeout,
    },
};
use anyhow::{Result, ensure};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;

fn request(host: &str, port: u16) -> Result<Vec<u8>> {
    ensure!(
        !host.is_empty() && !host.chars().any(|c| c.is_control() || c.is_whitespace()),
        "invalid HTTP host"
    );
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(format!(
        "GET / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: nscan/{}\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes())
}

fn parse_response(bytes: &[u8]) -> Result<ServiceInfo> {
    let raw = String::from_utf8_lossy(bytes).into_owned();
    let mut lines = raw.lines();
    let status = lines.next().unwrap_or("");
    let mut words = status.split_whitespace();
    ensure!(
        matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1")),
        "not an HTTP/1 response"
    );
    let code = words.next().unwrap_or("").parse::<u16>()?;
    ensure!((100..=599).contains(&code), "invalid HTTP status code");
    let server = lines.take_while(|line| !line.is_empty()).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("server")
            .then(|| value.trim().to_string())
    });
    Ok(ServiceInfo {
        name: Some("http".into()),
        banner: Some(status.to_string()),
        server_header: server,
        raw: Some(raw),
        ..Default::default()
    })
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    ctx: &ProbeContext,
) -> Result<ServiceInfo> {
    timeout(ctx.timeout, stream.write_all(payload)).await??;
    let response = read_timeout(stream, ctx.timeout, ctx.timeout, ctx.max_read_size).await?;
    parse_response(&response)
}

pub struct HttpProbe;
impl HttpProbe {
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        let host = ctx.hostname.clone().unwrap_or_else(|| ctx.ip.to_string());
        let payload = request(&host, ctx.probe.port)?;
        let mut tcp = timeout(ctx.timeout, TcpStream::connect((ctx.ip, ctx.probe.port))).await??;
        let service = if ctx.probe.probe_id == ServiceProbe::TcpHTTPSGet {
            let mut roots = RootCertStore::empty();
            if !ctx.skip_cert_verify {
                for cert in rustls_native_certs::load_native_certs().certs {
                    let _ = roots.add(cert);
                }
            }
            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.enable_sni = ctx.sni;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            if ctx.skip_cert_verify {
                config
                    .dangerous()
                    .set_certificate_verifier(SkipServerVerification::new());
            }
            let mut tls = timeout(
                ctx.timeout,
                TlsConnector::from(Arc::new(config)).connect(ServerName::try_from(host)?, tcp),
            )
            .await??;
            let info = extract_tls_info(&ctx, tls.get_ref().1);
            let mut service = exchange(&mut tls, &payload, &ctx).await?;
            service.tls_info = info;
            service
        } else {
            exchange(&mut tcp, &payload, &ctx).await?
        };
        Ok(ctx.result(service))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_observations_are_not_product_identification() {
        let result = parse_response(b"HTTP/1.1 200 OK\r\nServer: custom\r\n\r\nbody").unwrap();
        assert_eq!(result.server_header.as_deref(), Some("custom"));
        assert!(result.product.is_none());
        assert!(result.cpes.is_empty());
        assert!(parse_response(b"SSH-2.0-test\r\n").is_err());
        assert!(request("a\r\nInjected: value", 80).is_err());
        assert!(
            String::from_utf8(request("::1", 8080).unwrap())
                .unwrap()
                .contains("Host: [::1]:8080")
        );
    }
}
