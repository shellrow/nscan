use anyhow::Result;
use bytes::{Buf, BytesMut};
use x509_parser::prelude::FromDer;
use std::{net::SocketAddr, sync::Arc};
use quinn::{ClientConfig, Endpoint};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use http::{Request, Method};

use crate::{
    endpoint::{ServiceInfo, TlsInfo},
    service::{
        probe::{ProbeContext, PortProbeResult, tls::SkipServerVerification},
    },
};

/// Create a QUIC client configuration with optional certificate verification skipping and ALPN protocols.
pub fn quic_client_config(skip_verify: bool, alpn: &[&[u8]]) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        let _ = roots.add(cert);
    }
    let mut tls = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if skip_verify {
        tls.dangerous().set_certificate_verifier(SkipServerVerification::new());
    }
    tls.enable_early_data = true;
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let client_conf = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    Ok(ClientConfig::new(Arc::new(client_conf)))
}

/// Probe implementation for UDP QUIC (with optional HTTP/3)
pub struct QuicProbe;

impl QuicProbe {
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        let addr = SocketAddr::new(ctx.ip, ctx.probe.port);
        let hostname = ctx.hostname.clone().unwrap_or_else(|| ctx.ip.to_string());
        let bind_addr: SocketAddr = if ctx.ip.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid QUIC bind address: {}", e))?;

        // Set ALPN protocols
        let alpn = [
            b"h3".as_slice(),
            b"h3-34".as_slice(), b"h3-33".as_slice(), b"h3-32".as_slice(), b"h3-31".as_slice(), b"h3-30".as_slice(), b"h3-29".as_slice(),
            b"hq-29".as_slice(),
        ];
        let client_cfg = quic_client_config(ctx.skip_cert_verify, &alpn)?;
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_cfg);

        // Connect to the server (SNI is hostname or "localhost")
        let server_name = if ctx.sni { hostname.as_str() } else { "localhost" };
        let connect_fut = endpoint.connect(addr, server_name)?;
        let quinn_conn = tokio::time::timeout(ctx.timeout, connect_fut).await??;

        // QUIC connection is established. Get ALPN
        let alpn_proto = match quinn_conn.handshake_data() {
            Some(data) => {
                match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
                    Ok(hd) => {
                        match hd.protocol {
                            Some(ref p) => Some(String::from_utf8_lossy(p).to_string()),
                            None => None,
                        }
                    },
                    Err(_) => None,
                }
            },
            None => None,
        };

        let cert_der_bytes: Option<Vec<u8>> = quinn_conn
            .peer_identity()
            .and_then(|any| any.downcast_ref::<Vec<rustls::pki_types::CertificateDer>>().cloned())
            .and_then(|vec_der| vec_der.into_iter().next())
            .map(|der| der.to_vec());

        // Construct TlsInfo
        let mut tls_info = TlsInfo::default();
        tls_info.alpn = alpn_proto.clone();
        // Fixed to TLS 1.3 for QUIC
        tls_info.version = Some("TLSv1_3".into());
        if let Some(bytes) = cert_der_bytes.as_deref() {
            if let Ok((_, x509)) = x509_parser::prelude::X509Certificate::from_der(bytes) {
                tls_info.subject = x509.subject()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(|s| s.to_string());
                tls_info.issuer = x509.issuer()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(|s| s.to_string());
                let mut sans = Vec::new();
                for ext in x509.extensions() {
                    if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                        for name in san.general_names.iter() {
                            sans.push(name.to_string());
                        }
                    }
                }
                tls_info.san_list = sans;
                tls_info.not_before = Some(x509.validity().not_before.to_string());
                tls_info.not_after  = Some(x509.validity().not_after.to_string());
                tls_info.serial_hex = Some(x509.raw_serial_as_string());
                tls_info.sig_algorithm = Some(crate::db::tls::oid_sig_name(
                    x509.signature_algorithm.oid().to_id_string().as_str(),
                ));
                tls_info.pubkey_algorithm = Some(crate::db::tls::oid_pubkey_name(
                    x509.public_key().algorithm.oid().to_id_string().as_str(),
                ));
            }
        }

        // If ALPN indicates HTTP/3, perform a simple GET request
        if let Some(alpn_s) = &alpn_proto {
            if alpn_s.starts_with("h3") {
                // HTTP/3 client initialization
                tracing::debug!("HTTP/3 Probe: {}:{} - Connecting", ctx.ip, ctx.probe.port);
                let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn);
                let (mut driver, mut send_request) = h3::client::new(h3_quinn_conn).await?;
                let drive = async move {
                    return Err::<(), h3::error::ConnectionError>(futures::future::poll_fn(|cx| driver.poll_close(cx)).await);
                };

                let request = async move {
                    let mut svc = ServiceInfo::default();
                    // Simple GET request
                    let req = Request::builder()
                        .method(Method::GET)
                        .uri("https://".to_string() + server_name + "/")
                        .header("Host", server_name)
                        .header("User-Agent", "nscan/0.1 (probe)")
                        .body(())
                        .map_err(|e| anyhow::anyhow!("failed to build HTTP/3 request: {}", e))?;

                    tracing::debug!("HTTP/3 Probe: {}:{} - Sending request", ctx.ip, ctx.probe.port);
                    // Send request
                    let mut stream = send_request.send_request(req).await?;
                    //let mut stream = tokio::time::timeout(ctx.timeout, send_request.send_request(req)).await??;
                    stream.finish().await?;

                    // Receive response (headers)
                    tracing::debug!("HTTP/3 Probe: {}:{} - Receiving response", ctx.ip, ctx.probe.port);
                    let res = stream.recv_response().await?;
                    // Extract status and Server headers
                    let udp_svc_db = crate::db::service::udp_service_db();
                    svc.name = udp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());
                    svc.banner = Some(format!("HTTP/3 {}", res.status()));
                    svc.quic_version = Some("1".into());
                    if let Some(val) = res.headers().get("server") {
                        if let Ok(s) = val.to_str() { 
                            svc.product = Some(s.to_string()); 
                        }
                    }

                    // receiving potential response body
                    let mut read = 0usize;
                    let max_body = 8 * 1024;
                    let mut body_bytes = BytesMut::new();
                    while let Some(chunk) = stream.recv_data().await? {
                        let bytes: &[u8] = chunk.chunk();
                        body_bytes.extend_from_slice(bytes);
                        read += bytes.len();
                        if read >= max_body { break; }
                    }

                    svc.raw = Some(format!("alpn=h3; status={}", res.status()));

                    Ok::<ServiceInfo, anyhow::Error>(svc)
                };

                let (req_res, _drive_res) = tokio::join!(request, drive);
                match req_res {
                    Ok(mut svc) => {
                        tracing::debug!("HTTP/3 Probe: {}:{} - Request succeeded", ctx.ip, ctx.probe.port);
                        tracing::debug!("HTTP/3 Probe Result: {:?}", svc);
                        svc.tls_info = Some(tls_info.clone());
                        let probe_result = PortProbeResult {
                            ip: ctx.ip,
                            hostname: ctx.hostname,
                            port: ctx.probe.port,
                            transport: ctx.probe.transport,
                            probe_id: ctx.probe.probe_id,
                            service_info: svc,
                        };
                        return Ok(probe_result);
                    },
                    Err(e) => {
                        tracing::error!("HTTP/3 Probe: {}:{} - Request failed: {}", ctx.ip, ctx.probe.port, e);
                    }
                }
            }
        }

        let mut svc = ServiceInfo::default();
        svc.name = Some("quic".into());
        svc.quic_version = Some("1".into());
        svc.tls_info = Some(tls_info);

        let probe_result = PortProbeResult {
            ip: ctx.ip,
            hostname: ctx.hostname,
            port: ctx.probe.port,
            transport: ctx.probe.transport,
            probe_id: ctx.probe.probe_id,
            service_info: svc,
        };

        // Wait for the connection to be closed
        endpoint.wait_idle().await;

        Ok(probe_result)
    }
}
