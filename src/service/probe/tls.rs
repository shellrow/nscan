use crate::endpoint::ServiceInfo;
use crate::endpoint::TlsInfo;
use crate::service::probe::{PortProbeResult, ProbeContext};
use anyhow::Result;
use rustls::ClientConnection;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore},
};
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
pub struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Extract TLS info from a ClientConnection
pub fn extract_tls_info(
    probe_ctx: &ProbeContext,
    client_conn: &ClientConnection,
) -> Option<TlsInfo> {
    let mut tls_info = TlsInfo::default();
    if let Some(version) = client_conn.protocol_version() {
        if let Some(version) = version.as_str() {
            tls_info.version = Some(version.to_string());
        }
    }
    if let Some(cs) = client_conn.negotiated_cipher_suite() {
        if let Some(cs) = cs.suite().as_str() {
            tls_info.cipher_suite = Some(cs.to_string());
        }
    }
    if let Some(alpn) = client_conn.alpn_protocol() {
        tls_info.alpn = Some(String::from_utf8_lossy(alpn).to_string());
    }

    if let Some(cert) = client_conn
        .peer_certificates()
        .and_then(|v| v.first())
        .cloned()
    {
        tls_info.sni = probe_ctx.hostname.clone();
        match X509Certificate::from_der(&cert) {
            Ok((_, x509)) => {
                // Subject
                let subject = x509
                    .subject()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(|s| s.to_string());

                // Issuer
                let issuer = x509
                    .issuer()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(|s| s.to_string());

                // SAN (Subject Alternative Name)
                let mut san_list = Vec::new();
                for ext in x509.extensions() {
                    if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                        for name in san.general_names.iter() {
                            san_list.push(name.to_string());
                        }
                    }
                }

                tls_info.subject = subject;
                tls_info.issuer = issuer;
                tls_info.san_list = san_list;
                tls_info.not_before = Some(x509.validity().not_before.to_string());
                tls_info.not_after = Some(x509.validity().not_after.to_string());
                tls_info.serial_hex = Some(x509.raw_serial_as_string());
                let sig_alg_name = crate::db::tls::oid_sig_name(
                    x509.signature_algorithm.oid().to_id_string().as_str(),
                );
                tls_info.sig_algorithm = Some(sig_alg_name);
                let pubkey_alg_name = crate::db::tls::oid_pubkey_name(
                    x509.public_key().algorithm.oid().to_id_string().as_str(),
                );
                tls_info.pubkey_algorithm = Some(pubkey_alg_name);
            }
            Err(e) => {
                tracing::warn!("Failed to parse certificate: {}", e);
            }
        }
    }
    Some(tls_info)
}

/// Probe implementation for tcp:tls
pub struct TlsProbe;

impl TlsProbe {
    /// Run the TLS probe with the given context.
    pub async fn run(ctx: ProbeContext) -> Result<PortProbeResult> {
        let addr: SocketAddr = SocketAddr::new(ctx.ip, ctx.probe.port);
        let hostname = ctx.hostname.clone().unwrap_or_else(|| ctx.ip.to_string());
        let tcp_stream = timeout(ctx.timeout, TcpStream::connect(addr)).await??;

        // rustls config
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()? {
            let _ = roots.add(cert);
        }
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        if ctx.skip_cert_verify {
            config
                .dangerous()
                .set_certificate_verifier(SkipServerVerification::new());
        }

        let connector = TlsConnector::from(Arc::new(config));
        let sni_name = if ctx.sni {
            ServerName::try_from(hostname)?
        } else {
            ServerName::try_from("localhost")?
        };

        let tls_stream = timeout(ctx.timeout, connector.connect(sni_name, tcp_stream)).await??;
        let conn = tls_stream.get_ref().1; // server connection

        let mut svc = ServiceInfo::default();
        let tcp_svc_db = crate::db::service::tcp_service_db();
        svc.name = tcp_svc_db.get_name(ctx.probe.port).map(|s| s.to_string());

        svc.tls_info = crate::service::probe::tls::extract_tls_info(&ctx, &conn);

        let probe_result: PortProbeResult = PortProbeResult {
            ip: ctx.ip,
            hostname: ctx.hostname,
            port: ctx.probe.port,
            transport: ctx.probe.transport,
            probe_id: ctx.probe.probe_id,
            service_info: svc,
        };
        tracing::debug!("TLS Probe Result: {:?}", probe_result);
        return Ok(probe_result);
    }
}
