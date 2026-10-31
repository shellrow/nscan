//! End-to-end tests against local, deterministic protocol servers.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tls_config(alpn: &[u8]) -> rustls::ServerConfig {
    // This public test key is used only by ephemeral loopback listeners.
    let cert = CertificateDer::from(include_bytes!("fixtures/localhost-cert.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/localhost-key.der").to_vec(),
    ));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

async fn scan(addr: SocketAddr, extra: &[&str]) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scan result.json");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_nscan"));
    command
        .kill_on_drop(true)
        .args([
            "port",
            &addr.ip().to_string(),
            "-p",
            &addr.port().to_string(),
        ])
        .args(["--quiet", "--no-stdout", "--output"])
        .arg(&path)
        .args(extra);
    let output = tokio::time::timeout(Duration::from_secs(20), command.output())
        .await
        .expect("scan must terminate")
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn default_connect_scan_distinguishes_open_and_closed_on_both_ip_families() {
    for ip in ["127.0.0.1", "::1"] {
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let report = scan(addr, &[]).await;
        assert_eq!(report["endpoints"][ip]["ports"][0]["state"], "open");
        // Reserve a port without listening so parallel tests cannot reuse it.
        let closed = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4().unwrap()
        } else {
            tokio::net::TcpSocket::new_v6().unwrap()
        };
        closed.bind(SocketAddr::new(addr.ip(), 0)).unwrap();
        let report = scan(closed.local_addr().unwrap(), &[]).await;
        assert_eq!(report["endpoints"][ip]["ports"][0]["state"], "closed");
        assert_eq!(report["stats"]["open_ports"], 0);
    }
}

#[tokio::test]
async fn http_https_and_tls_probes_observe_local_services() {
    for (mode, ip) in [
        ("http", "127.0.0.1"),
        ("http", "::1"),
        ("https", "127.0.0.1"),
        ("tls", "::1"),
    ] {
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config(b"http/1.1")));
        let server = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tasks.spawn(async move {
                    if mode == "http" {
                        respond(socket).await;
                    } else if let Ok(stream) = acceptor.accept(socket).await {
                        respond(stream).await;
                    }
                });
            }
        });
        let report = scan(
            addr,
            &[
                "-S",
                "--service-probe",
                mode,
                "--sni",
                "localhost",
                "--read-timeout-ms",
                "1000",
            ],
        )
        .await;
        server.abort();
        let port = &report["endpoints"][ip]["ports"][0];
        assert_eq!(port["state"], "open");
        let service = &port["service"];
        if mode != "tls" {
            assert_eq!(service["name"], "http");
            assert_eq!(service["server_header"], "nscan-test-server");
        }
        if mode != "http" {
            assert_eq!(service["tls_info"]["subject"], "localhost");
            assert!(service["tls_info"]["version"].is_string());
        }
        assert!(service["product"].is_null());
    }
}

async fn respond<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut stream: S) {
    let mut request = [0; 4096];
    if let Ok(Ok(size)) =
        tokio::time::timeout(Duration::from_secs(3), stream.read(&mut request)).await
        && size > 0
    {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nServer: nscan-test-server\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await;
        let _ = stream.shutdown().await;
    }
}

#[tokio::test]
async fn quic_http3_probe_and_combined_transport_reports() {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config(b"h3")).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        while let Some(incoming) = endpoint.accept().await {
            tasks.spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok(mut h3) = h3::server::Connection::<_, bytes::Bytes>::new(
                    h3_quinn::Connection::new(connection),
                )
                .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    let Ok((request, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    assert_eq!(
                        request.uri().authority().unwrap().as_str(),
                        format!("localhost:{}", addr.port())
                    );
                    let response = http::Response::builder()
                        .status(200)
                        .header("server", "nscan-http3-test")
                        .body(())
                        .unwrap();
                    if stream.send_response(response).await.is_err() {
                        return;
                    }
                    let _ = stream.finish().await;
                }
            });
        }
    });
    let report = scan(
        addr,
        &[
            "--proto",
            "quic",
            "-S",
            "--sni",
            "localhost",
            "--connect-timeout-ms",
            "2000",
            "--read-timeout-ms",
            "2000",
        ],
    )
    .await;
    let port = &report["endpoints"]["127.0.0.1"]["ports"][0];
    assert_eq!(port["state"], "open");
    assert_eq!(port["service"]["name"], "http");
    assert_eq!(port["service"]["server_header"], "nscan-http3-test");
    assert_eq!(port["service"]["tls_info"]["alpn"], "h3");
    let combined = scan(
        addr,
        &[
            "--quic",
            "--sni",
            "localhost",
            "--connect-timeout-ms",
            "2000",
        ],
    )
    .await;
    assert_eq!(combined["stats"]["ports_scanned"], 2);
    assert_eq!(combined["stats"]["open_ports"], 2);
    drop(tcp);
    server.abort();
}
