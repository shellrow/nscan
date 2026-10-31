use std::process::Command;

fn nscan() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nscan"))
}

#[test]
fn invalid_inputs_fail_without_network_access() {
    for args in [
        vec!["port", "127.0.0.1", "--concurrency", "0"],
        vec!["domain", "example.invalid", "--concurrency", "0"],
        vec!["port", "127.0.0.1", "--proto", "udp"],
        vec!["port", "127.0.0.1", "--ports", "0"],
        vec!["port", "127.0.0.1", "--ports", "top-100"],
        vec!["port", "127.0.0.1", "--proto", "quic", "--nmap"],
        vec!["port", "127.0.0.1", "--service-probe", "http"],
        vec!["port", "127.0.0.1", "-S", "--service-probe", "quic"],
        vec!["port", "::/0"],
        vec!["port", "127.0.0.1", "--proto", "quic", "--method", "syn"],
    ] {
        let output = nscan().args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn interface_output_obeys_stdout_and_reports_save_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("interfaces.json");
    let output = nscan()
        .args(["--quiet", "--no-stdout", "--output"])
        .arg(&path)
        .args(["interface", "--all"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(json.is_array());
    let output = nscan()
        .args(["--quiet", "--no-stdout", "--output"])
        .arg(dir.path().join("missing/result.json"))
        .args(["interface", "--all"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn logging_setup_errors_are_visible() {
    let dir = tempfile::tempdir().unwrap();
    let output = nscan()
        .arg("--log-file-path")
        .arg(dir.path())
        .args(["interface", "--all"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to initialize logging"));
}

#[test]
fn basic_scan_does_not_need_nmap_or_signature_databases() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("scan.json");
    let missing_nmap = dir.path().join("missing-nmap");
    let output = nscan()
        .args([
            "port",
            "127.0.0.1",
            "-p",
            &port,
            "--quiet",
            "--no-stdout",
            "--output",
        ])
        .arg(&output_path)
        .arg("--nmap-path")
        .arg(&missing_nmap)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(json["endpoints"]["127.0.0.1"]["ports"][0]["state"], "open");
    assert!(json.get("identification").is_none());

    let output = nscan()
        .args(["port", "127.0.0.1", "-p", &port, "--nmap", "--nmap-path"])
        .arg(&missing_nmap)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Nmap unavailable"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("state: Open"));
}

#[cfg(unix)]
mod external_identification {
    use super::*;
    use std::{fs, net::TcpListener, os::unix::fs::PermissionsExt};

    fn fake_nmap(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("fake nmap");
        fs::write(&path, format!("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n echo 'Nmap version 7.99 (test)'\n exit 0\nfi\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn external_result_is_merged_with_basic_observations() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_nmap(
            dir.path(),
            &format!(
                r#"cat <<'XML'
<nmaprun scanner="nmap" version="7.99"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="{port}"><state state="closed"/><service name="example" product="External Product" method="probed"/></port></ports><os><osmatch name="External OS" accuracy="90"/></os></host><runstats><finished exit="success"/></runstats></nmaprun>
XML"#
            ),
        );
        let path = dir.path().join("scan.json");
        let output = nscan()
            .args([
                "port",
                "127.0.0.1",
                "-p",
                &port,
                "--nmap",
                "--os-detect",
                "--nmap-path",
            ])
            .arg(fake)
            .args(["--output"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(json["endpoints"]["127.0.0.1"]["ports"][0]["state"], "open");
        assert_eq!(
            json["endpoints"]["127.0.0.1"]["ports"][0]["service"]["product"],
            "External Product"
        );
        assert_eq!(json["identification"]["version"], "7.99");
        assert_eq!(json["identification"]["complete"], true);
        assert_eq!(
            json["endpoints"]["127.0.0.1"]["ports"][0]["service"]["product"],
            "External Product"
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("External Product"));
        assert!(text.contains("External OS"));
        assert_eq!(text.matches("External Product").count(), 1);
        assert_eq!(text.matches("External OS").count(), 1);
        assert!(!text.contains("Nmap 7.99"));
        assert!(json["identification"].get("hosts").is_none());
    }

    #[test]
    fn failures_warn_and_keep_basic_results_with_successful_exit() {
        for body in [
            "echo failure >&2; exit 1",
            "echo '<invalid'",
            "exec sleep 10",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port().to_string();
            let dir = tempfile::tempdir().unwrap();
            let fake = fake_nmap(dir.path(), body);
            let path = dir.path().join("scan.json");
            let started = std::time::Instant::now();
            let output = nscan()
                .args(["port", "127.0.0.1", "-p", &port, "--nmap", "--nmap-path"])
                .arg(fake)
                .args(["--nmap-timeout-ms", "50", "--output"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
            assert!(output.status.success());
            let json: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(json["endpoints"]["127.0.0.1"]["ports"][0]["state"], "open");
            assert_eq!(json["identification"]["complete"], false);
            assert!(json["identification"]["error"].is_string());
            assert!(String::from_utf8_lossy(&output.stdout).contains("state: Open"));
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("Optional identification incomplete")
            );
        }
    }
}
