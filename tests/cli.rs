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
