use std::io::Write;
use std::process::{Command, Output, Stdio};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../presign/tests/fixtures");

fn presign(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_presign"))
        .args(args)
        .env_remove("PRESIGN_RPC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn fixture(name: &str) -> String {
    format!("{FIXTURES}/{name}.json")
}

#[test]
fn bybit_exits_1_and_names_the_delegatecall() {
    let out = presign(&[&fixture("bybit_exec_transaction")], "");
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("verdict: CRITICAL"), "{text}");
    assert!(
        text.contains("0x96221423681A6d52E184D440a8eFCEbB105C7242"),
        "{text}"
    );
}

#[test]
fn harmless_request_exits_0() {
    let out = presign(&[&fixture("eth_transfer")], "");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn reads_stdin_and_prints_json() {
    let req = std::fs::read_to_string(fixture("permit_unlimited_unknown")).unwrap();
    let out = presign(&["--json"], &req);
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verdict"], "critical");
    assert!(v["hashes"]["signing"].as_str().unwrap().starts_with("0x"));
}

#[test]
fn bad_input_exits_2() {
    assert_eq!(presign(&[], "not json").status.code(), Some(2));
    assert_eq!(presign(&["--nope"], "").status.code(), Some(2));
    assert_eq!(presign(&["--rpc"], "").status.code(), Some(2));
    assert_eq!(presign(&["/no/such/file"], "").status.code(), Some(2));
}
