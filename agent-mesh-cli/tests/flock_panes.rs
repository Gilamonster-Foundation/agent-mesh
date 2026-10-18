//! `amesh flock panes` against a fake `herdr` on PATH: never the live one.
#![cfg(unix)]

use assert_cmd::Command;
use predicates::str::contains;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

const PANES: &str = r#"{"id":"x","result":{"panes":[
 {"pane_id":"w1:p1","tab_id":"w1:t1","label":"shep","agent":"claude","agent_status":"working"},
 {"pane_id":"w1:p2","tab_id":"w1:t1","label":"h1","agent":"newt","agent_status":"idle"},
 {"pane_id":"w1:p3","tab_id":"w1:t1","label":"reviewer","agent":"codex","agent_status":"idle"}]}}"#;

/// A `herdr` that records its arguments and prints `PANES`.
fn fake_herdr(bin: &TempDir) -> std::path::PathBuf {
    let calls = bin.path().join("calls");
    let script = format!(
        "#!/bin/sh\necho \"$*\" >> '{}'\ncat <<'EOF'\n{PANES}\nEOF\n",
        calls.display()
    );
    let path = bin.path().join("herdr");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    calls
}

#[test]
fn panes_joins_the_roster_to_labels_and_only_ever_lists() {
    let home = TempDir::new().unwrap();
    let bin = TempDir::new().unwrap();
    let calls = fake_herdr(&bin);
    let amesh = |args: &[&str]| {
        let mut c = Command::cargo_bin("amesh").unwrap();
        c.arg("--home").arg(home.path()).args(args);
        // The fake comes first, so the live herdr is never reached.
        c.env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()));
        c
    };
    amesh(&["keygen"]).assert().success();
    amesh(&[
        "flock",
        "init",
        "--name",
        "f",
        "--member",
        "shep:shepherd",
        "--member",
        "h1:helper",
        "--member",
        "h2:helper",
    ])
    .assert()
    .success();

    amesh(&["flock", "panes", "--name", "f"])
        .assert()
        .success()
        .stdout(contains("log ✓ 0"))
        .stdout(contains("shep"))
        .stdout(contains("w1:p1"))
        .stdout(contains("newt idle"))
        .stdout(contains("no pane")) // h2 has none
        .stdout(predicates::str::contains("reviewer").not()) // off the roster
        .stdout(predicates::str::contains("w1:p3").not());

    assert_eq!(std::fs::read_to_string(calls).unwrap(), "pane list\n");
}

use predicates::prelude::PredicateBooleanExt as _;

#[test]
fn hostile_member_names_and_herdr_text_are_printed_inert() {
    // a roster name, and a pane whose label, agent and status are all escape
    // sequences (herdr's text is untrusted too)
    let name = "ev\u{1b}]52;c;aGk=\u{7}il\nFORGED";
    let panes = r#"{"id":"x","result":{"panes":[
 {"pane_id":"w1:p\u001b[2J1","tab_id":"w1:t1","label":"ev\u001b]52;c;aGk=\u0007il\nFORGED","agent":"a\u001b[31mgent","agent_status":"\u001b]0;pwn\u0007idle\nFORGED"}]}}"#;
    let home = TempDir::new().unwrap();
    let bin = TempDir::new().unwrap();
    let script = format!("#!/bin/sh\ncat <<'EOF'\n{panes}\nEOF\n");
    let path = bin.path().join("herdr");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let amesh = |args: &[&str]| {
        let mut c = Command::cargo_bin("amesh").unwrap();
        c.arg("--home").arg(home.path()).args(args);
        c.env("PATH", format!("{}:/usr/bin:/bin", bin.path().display()));
        c
    };
    amesh(&["keygen"]).assert().success();
    amesh(&[
        "flock",
        "init",
        "--name",
        "f",
        "--member",
        &format!("{name}:helper"),
    ])
    .assert()
    .success();
    let out = amesh(&["flock", "panes", "--name", "f"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "a control character reached the terminal: {text:?}"
    );
    assert!(text.contains("ev\\x1b]52;c;aGk=\\x07il\\nFORGED"), "{text}");
    assert!(
        !text.lines().any(|l| l.starts_with("FORGED")),
        "a newline forged a line: {text:?}"
    );
}
