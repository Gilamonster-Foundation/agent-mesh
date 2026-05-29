//! Integration tests for the `amesh` CLI.
//!
//! Each test gets an isolated tempdir as `$AMESH_HOME` (passed via
//! `--home`) so it never touches the user's real `~/.agent-mesh`.

use assert_cmd::Command;
use predicates::str::contains;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tempfile::TempDir;

fn fresh_ssh_key_pem() -> (PrivateKey, String) {
    let key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519)
        .expect("generate ssh ed25519");
    let pem = key.to_openssh(LineEnding::LF).expect("encode openssh");
    (key, pem.to_string())
}

#[test]
fn keygen_creates_user_key() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success()
        .stdout(contains("generated user key"))
        .stdout(contains("fingerprint:"));

    assert!(dir.path().join("user.key").exists());
}

#[test]
fn keygen_refuses_overwrite() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn whoami_without_key_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "whoami"])
        .assert()
        .failure()
        .stderr(contains("run `amesh keygen` first"));
}

#[test]
fn whoami_prints_fingerprint() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "whoami"])
        .assert()
        .success()
        .stdout(contains("user fingerprint:"))
        .stdout(contains("github binding:   none"));
}

#[test]
fn bind_github_with_generated_ssh_key() {
    let dir = TempDir::new().unwrap();

    // Generate a fresh SSH ed25519 key in a tempfile (no real
    // private material on disk after the test).
    let (_ssh, pem) = fresh_ssh_key_pem();
    let ssh_path = dir.path().join("test_ssh_key");
    std::fs::write(&ssh_path, pem.as_bytes()).unwrap();

    // Generate the user key.
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();

    // Bind to "github".
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "bind",
            "github",
            "--ssh-key",
            ssh_path.to_str().unwrap(),
            "--username",
            "testuser",
        ])
        .assert()
        .success()
        .stdout(contains("github binding written"))
        .stdout(contains("username hint: testuser"));

    // Whoami should now surface the binding.
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "whoami"])
        .assert()
        .success()
        .stdout(contains("github binding:   testuser"));

    // The sig file landed where we expect.
    assert!(dir.path().join("user.github.sig").exists());
}

#[test]
fn bind_github_without_user_key_fails() {
    let dir = TempDir::new().unwrap();
    let (_ssh, pem) = fresh_ssh_key_pem();
    let ssh_path = dir.path().join("test_ssh_key");
    std::fs::write(&ssh_path, pem.as_bytes()).unwrap();

    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "bind",
            "github",
            "--ssh-key",
            ssh_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("run `amesh keygen` first"));
}

#[test]
fn bind_github_rejects_garbage_ssh_file() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();
    let ssh_path = dir.path().join("bad_ssh_key");
    std::fs::write(&ssh_path, b"not an openssh key").unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "bind",
            "github",
            "--ssh-key",
            ssh_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("parse SSH key"));
}

#[test]
fn help_lists_subcommands() {
    Command::cargo_bin("amesh")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("keygen"))
        .stdout(contains("bind"))
        .stdout(contains("whoami"))
        .stdout(contains("verify"));
}

#[test]
fn verify_fails_on_missing_binding_file() {
    // Drives `amesh verify` to its first I/O error — no network is
    // touched because the file read fails first. Phase 0 covers the
    // remaining verify paths via `GitHubBinding::verify` unit tests
    // in `agent-mesh-core::github_binding::tests`; a full end-to-end
    // verify test would need a `--keys-url` flag we deliberately
    // haven't shipped yet.
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "verify",
            "--binding",
            dir.path().join("nope.json").to_str().unwrap(),
            "--github-user",
            "octocat",
        ])
        .assert()
        .failure()
        .stderr(contains("read binding"));
}

#[test]
fn verify_fails_on_garbage_binding_file() {
    let dir = TempDir::new().unwrap();
    let binding_path = dir.path().join("garbage.json");
    std::fs::write(&binding_path, b"not json").unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "verify",
            "--binding",
            binding_path.to_str().unwrap(),
            "--github-user",
            "octocat",
        ])
        .assert()
        .failure();
}
