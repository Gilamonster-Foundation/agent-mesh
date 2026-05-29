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
        .stdout(contains("verify"))
        .stdout(contains("announce"))
        .stdout(contains("peers"));
}

#[test]
fn announce_help_shows_capability_flag() {
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["announce", "--help"])
        .assert()
        .success()
        .stdout(contains("--capability"))
        .stdout(contains("--role"))
        .stdout(contains("--host"))
        .stdout(contains("--duration"));
}

#[test]
fn peers_help_shows_listen_flag() {
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["peers", "--help"])
        .assert()
        .success()
        .stdout(contains("--listen"))
        .stdout(contains("--same-user"));
}

#[test]
fn announce_without_user_key_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "announce",
            "--duration",
            "1s",
        ])
        .assert()
        .failure()
        .stderr(contains("run `amesh keygen` first"));
}

#[test]
fn peers_without_user_key_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "peers",
            "--listen",
            "100ms",
        ])
        .assert()
        .failure()
        .stderr(contains("run `amesh keygen` first"));
}

#[test]
fn announce_for_duration_exits_cleanly() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "announce",
            "--capability",
            "test",
            "--role",
            "test-worker",
            "--duration",
            "500ms",
        ])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(contains("announcing as agent_fp="))
        .stdout(contains("role=test-worker"));
}

#[test]
fn peers_with_no_announcers_prints_header() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "peers",
            "--listen",
            "300ms",
        ])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(contains("listening for peers"))
        .stdout(contains("AGENT"))
        .stdout(contains("ROLE@HOST"));
}

#[test]
fn peers_with_same_user_filter_renders() {
    // Run announce + peers in sequence within the same $AMESH_HOME so
    // the peers command sees a same_user peer (the announcer used the
    // same user.key). The two commands run sequentially with overlap:
    // we use shell-style `sh -c` only for the inline orchestration.
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();

    // Spawn an announcer that runs for 3s in the background.
    let announcer_bin = assert_cmd::cargo::cargo_bin("amesh");
    let mut announcer = std::process::Command::new(&announcer_bin)
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "announce",
            "--capability",
            "ollama",
            "--role",
            "test-role",
            "--duration",
            "3s",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn announcer");

    // Give it a moment to start advertising before we browse.
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Now run peers --same-user; should see ourselves.
    let output = Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "peers",
            "--listen",
            "2s",
            "--same-user",
        ])
        .timeout(std::time::Duration::from_secs(15))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    let _ = announcer.wait();

    // We may or may not see ourselves within 2s on every CI runner,
    // but the table header must always render.
    assert!(stdout.contains("AGENT"));
    assert!(stdout.contains("ROLE@HOST"));
    assert!(stdout.contains("discovered "));
    // If we saw ourselves at all, SAME?=yes should appear since we
    // filtered to same-user-only.
    if stdout.contains("test-role@") {
        assert!(stdout.contains("yes"));
        assert!(stdout.contains("ollama"));
    }
}

#[test]
fn announce_rejects_invalid_duration() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "announce",
            "--duration",
            "forever",
        ])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .failure()
        .stderr(contains("invalid duration"));
}

#[test]
fn peers_rejects_invalid_listen_duration() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("amesh")
        .unwrap()
        .args(["--home", dir.path().to_str().unwrap(), "keygen"])
        .assert()
        .success();
    Command::cargo_bin("amesh")
        .unwrap()
        .args([
            "--home",
            dir.path().to_str().unwrap(),
            "peers",
            "--listen",
            "always",
        ])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .failure()
        .stderr(contains("invalid duration"));
}

#[test]
fn verify_fails_on_missing_binding_file() {
    // Drives `amesh verify` to its first I/O error — no network is
    // touched because the file read fails first. Phase 0 covers the
    // remaining verify paths via `GitHubBinding::verify` unit tests
    // in `agent-mesh-protocol::github_binding::tests`; a full end-to-end
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
