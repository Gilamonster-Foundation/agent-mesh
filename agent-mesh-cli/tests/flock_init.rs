//! `amesh flock init`: mints the server key and genesis, once.
#![cfg(unix)]

use agent_mesh_flock_server::{Server, ServerOnly};
use assert_cmd::Command;
use predicates::str::contains;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn amesh(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("amesh").unwrap();
    cmd.arg("--home").arg(home.path());
    cmd
}

fn init(home: &TempDir) -> assert_cmd::assert::Assert {
    amesh(home)
        .args(["flock", "init", "--name", "f"])
        .args(["--member", "shep:shepherd", "--member", "h1:helper"])
        .assert()
}

#[test]
fn init_mints_a_0600_key_and_a_genesis_the_server_reopens() {
    let home = TempDir::new().unwrap();
    amesh(&home).arg("keygen").assert().success();
    let out = init(&home)
        .success()
        .stdout(contains("flock id:"))
        .get_output()
        .stdout
        .clone();
    let dir = home.path().join("flocks").join("f");
    let mode = std::fs::metadata(dir.join("server.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let server = Server::open(&dir, Box::new(ServerOnly)).unwrap();
    assert!(String::from_utf8(out)
        .unwrap()
        .contains(&server.flock().to_string()));
}

#[test]
fn init_refuses_a_second_time_and_a_missing_user_key() {
    let home = TempDir::new().unwrap();
    init(&home).failure().stderr(contains("keygen"));
    amesh(&home).arg("keygen").assert().success();
    init(&home).success();
    init(&home).failure().stderr(contains("already"));
}

#[test]
fn init_rejects_a_bad_member_spec() {
    let home = TempDir::new().unwrap();
    amesh(&home).arg("keygen").assert().success();
    amesh(&home)
        .args(["flock", "init", "--name", "f", "--member", "shep"])
        .assert()
        .failure()
        .stderr(contains("name:role"));
    amesh(&home)
        .args(["flock", "init", "--name", "f", "--member", "shep:captain"])
        .assert()
        .failure()
        .stderr(contains("role"));
}
