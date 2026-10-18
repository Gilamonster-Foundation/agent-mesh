//! `amesh flock serve --attach`: the attach socket exists only when asked for,
//! and is private to its owner.
#![cfg(unix)]
mod harness;

use harness::{amesh, flock, Proc};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use tempfile::TempDir;

#[test]
fn serve_attach_adds_a_private_attach_socket_and_nothing_else_does() {
    // without the flag there is nothing remote to reach
    let plain = flock();
    assert!(!plain.dir.join("run").join("attach.sock").exists());

    let home = TempDir::new().unwrap();
    assert!(amesh(home.path()).arg("keygen").status().unwrap().success());
    assert!(amesh(home.path())
        .args(["flock", "init", "--name", "f", "--member", "shep:shepherd"])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success());
    let dir = home.path().join("flocks").join("f");
    let mut serve = amesh(home.path())
        .args(["flock", "serve", "--attach", "--dir"])
        .arg(&dir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(serve.stdout.take().unwrap());
    let (mut a, mut b) = (String::new(), String::new());
    out.read_line(&mut a).unwrap();
    out.read_line(&mut b).unwrap();
    let _serve = Proc(serve);
    assert!(a.starts_with("serving"), "{a}");
    assert!(b.starts_with("attach"), "{b}");
    let sock = dir.join("run").join("attach.sock");
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // the owner still mints invites over the owner socket
    let inv = amesh(home.path())
        .args(["flock", "invite", "--dir"])
        .arg(&dir)
        .arg("shep")
        .output()
        .unwrap();
    assert!(inv.status.success());
}
