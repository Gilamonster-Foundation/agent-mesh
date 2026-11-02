//! `amesh flock serve --bridge` and `amesh flock attach`, as real processes:
//! two homes (two config dirs holding the same user key, as two hosts of one
//! user would), a flock served at one and attached at the other.
#![cfg(unix)]
mod harness;

mod revocation_log;

use harness::{amesh, Proc};
use std::io::{BufRead, BufReader};
use std::process::Stdio;
use tempfile::TempDir;

fn line(r: &mut impl BufRead) -> String {
    let mut s = String::new();
    r.read_line(&mut s).unwrap();
    s.trim().to_owned()
}

#[test]
fn a_flock_served_at_one_host_is_attached_enrolled_and_used_from_another() {
    // home host: a flock, served with its attach socket and a bridge
    let home = TempDir::new().unwrap();
    assert!(amesh(home.path()).arg("keygen").status().unwrap().success());
    revocation_log::ensure_log(home.path());
    let init = amesh(home.path())
        .args(["flock", "init", "--name", "f"])
        .args(["--member", "shep:shepherd", "--member", "h1:helper"])
        .output()
        .unwrap();
    assert!(init.status.success());
    let id = String::from_utf8(init.stdout)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("flock id: ").map(str::to_owned))
        .unwrap();
    let dir = home.path().join("flocks").join("f");
    let mut serve = amesh(home.path())
        .args([
            "flock",
            "serve",
            "--attach",
            "--bridge",
            "--bridge-quiet",
            "--dir",
        ])
        .arg(&dir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(serve.stdout.take().unwrap());
    let _serve = Proc(serve);
    assert!(line(&mut out).starts_with("serving"));
    assert!(line(&mut out).starts_with("attach"));
    let bridge = line(&mut out);
    let parts: Vec<&str> = bridge.split_whitespace().collect();
    assert_eq!(parts[0], "bridge", "{bridge}");
    let peer = format!("{}@127.0.0.1:{}", parts[2], parts[3]);

    // the other host: the same user, its own config dir and flock directory
    let far = TempDir::new().unwrap();
    std::fs::copy(home.path().join("user.key"), far.path().join("user.key")).unwrap();
    revocation_log::copy_log(home.path(), far.path());
    let fdir = far.path().join("flocks").join("f");

    // a wrong id is refused and nothing is written
    let wrong = amesh(far.path())
        .args([
            "flock",
            "attach",
            "--id",
            &format!("{}x", &id[..id.len() - 1]),
            "--peer",
            &peer,
            "--dir",
        ])
        .arg(&fdir)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(!fdir.join("genesis").exists());

    // the right id: genesis pinned, the local socket served
    let mut attach = amesh(far.path())
        .args(["flock", "attach", "--id", &id, "--peer", &peer, "--dir"])
        .arg(&fdir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut aout = BufReader::new(attach.stdout.take().unwrap());
    let _attach = Proc(attach);
    assert!(line(&mut aout).starts_with("serving"));
    assert!(fdir.join("genesis").exists());

    // the owner mints a token at home; the far host enrols with it
    let token = amesh(home.path())
        .args(["flock", "invite", "--dir"])
        .arg(&dir)
        .arg("h1")
        .output()
        .unwrap();
    assert!(token.status.success());
    let token = String::from_utf8(token.stdout).unwrap().trim().to_owned();
    let mut session = amesh(far.path())
        .args([
            "flock",
            "session",
            "--member",
            "h1",
            "--allow-unlocked",
            "--dir",
        ])
        .arg(&fdir)
        .env("AMESH_FLOCK_TOKEN", token)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut sout = BufReader::new(session.stdout.take().unwrap());
    let _session = Proc(session);
    let _id = line(&mut sout);
    let sock = line(&mut sout);
    let sock = sock.strip_prefix("socket: ").unwrap().to_owned();

    // a job from the far host lands in the home log
    let run = amesh(far.path())
        .args(["flock", "run", "--lane", "l", "--session", &sock, "--dir"])
        .arg(&fdir)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let log = amesh(home.path())
        .args(["flock", "log", "--dir"])
        .arg(&dir)
        .output()
        .unwrap();
    let log = String::from_utf8(log.stdout).unwrap();
    assert!(log.contains(" job ") && log.contains(" job-end "), "{log}");
}

#[test]
fn the_bridge_needs_the_attach_socket() {
    let home = TempDir::new().unwrap();
    let o = amesh(home.path())
        .args(["flock", "serve", "--bridge", "--dir", "/nonexistent"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("--attach"));
}
