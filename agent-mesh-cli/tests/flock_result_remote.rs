//! `result` and `verdict` from a member attached over the bridge: the flock
//! directory there holds a pinned genesis and a proxy socket, not the home's
//! log, so the target must be resolved from the verified stream (PR-171).
#![cfg(unix)]
mod harness;

mod revocation_log;

use harness::{amesh, Proc};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;

fn line(r: &mut impl BufRead) -> String {
    let mut s = String::new();
    r.read_line(&mut s).unwrap();
    s.trim().to_owned()
}

struct Rig {
    home: TempDir,
    far: TempDir,
    dir: PathBuf,
    fdir: PathBuf,
    _procs: Vec<Proc>,
}

/// A session of `member` for the flock at `dir`, started from `cfg`.
fn session(cfg: &Path, dir: &Path, home: &Path, member: &str, procs: &mut Vec<Proc>) -> PathBuf {
    let token = amesh(home)
        .args(["flock", "invite", "--dir"])
        .arg(home.join("flocks").join("f"))
        .arg(member)
        .output()
        .unwrap();
    assert!(token.status.success());
    let token = String::from_utf8(token.stdout).unwrap().trim().to_owned();
    let mut child = amesh(cfg)
        .args(["flock", "session", "--member", member, "--allow-unlocked"])
        .arg("--dir")
        .arg(dir)
        .env("AMESH_FLOCK_TOKEN", token)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let _id = line(&mut out);
    let sock = line(&mut out);
    procs.push(Proc(child));
    sock.strip_prefix("socket: ").unwrap().into()
}

fn rig() -> (Rig, PathBuf, PathBuf, PathBuf) {
    let home = TempDir::new().unwrap();
    assert!(amesh(home.path()).arg("keygen").status().unwrap().success());
    revocation_log::ensure_log(home.path());
    let init = amesh(home.path())
        .args(["flock", "init", "--name", "f"])
        .args(["--member", "shep:shepherd", "--member", "h1:helper"])
        .args(["--member", "rev:reviewer"])
        .output()
        .unwrap();
    assert!(init.status.success());
    let id = String::from_utf8(init.stdout)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("flock id: ").map(str::to_owned))
        .unwrap();
    let dir = home.path().join("flocks").join("f");
    let mut procs = Vec::new();
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
    procs.push(Proc(serve));
    line(&mut out);
    line(&mut out);
    let bridge = line(&mut out);
    let p: Vec<&str> = bridge.split_whitespace().collect();
    let peer = format!("{}@127.0.0.1:{}", p[2], p[3]);

    let far = TempDir::new().unwrap();
    std::fs::copy(home.path().join("user.key"), far.path().join("user.key")).unwrap();
    revocation_log::copy_log(home.path(), far.path());
    let fdir = far.path().join("flocks").join("f");
    let mut attach = amesh(far.path())
        .args(["flock", "attach", "--id", &id, "--peer", &peer, "--dir"])
        .arg(&fdir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    line(&mut BufReader::new(attach.stdout.take().unwrap()));
    procs.push(Proc(attach));

    let shep = session(home.path(), &dir, home.path(), "shep", &mut procs);
    let h1 = session(far.path(), &fdir, home.path(), "h1", &mut procs);
    let rev = session(far.path(), &fdir, home.path(), "rev", &mut procs);
    (
        Rig {
            home,
            far,
            dir,
            fdir,
            _procs: procs,
        },
        shep,
        h1,
        rev,
    )
}

impl Rig {
    /// `amesh flock <args>` as the session `sock`, at home or far.
    fn run(&self, far: bool, sock: &Path, args: &[&str]) -> std::process::Output {
        let (cfg, dir) = if far {
            (self.far.path(), &self.fdir)
        } else {
            (self.home.path(), &self.dir)
        };
        amesh(cfg)
            .arg("flock")
            .arg(args[0])
            .arg("--dir")
            .arg(dir)
            .arg("--session")
            .arg(sock)
            .args(&args[1..])
            .output()
            .unwrap()
    }

    fn emit(&self, far: bool, sock: &Path, args: &[&str]) -> String {
        let o = self.run(far, sock, args);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned()
    }

    fn home_log(&self, shep: &Path) -> String {
        let o = self.run(false, shep, &["log"]);
        String::from_utf8(o.stdout).unwrap()
    }
}

#[test]
fn a_remote_member_closes_its_brief_and_review_by_id_and_by_lane_and_a_closed_one_is_refused() {
    let (r, shep, h1, rev) = rig();
    let b1 = r.emit(false, &shep, &["brief", "--to", "h1", "--lane", "l1"]);
    r.emit(true, &h1, &["take", &b1]);
    // by id, from the attached directory (no local log there)
    r.emit(true, &h1, &["result", &b1, "--outcome", "completed"]);
    assert!(
        !r.fdir.join("log").exists(),
        "the attached side has no local log"
    );
    // the fix round: by lane
    let b2 = r.emit(false, &shep, &["brief", "--to", "h1", "--lane", "l1"]);
    r.emit(true, &h1, &["take", &b2]);
    let before = r.home_log(&shep);
    let o = r.run(true, &h1, &["result", &b1, "--outcome", "completed"]);
    assert!(!o.status.success());
    let why = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(why.contains("already closed") && why.contains(&b2), "{why}");
    assert_eq!(r.home_log(&shep), before, "a conflict event was sent");
    r.emit(
        true,
        &h1,
        &["result", "--lane", "l1", "--outcome", "completed"],
    );
    assert!(!r.home_log(&shep).contains("conflict"));

    // a review
    let r1 = r.emit(
        false,
        &shep,
        &["review", "--to", "rev", "--lane", "l1", "--head", "aaa"],
    );
    r.emit(true, &rev, &["verdict", &r1, "--head", "aaa", "--reject"]);
    let r2 = r.emit(
        false,
        &shep,
        &["review", "--to", "rev", "--lane", "l1", "--head", "bbb"],
    );
    let before = r.home_log(&shep);
    let o = r.run(true, &rev, &["verdict", &r1, "--head", "aaa", "--approve"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains(&r2));
    assert_eq!(r.home_log(&shep), before);
    r.emit(
        true,
        &rev,
        &["verdict", "--lane", "l1", "--head", "bbb", "--approve"],
    );
    assert!(!r.home_log(&shep).contains("conflict"));
}
