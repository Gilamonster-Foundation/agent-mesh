//! Shared by the `amesh flock` process tests: a server and one session per member.
#![allow(dead_code)]

use assert_cmd::cargo::cargo_bin;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use tempfile::TempDir;

/// A child that is killed when the test ends, pass or fail.
pub struct Proc(pub Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct Flock {
    pub home: TempDir,
    pub dir: PathBuf,
    pub _serve: Proc,
}

pub fn amesh(home: &Path) -> Command {
    let mut c = Command::new(cargo_bin("amesh"));
    c.arg("--home").arg(home);
    c
}

pub fn flock() -> Flock {
    flock_with(&["shep:shepherd", "h1:helper", "h2:helper", "rev:reviewer"])
}

pub fn flock_with(members: &[&str]) -> Flock {
    let home = TempDir::new().unwrap();
    assert!(amesh(home.path()).arg("keygen").status().unwrap().success());
    let mut init = amesh(home.path());
    init.args(["flock", "init", "--name", "f"]);
    for m in members {
        init.args(["--member", m]);
    }
    assert!(init.stdout(Stdio::null()).status().unwrap().success());
    let dir = home.path().join("flocks").join("f");
    let mut serve = amesh(home.path())
        .args(["flock", "serve", "--dir"])
        .arg(&dir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(serve.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.starts_with("serving"), "{line}");
    Flock {
        home,
        dir,
        _serve: Proc(serve),
    }
}

/// A session process and its socket.
pub struct Sess {
    pub proc: Proc,
    pub sock: PathBuf,
}

impl Flock {
    pub fn session(&self, member: &str) -> Sess {
        self.session_in(member, None)
    }

    /// A session started inside a herdr pane `(pane, tab)`, or outside one.
    pub fn session_in(&self, member: &str, pane: Option<(&str, &str)>) -> Sess {
        let inv = amesh(self.home.path())
            .args(["flock", "invite", "--dir"])
            .arg(&self.dir)
            .arg(member)
            .output()
            .unwrap();
        assert!(inv.status.success());
        let token = String::from_utf8(inv.stdout).unwrap().trim().to_owned();
        let mut child = amesh(self.home.path());
        child
            .args(["flock", "session", "--dir"])
            .arg(&self.dir)
            .args(["--member", member])
            .env("AMESH_FLOCK_TOKEN", token)
            .env_remove("HERDR_PANE_ID")
            .env_remove("HERDR_TAB_ID");
        if let Some((p, t)) = pane {
            child.env("HERDR_PANE_ID", p).env("HERDR_TAB_ID", t);
        }
        let mut child = child
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let (mut id, mut sock) = (String::new(), String::new());
        out.read_line(&mut id).unwrap();
        out.read_line(&mut sock).unwrap();
        Sess {
            proc: Proc(child),
            sock: sock.trim().strip_prefix("socket: ").unwrap().into(),
        }
    }

    /// `amesh flock <args>` against this flock, as the given session.
    pub fn run(&self, s: Option<&Sess>, args: &[&str]) -> Output {
        let mut c = amesh(self.home.path());
        c.arg("flock").arg(args[0]);
        c.arg("--dir").arg(&self.dir);
        if let Some(s) = s {
            c.arg("--session").arg(&s.sock);
        }
        c.args(&args[1..]).output().unwrap()
    }

    pub fn ok(&self, s: &Sess, args: &[&str]) -> String {
        let o = self.run(Some(s), args);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap()
    }

    /// The content id a write printed ("admitted <cid> at <n>").
    pub fn emit(&self, s: &Sess, args: &[&str]) -> String {
        self.ok(s, args)
            .split_whitespace()
            .nth(1)
            .expect("an admitted line")
            .to_owned()
    }

    pub fn log(&self, s: &Sess) -> String {
        self.ok(s, &["log"])
    }
}

/// `amesh flock <args>` naming flock `named` but possibly pointing at another
/// flock's session by flag or environment.
pub fn aimed(named: &Flock, sock: Option<&Path>, env_sock: Option<&Path>, args: &[&str]) -> Output {
    let mut c = amesh(named.home.path());
    c.arg("flock").arg(args[0]).arg("--dir").arg(&named.dir);
    if let Some(s) = sock {
        c.arg("--session").arg(s);
    }
    c.env_remove("AMESH_FLOCK_SESSION");
    if let Some(s) = env_sock {
        c.env("AMESH_FLOCK_SESSION", s);
    }
    c.args(&args[1..]).output().unwrap()
}

pub fn code(o: &Output) -> Option<i32> {
    o.status.code()
}
