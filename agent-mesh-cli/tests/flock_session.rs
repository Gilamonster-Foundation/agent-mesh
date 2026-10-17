//! `amesh flock serve` and `amesh flock session`, as real processes.
#![cfg(unix)]

use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::Frame;
use agent_mesh_flock_session::{call, CtlReq, CtlResp};
use assert_cmd::cargo::cargo_bin;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

/// A child that is killed when the test ends, pass or fail.
struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Flock {
    home: TempDir,
    dir: PathBuf,
    _serve: Proc,
}

fn amesh(home: &Path) -> Command {
    let mut c = Command::new(cargo_bin("amesh"));
    c.arg("--home").arg(home);
    c
}

fn flock() -> Flock {
    let home = TempDir::new().unwrap();
    assert!(amesh(home.path()).arg("keygen").status().unwrap().success());
    assert!(amesh(home.path())
        .args(["flock", "init", "--name", "f"])
        .args(["--member", "shep:shepherd", "--member", "h1:helper"])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success());
    let dir = home.path().join("flocks").join("f");
    let mut serve = amesh(home.path())
        .args(["flock", "serve", "--dir"])
        .arg(&dir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // "serving <path>" means the socket is bound
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

impl Flock {
    fn invite(&self, member: &str) -> String {
        let out = amesh(self.home.path())
            .args(["flock", "invite", "--dir"])
            .arg(&self.dir)
            .arg(member)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// Start a session process; returns it with its id and socket.
    fn session(&self, member: &str, extra: &[&str], pre: &str) -> (Proc, String, PathBuf) {
        let token = self.invite(member);
        let script = format!(
            "{pre} exec \"$0\" --home \"$1\" flock session --dir \"$2\" --member \"$3\" {}",
            extra.join(" ")
        );
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg(cargo_bin("amesh"))
            .arg(self.home.path())
            .arg(&self.dir)
            .arg(member)
            .env("AMESH_FLOCK_TOKEN", token)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let (mut id, mut sock) = (String::new(), String::new());
        out.read_line(&mut id).unwrap();
        out.read_line(&mut sock).unwrap();
        let id = id.trim().strip_prefix("session: ").unwrap_or("").to_owned();
        let sock = sock.trim().strip_prefix("socket: ").unwrap_or("").into();
        (Proc(child), id, sock)
    }

    fn serve_sock(&self) -> PathBuf {
        self.dir.join("run").join("serve.sock")
    }

    /// Wait (no sleeps) until the server's epoch reaches `n`.
    fn epoch_reaches(&self, n: u64) {
        for _ in 0..50_000 {
            let mut c = UnixStream::connect(self.serve_sock()).unwrap();
            write_msg(&mut c, &Req::Hello).unwrap();
            if let Some(Resp::Hello { epoch, .. }) = read_msg(&mut c).unwrap() {
                if epoch >= n {
                    return;
                }
            }
            std::thread::yield_now();
        }
        panic!("epoch never reached {n}");
    }

    fn log_bodies(&self) -> Vec<Body> {
        let bytes =
            std::fs::read(self.dir.join(agent_mesh_flock_server::LOG_FILE)).unwrap_or_default();
        let (mut at, mut out) = (0, vec![]);
        while at + 8 <= bytes.len() {
            let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            let frame: Frame = content_addressable::canonical::from_canonical_dagcbor_checked(
                &bytes[at + 8..at + 8 + len],
            )
            .unwrap();
            out.extend(frame.sealed.into_iter().map(|s| s.event.payload.body));
            at += 8 + len;
        }
        out
    }
}

#[test]
fn kill_dash_nine_records_lost_and_the_epoch_bump_follows() {
    let f = flock();
    let (mut session, id, _) = f.session("shep", &[], "");
    assert!(!id.is_empty());
    session.0.kill().unwrap(); // SIGKILL: no goodbye
    session.0.wait().unwrap();
    f.epoch_reaches(1);
    let bodies = f.log_bodies();
    assert!(bodies.iter().any(|b| matches!(
        b,
        Body::SessionEnd { session, reason: agent_mesh_flock::EndReason::Lost } if *session == id
    )));
    assert!(matches!(bodies.last(), Some(Body::Epoch { epoch: 1 })));
}

#[test]
fn a_clean_end_records_closed_and_the_cli_can_use_the_key() {
    let f = flock();
    let (mut session, id, sock) = f.session("shep", &[], "");
    let CtlResp::Who { session: who, .. } = call(&sock, &CtlReq::Whoami).unwrap() else {
        panic!("not Who")
    };
    assert_eq!(who, id);
    let CtlResp::Admitted { index, .. } = call(
        &sock,
        &CtlReq::Emit {
            kind: Kind::Brief,
            refs: Default::default(),
            body: Body::Brief {
                to: "h1".into(),
                lane: "l1".into(),
            },
        },
    )
    .unwrap() else {
        panic!("not Admitted")
    };
    assert!(index > 1);
    call(&sock, &CtlReq::End).unwrap();
    assert!(session.0.wait().unwrap().success());
    assert!(f.log_bodies().iter().any(|b| matches!(
        b,
        Body::SessionEnd {
            reason: agent_mesh_flock::EndReason::Closed,
            ..
        }
    )));
    assert!(!sock.exists(), "socket is removed on exit");
}

#[test]
fn the_socket_is_0600_in_a_0700_directory_and_a_loose_directory_is_refused() {
    let f = flock();
    let (_s, _, sock) = f.session("shep", &[], "");
    let m = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(m(&sock), 0o600);
    assert_eq!(m(sock.parent().unwrap()), 0o700);
    // a world-enterable directory is refused, not silently tightened
    let loose = f.home.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
    let token = f.invite("h1");
    let out = amesh(f.home.path())
        .args(["flock", "session", "--member", "h1", "--dir"])
        .arg(&f.dir)
        .arg("--socket")
        .arg(loose.join("s.sock"))
        .env("AMESH_FLOCK_TOKEN", token)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("only its owner"));
}

#[cfg(target_os = "linux")]
#[test]
fn the_session_has_core_dumps_off_and_its_memory_locked() {
    let f = flock();
    // start with core dumps allowed, so the session itself must turn them off
    let (s, _, _) = f.session(
        "shep",
        &[],
        "ulimit -c unlimited 2>/dev/null || ulimit -S -c 1000000;",
    );
    let pid = s.0.id();
    // a non-dumpable process's /proc files are closed even to its own user
    let e = std::fs::read(format!("/proc/{pid}/environ")).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    assert!(
        core.split_whitespace().rev().take(3).any(|w| w == "0"),
        "{core}"
    );
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let lck = status.lines().find(|l| l.starts_with("VmLck")).unwrap();
    assert!(!lck.contains(" 0 kB"), "{lck}");
}

#[test]
fn without_lockable_memory_the_session_refuses_unless_told_otherwise() {
    let f = flock();
    let (mut s, id, _) = f.session("shep", &[], "ulimit -l 0;");
    assert!(id.is_empty());
    assert!(!s.0.wait().unwrap().success());
    let mut err = String::new();
    std::io::Read::read_to_string(&mut s.0.stderr.take().unwrap(), &mut err).unwrap();
    assert!(err.contains("mlock"), "{err}");
    let (_ok, id, _) = f.session("h1", &["--allow-unlocked"], "ulimit -l 0;");
    assert!(!id.is_empty());
}

/// A `herdr` that lists one unlabelled pane, `w1:p9`.
fn fake_herdr_with_one_pane(bin: &Path) {
    let script = "#!/bin/sh\ncat <<'EOF'\n{\"id\":\"x\",\"result\":{\"panes\":[{\"pane_id\":\"w1:p9\",\"tab_id\":\"w1:t1\",\"agent\":\"newt\",\"agent_status\":\"idle\"}]}}\nEOF\n";
    let path = bin.join("herdr");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn panes_output(f: &Flock, bin: &Path) -> String {
    let out = amesh(f.home.path())
        .args(["flock", "panes", "--name", "f", "--dir"])
        .arg(&f.dir)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn a_session_started_in_a_herdr_pane_announces_it_and_panes_links_it_as_a_claim() {
    let f = flock();
    let bin = TempDir::new().unwrap();
    fake_herdr_with_one_pane(bin.path());
    // no label anywhere: the only link is the session's own signed claim
    let (_s, id, sock) = f.session(
        "shep",
        &[],
        "export HERDR_PANE_ID=w1:p9 HERDR_TAB_ID=w1:t1;",
    );
    assert!(!id.is_empty());
    let out = panes_output(&f, bin.path());
    let row = out.lines().find(|l| l.starts_with("shep")).unwrap();
    assert!(row.contains("w1:p9") && row.contains("session"), "{row}");
    // announcing again chains onto the first claim and is admitted
    let CtlResp::Admitted { index, .. } = call(&sock, &CtlReq::Announce).unwrap() else {
        panic!("not Admitted")
    };
    assert!(index > 2);
    let h1 = out.lines().find(|l| l.starts_with("h1")).unwrap();
    assert!(h1.contains("no pane"), "{h1}");
}

#[test]
fn outside_herdr_nothing_is_announced_and_a_bad_claim_does_not_stop_the_session() {
    let f = flock();
    let (_s, id, sock) = f.session("shep", &[], "unset HERDR_PANE_ID HERDR_TAB_ID;");
    assert!(!id.is_empty());
    assert!(call(&sock, &CtlReq::Announce).is_err());
    assert!(!f
        .log_bodies()
        .iter()
        .any(|b| matches!(b, Body::Pane { .. })));
    // an unprintable claim is refused by admission; the session carries on
    let (_t, id2, _) = f.session(
        "h1",
        &[],
        "export HERDR_PANE_ID=\"$(printf 'a\\033b')\" HERDR_TAB_ID=t;",
    );
    assert!(!id2.is_empty(), "a refused claim must not stop the session");
    assert!(!f
        .log_bodies()
        .iter()
        .any(|b| matches!(b, Body::Pane { .. })));
}
