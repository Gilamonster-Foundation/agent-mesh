//! A valid signature says who spoke, not that their words are harmless. A really
//! admitted flock carries terminal-control text in a status, a member name, a
//! lane and a job label; no command may hand it to the operator's terminal.
#![cfg(unix)]
mod harness;

use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock_session::{call, CtlReq};
use harness::{amesh, flock_with, Sess};
use std::collections::BTreeMap;
use std::process::Output;

/// OSC 52 (set the clipboard), BEL, a one-character CSI, a bidi override, and a
/// newline that would start a forged line. No colon (member specs split on it).
const HOSTILE: &str = "\u{1b}]52;c;aGk=\u{7}\u{9b}31m\u{202e}rtl\nFORGED";

/// What a terminal could act on: ESC, BEL, any C1 control, bidi/zero-width.
fn dangerous(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(bytes);
    s.chars()
        .find(|c| {
            c.is_control() && !matches!(c, '\n' | '\t')
                || matches!(c, '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{e0000}'..='\u{e007f}')
        })
        .map(|c| format!("{c:?} in {s:?}"))
}

fn safe(o: &Output, what: &str) {
    // a newline in a member's text must not start a line of its own
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        assert!(!line.starts_with("FORGED"), "{what}: forged line {line:?}");
    }
    for (name, b) in [("stdout", &o.stdout), ("stderr", &o.stderr)] {
        assert!(dangerous(b).is_none(), "{what} {name}: {:?}", dangerous(b));
    }
}

struct World {
    f: harness::Flock,
    shep: Sess,
    evil: Sess,
    _adapter: Sess,
}

fn world() -> World {
    let evil_member = format!("ev{HOSTILE}il");
    // the sender is hostile too, so `inbox` (which shows who a brief is from)
    // has something to escape
    let shep_member = format!("sh{HOSTILE}ep");
    let f = flock_with(&[
        &format!("{shep_member}:shepherd"),
        &format!("{evil_member}:helper"),
        "herdr:adapter",
    ]);
    let shep = f.session(&shep_member);
    let evil = f.session(&evil_member);
    let adapter = f.session("herdr");
    // a brief into the hostile lane, for the hostile member
    f.emit(&shep, &["brief", "--to", &evil_member, "--lane", HOSTILE]);
    // a status carrying the payload, and a job with a hostile label
    let refs = BTreeMap::new();
    call(
        &adapter.sock,
        &CtlReq::Emit {
            kind: Kind::Status,
            refs,
            body: Body::Status {
                text: format!("all fine{HOSTILE}"),
            },
        },
    )
    .unwrap();
    let o = f.run(
        Some(&evil),
        &["run", "--lane", HOSTILE, "--label", HOSTILE, "--", "true"],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    World {
        f,
        shep,
        evil,
        _adapter: adapter,
    }
}

#[test]
fn no_command_hands_member_authored_text_to_the_terminal() {
    let w = world();
    let run = |s: &Sess, args: &[&str]| {
        let o = w.f.run(Some(s), args);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        safe(&o, &args.join(" "));
        String::from_utf8(o.stdout).unwrap()
    };
    // `watch --once` first: it prints each event once, as it verifies it
    let watch = run(&w.shep, &["watch", "--once"]);
    let log = run(&w.shep, &["log"]);
    let status = run(&w.shep, &["status"]);
    let inbox = run(&w.evil, &["inbox"]);
    let join = run(&w.evil, &["join"]);
    // the payload really is in the log, and the escaped forms are what is shown
    let want = "\\x1b]52;c;aGk=\\x07\\x9b31m\\u{202e}rtl\\nFORGED";
    assert!(log.contains(want), "{log}");
    assert!(watch.contains(want), "{watch}");
    assert!(status.contains("\\x1b"), "{status}");
    assert!(inbox.contains("\\x1b"), "{inbox}");
    assert!(join.contains("ev\\x1b"), "{join}");
}

#[test]
fn an_error_that_names_hostile_text_is_inert_too() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(format!("no{HOSTILE}pe"));
    let o = amesh(home.path())
        .args(["flock", "join", "--dir"])
        .arg(&dir)
        .arg("--session")
        .arg(home.path().join("nosock"))
        .output()
        .unwrap();
    assert!(!o.status.success());
    safe(&o, "error");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("\\x1b"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// A server socket that is not the real server: answers one `Invite` with `token`.
/// Every wait is bounded, so a CLI that never connects (or never answers) is a
/// failed test, not a hung one. The bound is a failure guard, not a measurement.
const GUARD: std::time::Duration = std::time::Duration::from_secs(60);

fn mock_invite_server(token: &str) -> (tempfile::TempDir, std::thread::JoinHandle<()>) {
    use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("run")).unwrap();
    let listener =
        std::os::unix::net::UnixListener::bind(dir.path().join("run/serve.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let token = token.to_string();
    let t = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let mut c = loop {
            match listener.accept() {
                Ok((c, _)) => break c,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && start.elapsed() < GUARD => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("the CLI never connected to the mock server: {e}"),
            }
        };
        c.set_nonblocking(false).unwrap();
        c.set_read_timeout(Some(GUARD)).unwrap();
        assert!(matches!(
            read_msg::<Req>(&mut c).unwrap(),
            Some(Req::Invite { .. })
        ));
        write_msg(&mut c, &Resp::Invited { token }).unwrap();
    });
    (dir, t)
}

fn invite_against(token: &str) -> Output {
    let (dir, t) = mock_invite_server(token);
    let home = tempfile::TempDir::new().unwrap();
    let mut child = amesh(home.path())
        .args(["flock", "invite", "--dir"])
        .arg(dir.path())
        .arg("m")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > GUARD {
            child.kill().unwrap();
            panic!("`flock invite` hung against the mock server");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    t.join().unwrap();
    out
}

#[test]
fn a_hostile_invite_token_from_the_server_socket_is_refused_not_printed() {
    let out = invite_against(HOSTILE);
    assert!(!out.status.success(), "a malformed token must be an error");
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
    safe(&out, "invite");
    // a plausible but wrong token is refused too: uppercase, short, long
    for bad in [
        "A".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        String::new(),
    ] {
        let out = invite_against(&bad);
        assert!(!out.status.success(), "{bad:?}");
        assert!(out.stdout.is_empty(), "{bad:?}");
    }
}

#[test]
fn a_well_formed_invite_token_is_printed_unchanged() {
    let token = "0123456789abcdef".repeat(4);
    let out = invite_against(&token);
    assert!(
        out.status.success(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, format!("{token}\n").into_bytes());
}
