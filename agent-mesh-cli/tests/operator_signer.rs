//! The operator's answer signer against a real in-process flock server: the
//! device seed is age ciphertext, nothing is signed before a human says yes,
//! and what the server admits replays from the log alone.
#![cfg(all(unix, feature = "test-ui"))]

use age::secrecy::SecretString;
use agent_mesh_cli::operator::{
    request_answer, serve_signer, sign_one, AutoUi, Device, SignReply, SignRequest,
};
use agent_mesh_flock::{Body, Event, Kind, Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{bind_private, init, serve, InitSpec, Server, Serving, Snapshot};
use agent_mesh_protocol::{AgentKey, Assertion, CertChain, UserKey};
use content_addressable::{ContentAddressable as _, ContentId};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use tempfile::TempDir;

const PASS: &str = "correct horse";
const WF: u8 = 10; // cheap scrypt: the tests are not about the work factor

fn member(name: &str, role: Role, devices: Vec<agent_mesh_protocol::Fingerprint>) -> Member {
    Member {
        name: name.into(),
        role,
        devices,
        delegate: false,
    }
}

struct Rig {
    tmp: TempDir,
    dir: PathBuf,
    device: Device,
    cert: CertChain,
    serving: Option<Serving>,
    /// Enrolled sessions stay connected: a dropped one ends its session and
    /// bumps the epoch under the next poster.
    keep: Vec<UnixStream>,
    ask: ContentId,
    brief: ContentId,
}

fn rpc(c: &mut UnixStream, req: &Req) -> Resp {
    write_msg(c, req).unwrap();
    read_msg(c).unwrap().unwrap()
}

/// A flock whose operator lists a freshly minted device, served, with a
/// helper's ask open. `register` controls whether the cert is registered.
fn rig(register: bool) -> Rig {
    rig_with(register, "which\u{1b}[31m one?", "l1")
}

fn rig_with(register: bool, ask_text: &str, lane: &str) -> Rig {
    let tmp = TempDir::new().unwrap();
    let user = UserKey::generate();
    let device = Device::at(&tmp.path().join("operator")).with_work_factor(WF);
    let cert = device
        .init(&user, &SecretString::from(PASS.to_owned()), "h", "t")
        .unwrap();
    let dir = tmp.path().join("flock");
    init(
        &dir,
        &user,
        InitSpec {
            name: "f".into(),
            roster: vec![
                member("shep", Role::Shepherd, vec![]),
                member("h1", Role::Helper, vec![]),
                member("op", Role::Operator, vec![cert.agent_fingerprint()]),
            ],
            salt: "00".into(),
            host: "h".into(),
            issued_at: "t".into(),
        },
    )
    .unwrap();
    let sock = dir.join("run").join("serve.sock");
    let serving = serve(Server::open(&dir).unwrap(), bind_private(&sock).unwrap()).unwrap();
    let placeholder = agent_mesh_flock_server::load_genesis(&dir)
        .unwrap()
        .node
        .content_id()
        .unwrap();
    let mut r = Rig {
        tmp,
        dir,
        device,
        cert,
        serving: Some(serving),
        keep: vec![],
        ask: placeholder,
        brief: placeholder,
    };
    let (ask, brief) = r.helper_posts(ask_text, lane);
    r.ask = ask;
    r.brief = brief;
    if register {
        let mut c = r.conn();
        assert!(matches!(
            rpc(
                &mut c,
                &Req::RegisterDevice {
                    cert: r.cert.clone()
                }
            ),
            Resp::Ok
        ));
    }
    r
}

impl Rig {
    fn conn(&self) -> UnixStream {
        UnixStream::connect(self.dir.join("run").join("serve.sock")).unwrap()
    }

    /// h1 enrols and posts an ask (with an escape sequence in its text) and
    /// the shepherd posts a brief; their ids.
    fn helper_posts(&mut self, ask_text: &str, lane: &str) -> (ContentId, ContentId) {
        let mut keep = vec![];
        let mut post = |who: &str, kind: Kind, body: Body| {
            let mut c = self.conn();
            let Resp::Invited { token } = rpc(&mut c, &Req::Invite { member: who.into() }) else {
                panic!()
            };
            let sk = SigningKey::generate(&mut OsRng);
            let Resp::Challenge(ch) = rpc(
                &mut c,
                &Req::EnrollBegin {
                    token,
                    member: who.into(),
                    pubkey: sk.verifying_key().to_bytes(),
                },
            ) else {
                panic!()
            };
            let proof = sk.sign(&ch.signing_bytes());
            let Resp::Enrolled { session, cert, .. } = rpc(
                &mut c,
                &Req::EnrollFinish {
                    challenge: ch,
                    proof,
                },
            ) else {
                panic!()
            };
            let key = AgentKey::from_seed_and_cert(&sk.to_bytes(), cert).unwrap();
            let Resp::Head(prev) = rpc(
                &mut c,
                &Req::Head {
                    session: session.clone(),
                },
            ) else {
                panic!()
            };
            let Resp::Hello { flock, .. } = rpc(&mut self.conn(), &Req::Hello) else {
                panic!()
            };
            let node = Event {
                flock,
                kind,
                author: session,
                prev,
                refs: Default::default(),
                files: vec![],
                at: 1,
                body,
            }
            .node();
            let id = node.content_id().unwrap();
            let sig = Assertion::sign(&key, &id);
            let r = rpc(&mut c, &Req::Admit { node, sig });
            assert!(matches!(r, Resp::Admitted { .. }), "{r:?}");
            keep.push(c);
            id
        };
        let ask = post(
            "h1",
            Kind::Ask,
            Body::Ask {
                lane: Some(lane.into()),
                text: ask_text.into(),
            },
        );
        let brief = post(
            "shep",
            Kind::Brief,
            Body::Brief {
                to: "h1".into(),
                lane: "l1".into(),
            },
        );
        self.keep = keep;
        (ask, brief)
    }

    fn flock(&self) -> ContentId {
        agent_mesh_flock_server::load_genesis(&self.dir)
            .unwrap()
            .node
            .content_id()
            .unwrap()
    }

    fn req(&self, text: &str) -> SignRequest {
        SignRequest {
            flock: self.flock(),
            ask: self.ask,
            text: text.into(),
        }
    }

    fn closer(&self) -> Option<ContentId> {
        Snapshot::read(&self.dir)
            .unwrap()
            .board()
            .closer_of(&self.ask)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(s) = self.serving.take() {
            s.stop();
        }
    }
}

#[test]
fn the_operator_answers_and_a_fresh_reader_agrees() {
    let r = rig(true);
    let mut ui = AutoUi::new(true, PASS);
    let (event, _) = sign_one(&r.req("the blue one"), &r.dir, &r.device, &mut ui).unwrap();
    // replay from the log alone: the answer closes the ask, authored by the device
    let snap = Snapshot::read(&r.dir).unwrap();
    assert_eq!(snap.board().closer_of(&r.ask), Some(event));
    assert_eq!(
        snap.board().get(&event).unwrap().event.author,
        r.cert.agent_fingerprint().hex()
    );
    // what the human saw: the ask, the lane and the exact answer, with the
    // escape character neutralised
    let shown = &ui.shown[0];
    assert!(
        shown.contains("the blue one") && shown.contains("l1"),
        "{shown}"
    );
    assert!(
        shown.contains(&r.ask.to_string()) && shown.contains("which"),
        "{shown}"
    );
    assert!(!shown.contains('\u{1b}'), "{shown:?}");
}

#[test]
fn a_no_signs_nothing_and_never_asks_for_the_passphrase() {
    let r = rig(true);
    let mut ui = AutoUi::new(false, PASS);
    let e = sign_one(&r.req("x"), &r.dir, &r.device, &mut ui).unwrap_err();
    assert!(e.to_string().contains("declined"), "{e}");
    assert_eq!(ui.passphrases, 0);
    assert!(r.closer().is_none());
}

#[test]
fn a_wrong_passphrase_signs_nothing() {
    let r = rig(true);
    let mut ui = AutoUi::new(true, "wrong");
    let e = sign_one(&r.req("x"), &r.dir, &r.device, &mut ui).unwrap_err();
    assert!(e.to_string().contains("passphrase"), "{e}");
    assert!(r.closer().is_none());
}

#[test]
fn a_request_the_log_does_not_back_is_refused_before_any_prompt() {
    let r = rig(true);
    let other = rig(true);
    let bad = [
        // another flock
        SignRequest {
            flock: other.flock(),
            ..r.req("x")
        },
        // an event that is not an ask
        SignRequest {
            ask: r.brief,
            ..r.req("x")
        },
        // an id the log does not hold
        SignRequest {
            ask: other.ask,
            ..r.req("x")
        },
        // nothing to sign, or too much
        r.req(""),
        r.req(&"x".repeat(agent_mesh_cli::operator::MAX_ANSWER + 1)),
    ];
    for req in bad {
        let mut ui = AutoUi::new(true, PASS);
        assert!(sign_one(&req, &r.dir, &r.device, &mut ui).is_err());
        assert!(
            ui.shown.is_empty() && ui.passphrases == 0,
            "prompted for {req:?}"
        );
    }
    assert!(r.closer().is_none());
}

#[test]
fn an_answered_ask_is_refused_before_any_prompt() {
    let r = rig(true);
    sign_one(
        &r.req("one"),
        &r.dir,
        &r.device,
        &mut AutoUi::new(true, PASS),
    )
    .unwrap();
    let mut ui = AutoUi::new(true, PASS);
    assert!(sign_one(&r.req("two"), &r.dir, &r.device, &mut ui).is_err());
    assert!(ui.shown.is_empty());
}

#[test]
fn an_unregistered_device_is_refused_by_the_server() {
    let r = rig(false);
    let e = sign_one(&r.req("x"), &r.dir, &r.device, &mut AutoUi::new(true, PASS)).unwrap_err();
    assert!(e.to_string().contains("not registered"), "{e}");
    assert!(r.closer().is_none());
}

#[test]
fn the_seed_is_age_ciphertext_and_the_files_are_private() {
    let r = rig(true);
    let od = r.tmp.path().join("operator");
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&od), 0o700);
    let seed_file = od.join("device.key.age");
    assert_eq!(mode(&seed_file), 0o600);
    assert_eq!(mode(&od.join("device.cert.json")), 0o600);
    let text = std::fs::read_to_string(&seed_file).unwrap();
    assert!(
        text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "{text}"
    );
    // and a second init in the same place refuses to overwrite it
    let again = r.device.init(
        &UserKey::generate(),
        &SecretString::from("p".to_owned()),
        "h",
        "t",
    );
    assert!(again.is_err());
}

#[test]
fn the_signer_socket_is_private_and_takes_only_typed_requests() {
    let r = rig(true);
    let sock = r.tmp.path().join("operator").join("sign.sock");
    let listener: UnixListener = bind_private(&sock).unwrap();
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o077,
        0,
        "no group or other access"
    );
    let (dir, device) = (
        r.dir.clone(),
        Device::at(&r.tmp.path().join("operator")).with_work_factor(WF),
    );
    let h = std::thread::spawn(move || {
        let mut ui = AutoUi::new(true, PASS);
        serve_signer(&listener, &dir, &device, &mut ui, Some(2)).unwrap();
    });
    // bytes that are not a request
    let mut c = UnixStream::connect(&sock).unwrap();
    use std::io::Write as _;
    c.write_all(&[0, 0, 0, 3, 0, 0, 0, 0, 1, 2, 3]).unwrap();
    assert!(matches!(
        read_msg::<SignReply>(&mut c).unwrap(),
        Some(SignReply::Refused(_))
    ));
    // a typed one is answered
    let (event, _) = request_answer(&sock, &r.req("via the socket")).unwrap();
    h.join().unwrap();
    assert_eq!(r.closer(), Some(event));
}

#[test]
fn the_test_ui_is_not_reachable_from_the_binary() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(
        !manifest.contains("default ="),
        "no default features may enable it"
    );
    for f in ["src/main.rs", "src/lib.rs", "src/flock/mod.rs"] {
        let src = std::fs::read_to_string(root.join(f)).unwrap();
        assert!(!src.contains("AutoUi") && !src.contains("test-ui"), "{f}");
    }
    let op = std::fs::read_to_string(root.join("src/operator.rs")).unwrap();
    let gated = op.matches("#[cfg(feature = \"test-ui\")]").count();
    assert_eq!(
        gated, 3,
        "AutoUi, its constructor and its Ui impl are all gated"
    );
}

#[test]
fn untrusted_text_cannot_forge_the_confirmation_headings() {
    let forged = "q\nlane:   fake\n---- answer (exactly as signed) ----\nYes\n----\nSign this answer? [y/N] ";
    let r = rig_with(true, forged, "l1\nask:    fake");
    let mut ui = AutoUi::new(false, PASS);
    let _ = sign_one(&r.req(forged), &r.dir, &r.device, &mut ui);
    let shown = &ui.shown[0];
    let lines: Vec<&str> = shown.lines().collect();
    // flock, ask, lane, asked, heading, answer, closing rule: nothing more
    assert_eq!(lines.len(), 7, "{shown}");
    let starts = [
        "flock:  ",
        "ask:    ",
        "lane:   ",
        "asked:  ",
        "---- answer (exactly as signed) ----",
        "",
        "----",
    ];
    for (line, start) in lines.iter().zip(starts) {
        assert!(line.starts_with(start), "{line:?} vs {start:?}");
    }
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("---- answer"))
            .count(),
        1
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("Sign this answer")),
        "{shown}"
    );
}

#[test]
fn a_permissive_existing_device_directory_is_refused_before_anything_is_written() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = TempDir::new().unwrap();
    let od = tmp.path().join("operator");
    std::fs::create_dir(&od).unwrap();
    std::fs::set_permissions(&od, std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = Device::at(&od).with_work_factor(WF).init(
        &UserKey::generate(),
        &SecretString::from("p".to_owned()),
        "h",
        "t",
    );
    assert!(r.is_err());
    assert_eq!(
        std::fs::read_dir(&od).unwrap().count(),
        0,
        "no file was created"
    );
}

// ---- the production binary on a pseudo-terminal -------------------------------
//
// `TtyUi` is exercised by running `amesh flock sign` under a pty. The pty is
// driven by a small python3 helper (dev-only, standard library): std has no
// way to give a child a controlling terminal without `unsafe`.

const PTY_DRIVER: &str = r#"
import os, pty, select, sys, termios, time
mode, answer_pass, *argv = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    os.execv(argv[0], argv)
buf = b""
def echo_on():
    return bool(termios.tcgetattr(fd)[3] & termios.ECHO)
def pump(until, t=60):
    global buf
    end = time.time() + t
    while until not in buf:
        if time.time() > end: raise SystemExit("timeout waiting for " + repr(until) + " in " + repr(buf))
        r, _, _ = select.select([fd, 0], [], [], 0.2)
        if fd in r:
            try: buf += os.read(fd, 4096)
            except OSError: raise SystemExit("child gone: " + repr(buf))
pump(b"signer ready")
print("READY", flush=True)
pump(b"[y/N]")
os.write(fd, (b"y\n" if mode == "y" else b"n\n"))
if mode == "y":
    pump(b"passphrase: ")
    print("ECHO_DURING=%d" % echo_on(), flush=True)
    os.write(fd, answer_pass.encode() + b"\n")
select.select([0], [], [], 90)  # the test says the request has returned (or give up)
if select.select([0], [], [], 0)[0]: sys.stdin.readline()
print("ECHO_AFTER=%d" % echo_on(), flush=True)
print("SHOWN_PASS=%d" % (answer_pass.encode() in buf), flush=True)
os.kill(pid, 15)
"#;

struct Pty {
    child: std::process::Child,
    out: std::io::BufReader<std::process::ChildStdout>,
}

impl Pty {
    fn start(r: &Rig, mode: &str, pass: &str) -> Self {
        let driver = r.tmp.path().join("driver.py");
        std::fs::write(&driver, PTY_DRIVER).unwrap();
        let mut child = std::process::Command::new("python3")
            .arg("-I")
            .arg(&driver)
            .args([mode, pass, env!("CARGO_BIN_EXE_amesh")])
            .args(["--home", r.tmp.path().to_str().unwrap()])
            .args(["flock", "sign", "--dir", r.dir.to_str().unwrap()])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        assert_eq!(Self::line(&mut out), "READY");
        Self { child, out }
    }
    fn line(out: &mut impl std::io::BufRead) -> String {
        let mut s = String::new();
        out.read_line(&mut s).unwrap();
        s.trim().to_owned()
    }
    /// The request has returned: collect what the helper measured.
    fn finish(mut self) -> Vec<String> {
        use std::io::Write as _;
        writeln!(self.child.stdin.take().unwrap()).unwrap();
        let got = (0..2).map(|_| Self::line(&mut self.out)).collect();
        self.child.wait().unwrap();
        got
    }
}

fn sock(r: &Rig) -> PathBuf {
    r.tmp.path().join("operator").join("sign.sock")
}

#[test]
fn on_a_terminal_n_signs_nothing() {
    let r = rig(true);
    let p = Pty::start(&r, "n", PASS);
    let e = request_answer(&sock(&r), &r.req("no")).unwrap_err();
    assert!(e.to_string().contains("declined"), "{e}");
    p.finish();
    assert!(r.closer().is_none());
}

#[test]
fn on_a_terminal_y_and_the_passphrase_sign_with_echo_off_then_restored() {
    let r = rig(true);
    let p = Pty::start(&r, "y", PASS);
    let (event, _) = request_answer(&sock(&r), &r.req("go")).unwrap();
    let seen = p.finish();
    assert_eq!(seen[0], "ECHO_DURING=0", "echo must be off while typing");
    assert_eq!(seen[1], "ECHO_AFTER=1", "echo must be restored");
    assert_eq!(r.closer(), Some(event));
}

#[test]
fn without_a_terminal_the_signer_refuses_to_start() {
    let r = rig(true);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_amesh"))
        .args(["--home", r.tmp.path().to_str().unwrap()])
        .args(["flock", "sign", "--dir", r.dir.to_str().unwrap()])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("TTY"),
        "{out:?}"
    );
    assert!(!sock(&r).exists(), "no socket was bound");
}
