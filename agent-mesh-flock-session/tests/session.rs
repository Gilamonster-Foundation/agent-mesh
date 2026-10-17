//! The session against an in-process server.
#![cfg(unix)]

use agent_mesh_flock::{Body, EndReason, Kind, Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{bind_private, init, serve, InitSpec, Server, Serving};
use agent_mesh_flock_session::{Locked, Policy, Session};
use agent_mesh_protocol::{AgentKey, Assertion, UserKey};
use content_addressable::ContentAddressable;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tempfile::TempDir;

struct Rig {
    _tmp: TempDir,
    sock: PathBuf,
    serving: Option<Serving>,
}

fn rig() -> Rig {
    let tmp = TempDir::new().unwrap();
    let spec = InitSpec {
        name: "f".into(),
        roster: vec![
            Member {
                name: "shep".into(),
                role: Role::Shepherd,
            },
            Member {
                name: "h1".into(),
                role: Role::Helper,
            },
        ],
        salt: "00".into(),
        host: "h".into(),
        issued_at: "t".into(),
    };
    init(tmp.path(), &UserKey::generate(), spec).unwrap();
    let server = Server::open(tmp.path()).unwrap();
    let sock = tmp.path().join("run").join("serve.sock");
    let serving = serve(server, bind_private(&sock).unwrap()).unwrap();
    Rig {
        _tmp: tmp,
        sock,
        serving: Some(serving),
    }
}

impl Rig {
    fn rpc(&self, c: &mut UnixStream, req: &Req) -> Resp {
        write_msg(c, req).unwrap();
        read_msg(c).unwrap().unwrap()
    }
    fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.sock).unwrap()
    }
    fn invite(&self, member: &str) -> String {
        let mut c = self.connect();
        match self.rpc(
            &mut c,
            &Req::Invite {
                member: member.into(),
            },
        ) {
            Resp::Invited { token } => token,
            other => panic!("{other:?}"),
        }
    }
    fn session(&self, member: &str) -> Session {
        Session::enroll(
            &self.sock,
            &self.invite(member),
            member,
            Policy::AllowUnlocked,
        )
        .unwrap()
    }
    fn epoch(&self) -> u64 {
        match self.rpc(&mut self.connect(), &Req::Hello) {
            Resp::Hello { epoch, .. } => epoch,
            other => panic!("{other:?}"),
        }
    }
    fn wait_epoch(&self, n: u64) {
        for _ in 0..50_000 {
            if self.epoch() >= n {
                return;
            }
            std::thread::yield_now();
        }
        panic!("epoch never reached {n}");
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(s) = self.serving.take() {
            s.stop();
        }
    }
}

fn brief() -> (Kind, Body) {
    (
        Kind::Brief,
        Body::Brief {
            to: "h1".into(),
            lane: "l".into(),
        },
    )
}

#[test]
fn a_session_renews_itself_after_another_session_ends() {
    let r = rig();
    let mut shep = r.session("shep");
    let h1 = r.session("h1");
    let (k, b) = brief();
    shep.emit(k, Default::default(), b.clone()).unwrap();
    h1.end().unwrap();
    assert_eq!(r.epoch(), 1);
    // its certificate is now behind; emit renews first, then signs
    shep.emit(k, Default::default(), b).unwrap();
}

#[test]
fn a_replacement_session_is_pending_and_signs_nothing() {
    let r = rig();
    let _first = r.session("shep");
    let mut second = r.session("shep");
    let (k, b) = brief();
    assert!(second.emit(k, Default::default(), b).is_err());
}

/// A key held by the test, enrolled over the wire, so it can be used after
/// its connection is gone.
fn enrol_by_hand(r: &Rig, member: &str) -> (UnixStream, AgentKey, String) {
    let mut c = r.connect();
    let sk = SigningKey::generate(&mut OsRng);
    let Resp::Challenge(ch) = r.rpc(
        &mut c,
        &Req::EnrollBegin {
            token: r.invite(member),
            member: member.into(),
            pubkey: sk.verifying_key().to_bytes(),
        },
    ) else {
        panic!()
    };
    let proof = sk.sign(&ch.signing_bytes());
    let Resp::Enrolled { session, cert, .. } = r.rpc(
        &mut c,
        &Req::EnrollFinish {
            challenge: ch,
            proof,
        },
    ) else {
        panic!()
    };
    (
        c,
        AgentKey::from_seed_and_cert(&sk.to_bytes(), cert).unwrap(),
        session,
    )
}

#[test]
fn a_connection_that_ends_without_goodbye_is_lost_and_its_key_is_uncertified() {
    let r = rig();
    let (conn, key, session) = enrol_by_hand(&r, "shep");
    let other = r.session("h1"); // keeps the flock busy at the new epoch
    drop(conn); // no `End`: the stream is gone
    r.wait_epoch(1);
    // the old key, with its old certificate, no longer signs
    let ev = agent_mesh_flock::Event {
        flock: match r.rpc(&mut r.connect(), &Req::Hello) {
            Resp::Hello { flock, .. } => flock,
            _ => panic!(),
        },
        kind: Kind::Brief,
        author: session,
        prev: None,
        refs: Default::default(),
        files: vec![],
        at: 0,
        body: brief().1,
    };
    let node = ev.node();
    let sig = Assertion::sign(&key, &node.content_id().unwrap());
    let Resp::Err(why) = r.rpc(&mut r.connect(), &Req::Admit { node, sig }) else {
        panic!("admitted a lost session's event")
    };
    assert!(!why.is_empty());
    drop(other);
    let _ = EndReason::Lost;
}

#[test]
fn locked_memory_reports_whether_it_is_locked() {
    // AllowUnlocked never fails; Locked either locks or refuses, never lies.
    let soft = Locked::new([7u8; 32], Policy::AllowUnlocked).unwrap();
    assert_eq!(soft.get(), &[7u8; 32]);
    match Locked::new([7u8; 32], Policy::Locked) {
        Ok(l) => assert!(l.is_locked()),
        Err(e) => assert!(e.to_string().contains("mlock")),
    }
}
