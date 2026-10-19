//! The session against an in-process server.
#![cfg(all(unix, feature = "emit"))]

use agent_mesh_flock::{Body, EndReason, Kind, Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{
    bind_private, init, serve, CrashPlan, InitSpec, Server, Serving, Snapshot, Status,
};
use agent_mesh_flock_session::{Locked, Policy, Session};
use agent_mesh_protocol::{AgentKey, Assertion, UserKey};
use content_addressable::ContentAddressable;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tempfile::TempDir;

struct Rig {
    tmp: TempDir,
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
                devices: vec![],
                delegate: false,
            },
            Member {
                name: "h1".into(),
                role: Role::Helper,
                devices: vec![],
                delegate: false,
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
        tmp,
        sock,
        serving: Some(serving),
    }
}

impl Rig {
    /// Stop serving (which ends and joins every connection, so the log's
    /// lock is free on return) and reopen the log: what a restart would see.
    fn restart(&mut self) -> Server {
        if let Some(s) = self.serving.take() {
            s.stop();
        }
        Server::open(self.tmp.path()).unwrap()
    }
    fn status(&self, session: &str) -> Status {
        let snap = Snapshot::read(self.tmp.path()).unwrap();
        snap.sessions().get(session).unwrap().status
    }
    /// Block until the server stops itself on a failure to persist; the
    /// failure stops its accept loop, so joining that is the wait.
    fn wait_failure(&mut self) -> String {
        self.serving
            .take()
            .unwrap()
            .wait()
            .expect("the server stopped without reporting a failure")
    }
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
        assert!(self.serving.as_ref().unwrap().wait_epoch(n));
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

#[test]
fn a_second_enrollment_on_one_connection_is_refused_and_the_first_session_still_ends() {
    let r = rig();
    let (mut conn, _key, first) = enrol_by_hand(&r, "shep");
    // a second valid token and key, same connection
    let sk = SigningKey::generate(&mut OsRng);
    let again = r.rpc(
        &mut conn,
        &Req::EnrollBegin {
            token: r.invite("h1"),
            member: "h1".into(),
            pubkey: sk.verifying_key().to_bytes(),
        },
    );
    assert!(matches!(again, Resp::Err(_)), "{again:?}");
    drop(conn);
    r.wait_epoch(1);
    // verified replay: the connection's end ended the session it carried
    assert_eq!(r.status(&first), Status::Ended);
    assert!(Snapshot::read(r.tmp.path())
        .unwrap()
        .sessions()
        .live()
        .next()
        .is_none());
}

#[test]
fn a_goodbye_that_cannot_be_recorded_is_not_acknowledged() {
    let mut r = rig();
    let shep = r.session("shep");
    let id = shep.id().to_owned();
    r.serving
        .as_ref()
        .unwrap()
        .plan_crash(Some(CrashPlan::AfterBytes(0)));
    assert!(shep.end().is_err(), "told the end was recorded; it was not");
    r.wait_failure();
    let server = r.restart();
    assert_eq!(server.sessions().get(&id).unwrap().status, Status::Active);
    assert_eq!(server.epoch(), 0);
}

#[test]
fn a_lost_session_that_cannot_be_recorded_stops_the_server() {
    let mut r = rig();
    let (conn, _key, id) = enrol_by_hand(&r, "shep");
    r.serving
        .as_ref()
        .unwrap()
        .plan_crash(Some(CrashPlan::AfterBytes(0)));
    drop(conn);
    r.wait_failure();
    let server = r.restart();
    assert_eq!(server.sessions().get(&id).unwrap().status, Status::Active);
    assert_eq!(server.epoch(), 0);
}

#[test]
fn serving_a_log_already_at_a_later_epoch_waits_for_nothing() {
    let mut r = rig();
    r.session("shep").end().unwrap(); // a goodbye bumps the epoch: now 1
    assert!(r.serving.as_ref().unwrap().wait_epoch(1));
    let server = r.restart();
    assert_eq!(server.epoch(), 1);
    let serving = serve(server, bind_private(&r.sock).unwrap()).unwrap();
    // no request has been served yet: the predicate must start from the log
    assert!(serving.wait_epoch(1));
    r.serving = Some(serving);
}

#[test]
fn a_session_a_hand_off_activated_can_emit_because_the_server_hands_it_its_chain_head() {
    use agent_mesh_flock::{FileRef, HandoffApproval};
    use content_addressable::{MerkleNode, RawContentId};
    let r = rig();
    let (_shep_conn, shep_key, _) = enrol_by_hand(&r, "shep");
    let old = r.session("h1");
    let mut new = r.session("h1"); // pending replacement
    let approval = r.serving.as_ref().unwrap().with_server(|s| {
        MerkleNode::genesis(HandoffApproval {
            flock: s.flock(),
            member: "h1".into(),
            from: old.id().to_owned(),
            to: new.id().to_owned(),
            resume: s.sessions().get(old.id()).unwrap().start,
            context: Some(FileRef {
                root: "r".into(),
                path: "HANDOFF.md".into(),
                id: RawContentId::from_content(b"h"),
            }),
        })
    });
    let sig = Assertion::sign(&shep_key, &approval.content_id().unwrap());
    r.serving
        .as_ref()
        .unwrap()
        .with_server(|s| s.handoff(approval, sig))
        .unwrap();
    // its first event must chain from the hand-off; the session cannot know
    // that, so the server's answer to "what is my head?" has to say so
    let job = Body::Job {
        lane: "l".into(),
        label: "first".into(),
    };
    let (_, first) = new
        .emit(Kind::Job, Default::default(), job.clone())
        .unwrap();
    let (_, second) = new.emit(Kind::Job, Default::default(), job).unwrap();
    assert!(first > 0 && second == first + 1);
}

#[test]
fn a_replacement_a_hand_off_activated_can_open_a_watch_with_its_session_proof() {
    use agent_mesh_flock::{FileRef, HandoffApproval};
    use agent_mesh_flock_session::{Watch, WatchEvent};
    use content_addressable::{MerkleNode, RawContentId};
    let r = rig();
    let (_shep_conn, shep_key, _) = enrol_by_hand(&r, "shep");
    let old = r.session("h1");
    let new = r.session("h1"); // pending replacement, enrolled before the bump
    let approval = r.serving.as_ref().unwrap().with_server(|s| {
        MerkleNode::genesis(HandoffApproval {
            flock: s.flock(),
            member: "h1".into(),
            from: old.id().to_owned(),
            to: new.id().to_owned(),
            resume: s.sessions().get(old.id()).unwrap().start,
            context: Some(FileRef {
                root: "r".into(),
                path: "HANDOFF.md".into(),
                id: RawContentId::from_content(b"h"),
            }),
        })
    });
    let sig = Assertion::sign(&shep_key, &approval.content_id().unwrap());
    r.serving
        .as_ref()
        .unwrap()
        .with_server(|s| s.handoff(approval, sig))
        .unwrap();
    // its enrollment certificate is behind the epoch the hand-off raised; the
    // proof must renew first, with no emit before it
    let new = std::cell::RefCell::new(new);
    let prove = |ch: &agent_mesh_flock_server::wire::StreamChallenge| {
        new.borrow_mut()
            .prove_stream(ch)
            .map_err(|e| agent_mesh_flock_session::ReaderError::Stream(e.to_string()))
    };
    let mut w = Watch::open(&r.sock, &prove, None).unwrap();
    loop {
        match w.next_event().unwrap() {
            WatchEvent::Caught(_) => break,
            WatchEvent::Frame(_) => {}
            WatchEvent::Closed(why) => panic!("closed: {why}"),
        }
    }
}
