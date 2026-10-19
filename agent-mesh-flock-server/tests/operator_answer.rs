//! An operator `answer`, signed by a listed device and verified from the log
//! alone: live at admission and again on replay at each record's index.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::{Body, ConflictKind, Event, Kind, Refusal, Role};
use agent_mesh_flock_server::{encode, seal, Frame, Server, ServerError, Snapshot};
use agent_mesh_protocol::{AgentKey, Assertion, Fingerprint, UserKey};
use content_addressable::{ContentId, MerkleNode};
use std::io::Write;
use support::{enroll, id, operator, Enrolment, Env};

struct Flock {
    env: Env,
    server: Server,
    h1: Enrolment,
    ask: ContentId,
}

fn set_devices(server: &mut Server, devices: Vec<Fingerprint>) {
    let mut ms = server.board().members().to_vec();
    for m in &mut ms {
        if m.role == Role::Operator {
            m.devices.clone_from(&devices);
        }
    }
    server.replace_roster(ms).unwrap();
}

/// An ask by `h1`, and an operator device that is neither listed nor
/// registered.
fn bare() -> (Flock, AgentKey) {
    let mut env = Env::new();
    let mut server = env.open();
    let h1 = enroll(&mut server, "h1");
    let (n, s) = env.event(
        &h1.key,
        Kind::Ask,
        None,
        &[],
        Body::Ask {
            lane: None,
            text: "which one?".into(),
        },
    );
    let ask = id(&n);
    server.admit(n, s).unwrap();
    let dev = operator(&env);
    (
        Flock {
            env,
            server,
            h1,
            ask,
        },
        dev,
    )
}

/// The same, with the device listed and its certificate registered.
fn flock() -> (Flock, AgentKey) {
    let (mut f, dev) = bare();
    set_devices(&mut f.server, vec![dev.fingerprint()]);
    f.server.register_device(dev.cert().clone()).unwrap();
    (f, dev)
}

impl Flock {
    fn answer(&mut self, key: &AgentKey, text: &str) -> (MerkleNode<Event>, Assertion) {
        self.env.event(
            key,
            Kind::Answer,
            None,
            &[("ask", self.ask)],
            Body::Answer { text: text.into() },
        )
    }
    fn admit_answer(&mut self, key: &AgentKey, text: &str) -> Result<(), ServerError> {
        let (n, s) = self.answer(key, text);
        self.server.admit(n, s).map(|_| ())
    }
}

fn refused(r: Result<(), ServerError>) -> Refusal {
    match r {
        Err(ServerError::Refused(r)) => r,
        other => panic!("expected a model refusal, got {other:?}"),
    }
}

fn signer_err(r: Result<(), ServerError>) -> String {
    match r {
        Err(ServerError::Signer(w)) => w,
        other => panic!("expected a signer refusal, got {other:?}"),
    }
}

#[test]
fn a_listed_registered_device_closes_the_ask_and_a_fresh_reader_agrees() {
    let (mut f, dev) = flock();
    f.admit_answer(&dev, "yes").unwrap();
    let first = f.server.board().closer_of(&f.ask).expect("ask closed");
    assert_eq!(
        f.server.board().get(&first).unwrap().event.author,
        dev.fingerprint().hex()
    );
    let dir = f.env.dir();
    drop(f.server);
    let snap = Snapshot::read(&dir).unwrap();
    assert_eq!(snap.board().closer_of(&f.ask), Some(first));
    assert!(Server::open(&dir).is_ok());
}

#[test]
fn a_registered_but_unlisted_device_is_refused() {
    let (mut f, dev) = bare();
    f.server.register_device(dev.cert().clone()).unwrap();
    assert_eq!(
        refused(f.admit_answer(&dev, "yes")),
        Refusal::NotAListedDevice
    );
    assert!(f.server.board().closer_of(&f.ask).is_none());
}

#[test]
fn a_listed_device_whose_certificate_was_never_registered_is_refused() {
    let (mut f, dev) = bare();
    set_devices(&mut f.server, vec![dev.fingerprint()]);
    let w = signer_err(f.admit_answer(&dev, "yes"));
    assert!(w.contains("not registered"), "{w}");
}

#[test]
fn a_device_of_another_user_cannot_be_registered_or_answer() {
    let (mut f, _) = flock();
    let stranger = AgentKey::issue(&UserKey::generate(), support::meta("operator"));
    set_devices(&mut f.server, vec![stranger.fingerprint()]);
    assert!(f.server.register_device(stranger.cert().clone()).is_err());
    signer_err(f.admit_answer(&stranger, "yes"));
}

#[test]
fn an_indirect_certificate_cannot_be_registered() {
    let (mut f, _) = flock();
    // the session's certificate is issued by the server key, not the user
    assert!(f.server.register_device(f.h1.key.cert().clone()).is_err());
}

#[test]
fn a_session_cannot_sign_an_answer() {
    let (mut f, _) = flock();
    let key = f.env.server_key();
    for k in [&f.h1.key] {
        let (n, s) = f.env.event(
            k,
            Kind::Answer,
            None,
            &[("ask", f.ask)],
            Body::Answer { text: "no".into() },
        );
        assert_eq!(
            refused(f.server.admit(n, s).map(|_| ())),
            Refusal::NotAllowed
        );
    }
    let (n, s) = f.env.event(
        &key,
        Kind::Answer,
        None,
        &[("ask", f.ask)],
        Body::Answer { text: "no".into() },
    );
    assert_eq!(
        refused(f.server.admit(n, s).map(|_| ())),
        Refusal::NotAllowed
    );
}

#[test]
fn a_tampered_answer_ask_or_flock_does_not_verify() {
    let (mut f, dev) = flock();
    // text changed after signing
    let (mut n, s) = f.answer(&dev, "yes");
    n.payload.body = Body::Answer { text: "no".into() };
    signer_err(f.server.admit(n, s).map(|_| ()));
    // the cited ask changed after signing
    let (mut n, s) = f.answer(&dev, "yes");
    let other = id(&f
        .env
        .event(
            &f.h1.key,
            Kind::Ask,
            None,
            &[],
            Body::Ask {
                lane: None,
                text: "x".into(),
            },
        )
        .0);
    n.payload.refs.insert("ask".into(), other);
    signer_err(f.server.admit(n, s).map(|_| ()));
    // signed (properly) for another flock
    let real = f.env.flock;
    f.env.flock = f.ask;
    let (n, s) = f.answer(&dev, "yes");
    f.env.flock = real;
    assert_eq!(
        refused(f.server.admit(n, s).map(|_| ())),
        Refusal::WrongFlock
    );
    assert!(f.server.board().closer_of(&f.ask).is_none());
}

#[test]
fn a_revoked_device_is_refused_now_but_its_earlier_answer_still_replays() {
    let (mut f, dev) = flock();
    f.admit_answer(&dev, "yes").unwrap();
    let first = f.server.board().closer_of(&f.ask).unwrap();
    set_devices(&mut f.server, vec![]);
    assert_eq!(
        refused(f.admit_answer(&dev, "again")),
        Refusal::NotAListedDevice
    );
    let dir = f.env.dir();
    drop(f.server);
    assert_eq!(
        Snapshot::read(&dir).unwrap().board().closer_of(&f.ask),
        Some(first)
    );
    assert!(Server::open(&dir).is_ok());
}

#[test]
fn a_registration_is_not_repeated_and_grants_no_listing() {
    let (mut f, dev) = flock();
    assert!(f.server.register_device(dev.cert().clone()).is_err());
    let (mut g, dev2) = bare();
    g.server.register_device(dev2.cert().clone()).unwrap();
    assert_eq!(
        refused(g.admit_answer(&dev2, "x")),
        Refusal::NotAListedDevice
    );
}

#[test]
fn a_session_may_not_register_a_device() {
    let (mut f, dev) = bare();
    let (n, s) = f.env.event(
        &f.h1.key,
        Kind::DeviceCert,
        None,
        &[],
        Body::DeviceCert {
            cert: dev.cert().clone(),
        },
    );
    assert_eq!(
        refused(f.server.admit(n, s).map(|_| ())),
        Refusal::NotAllowed
    );
}

#[test]
fn a_logged_answer_whose_device_certificate_is_missing_fails_replay_in_both_readers() {
    let (mut f, dev) = bare();
    set_devices(&mut f.server, vec![dev.fingerprint()]);
    // seal the answer by hand: live admission would refuse it
    let key = f.env.server_key();
    let (n, s) = f.answer(&dev, "yes");
    let sealed = seal(
        &key,
        f.server.head_record(),
        f.server.admitted() + 1,
        f.server.epoch(),
        n,
        s,
    )
    .unwrap();
    let env = f.env;
    drop(f.server);
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .open(env.log_path())
        .unwrap();
    log.write_all(
        &encode(&Frame {
            sealed: vec![sealed],
        })
        .unwrap(),
    )
    .unwrap();
    drop(log);
    let why = |r: Result<(), ServerError>| r.unwrap_err().to_string();
    let opened = Server::open(&env.dir()).map(|_| ());
    assert!(why(opened).contains("does not hold"), "Server::open");
    let read = Snapshot::read(&env.dir()).map(|_| ());
    assert!(why(read).contains("does not hold"), "Snapshot::read");
}

#[test]
fn a_second_answer_is_a_conflict_and_a_relay_closes_nothing() {
    let (mut f, dev) = flock();
    // a member's copy first: it closes nothing
    let prev = f.server.board().head_of(&f.h1.session);
    let (n, s) = f.env.event(
        &f.h1.key,
        Kind::RelayedAnswer,
        prev,
        &[("ask", f.ask)],
        Body::RelayedAnswer { text: "yes".into() },
    );
    f.server.admit(n, s).unwrap();
    assert!(f.server.board().closer_of(&f.ask).is_none());
    f.admit_answer(&dev, "yes").unwrap();
    let first = f.server.board().closer_of(&f.ask).unwrap();
    let (n, s) = f.answer(&dev, "different");
    let r = f.server.admit(n, s).unwrap();
    assert_eq!(r.conflict, Some(ConflictKind::SecondCloser { first }));
    assert_eq!(f.server.board().closer_of(&f.ask), Some(first));
}
