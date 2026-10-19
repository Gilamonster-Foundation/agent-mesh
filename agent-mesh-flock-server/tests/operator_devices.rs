//! Operator devices: the roster lists them, and only a listed device's
//! signature approves a shepherd hand-off (#127).
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::{Body, Kind, Member, Refusal, Role};
use agent_mesh_flock_server::{load_genesis, SignedGenesis, Snapshot, GENESIS_FILE};
use agent_mesh_flock_server::{Server, ServerError, Status};
use agent_mesh_protocol::Assertion;
use agent_mesh_protocol::{AgentKey, Fingerprint, UserKey};
use content_addressable::canonical::to_canonical_dagcbor;
use content_addressable::ContentAddressable;
use support::{approval, enroll, operator, sign_approval, Enrolment, Env};

fn why<T: std::fmt::Debug>(r: Result<T, ServerError>) -> String {
    match r {
        Err(ServerError::Session(w)) => w,
        other => panic!("expected a session-rule refusal, got {other:?}"),
    }
}

/// The roster with `devices` listed under the operator member.
fn with_devices(server: &Server, devices: Vec<Fingerprint>) -> Vec<Member> {
    server
        .board()
        .members()
        .iter()
        .cloned()
        .map(|mut m| {
            if m.role == Role::Operator {
                m.devices.clone_from(&devices);
            }
            m
        })
        .collect()
}

struct Flock {
    env: Env,
    server: Server,
    shep: Enrolment,
    shep2: Enrolment,
}

/// An active shepherd and a pending replacement for it.
fn flock() -> Flock {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let shep2 = enroll(&mut server, "shep");
    assert!(shep2.pending);
    Flock {
        env,
        server,
        shep,
        shep2,
    }
}

impl Flock {
    fn list(&mut self, devices: Vec<Fingerprint>) {
        let roster = with_devices(&self.server, devices);
        self.server.replace_roster(roster).unwrap();
    }
    fn approve_with(&mut self, key: &AgentKey) -> Result<(), ServerError> {
        let ap = approval(&self.env, &self.server, "shep", &self.shep, &self.shep2);
        self.server
            .handoff(ap.clone(), sign_approval(key, &ap))
            .map(|_| ())
    }
    fn holder(&self, e: &Enrolment) -> Status {
        self.server.sessions().get(&e.session).unwrap().status
    }
}

#[test]
fn a_key_certified_by_the_same_user_but_not_listed_is_refused() {
    let mut f = flock();
    let dev = operator(&f.env);
    let before = f.server.board().entries().count();
    let w = why(f.approve_with(&dev));
    assert!(w.contains("not a listed operator device"), "{w}");
    assert_eq!(
        (f.server.epoch(), f.server.board().entries().count()),
        (0, before)
    );
    assert_eq!(f.holder(&f.shep2), Status::Pending);
}

#[test]
fn a_listed_device_approves_a_shepherd_handoff_and_a_fresh_reader_agrees() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.list(vec![dev.fingerprint()]);
    f.approve_with(&dev).unwrap();
    assert_eq!(f.holder(&f.shep2), Status::Active);
    assert_eq!(f.holder(&f.shep), Status::Ended);
    // replay from the log alone reaches the same state
    drop(f.server);
    let again = f.env.open();
    assert_eq!(
        again.sessions().get(&f.shep2.session).unwrap().status,
        Status::Active
    );
}

#[test]
fn a_removed_device_cannot_approve_but_its_earlier_handoff_still_replays() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.list(vec![dev.fingerprint()]);
    f.approve_with(&dev).unwrap();
    // a second replacement, then the device is removed
    let shep3 = enroll(&mut f.server, "shep");
    f.list(vec![]);
    let ap = approval(&f.env, &f.server, "shep", &f.shep2, &shep3);
    let w = why(f.server.handoff(ap.clone(), sign_approval(&dev, &ap)));
    assert!(w.contains("not a listed operator device"), "{w}");
    assert_eq!(f.holder(&shep3), Status::Pending);
    // the hand-off admitted while it was listed is still part of the log
    drop(f.server);
    let again = f.env.open();
    assert_eq!(
        again.sessions().get(&f.shep2.session).unwrap().status,
        Status::Active
    );
}

#[test]
fn a_device_certified_by_another_user_is_refused_even_if_listed() {
    let mut f = flock();
    let stranger = AgentKey::issue(&UserKey::generate(), support::meta("operator"));
    f.list(vec![stranger.fingerprint()]);
    let w = why(f.approve_with(&stranger));
    assert!(w.contains("approval"), "{w}");
    assert_eq!(f.holder(&f.shep2), Status::Pending);
}

#[test]
fn a_device_approves_shepherds_only() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.list(vec![dev.fingerprint()]);
    let old = enroll(&mut f.server, "h1");
    let new = enroll(&mut f.server, "h1");
    let ap = approval(&f.env, &f.server, "h1", &old, &new);
    let w = why(f.server.handoff(ap.clone(), sign_approval(&dev, &ap)));
    assert!(w.contains("shepherd"), "{w}");
    assert_eq!(f.holder(&new), Status::Pending);
}

#[test]
fn a_shepherd_cannot_change_the_device_list() {
    let mut f = flock();
    let dev = operator(&f.env);
    // the shepherd lists its own idea of a device
    let roster = with_devices(&f.server, vec![dev.fingerprint()]);
    let replaces = f.server.board().roster_id();
    let (n, s) = f.env.event(
        &f.shep.key,
        Kind::Roster,
        None,
        &[("replaces", replaces)],
        Body::Roster {
            members: roster,
            roots: vec![],
        },
    );
    assert!(matches!(
        f.server.admit(n, s),
        Err(ServerError::Refused(Refusal::DevicesLocked))
    ));
    // unchanged devices are fine
    let roster = f.server.board().members().to_vec();
    let (n, s) = f.env.event(
        &f.shep.key,
        Kind::Roster,
        None,
        &[("replaces", replaces)],
        Body::Roster {
            members: roster,
            roots: vec![],
        },
    );
    f.server.admit(n, s).unwrap();
}

#[test]
fn devices_belong_to_operator_members_only() {
    let mut f = flock();
    let dev = operator(&f.env);
    let mut roster = f.server.board().members().to_vec();
    roster
        .iter_mut()
        .find(|m| m.role == Role::Helper)
        .unwrap()
        .devices = vec![dev.fingerprint()];
    assert!(matches!(
        f.server.replace_roster(roster),
        Err(ServerError::Refused(Refusal::DevicesOnNonOperator))
    ));
}

#[test]
fn a_signed_genesis_listing_a_device_under_a_helper_is_refused_by_both_readers() {
    let env = Env::new();
    let dev = operator(&env);
    // re-sign the genesis with a device under the helper, as a hostile or
    // buggy `init` could have written it
    let mut g = load_genesis(&env.dir()).unwrap();
    for m in &mut g.node.payload.roster {
        if m.role == Role::Helper {
            m.devices = vec![dev.fingerprint()];
        }
    }
    let node = g.node.payload.clone().node();
    let sig = Assertion::sign(&env.server_key(), &node.content_id().unwrap());
    let bytes = to_canonical_dagcbor(&SignedGenesis { node, sig }).unwrap();
    std::fs::write(env.dir().join(GENESIS_FILE), bytes).unwrap();
    assert!(Server::open(&env.dir()).is_err(), "Server::open");
    assert!(Snapshot::read(&env.dir()).is_err(), "Snapshot::read");
}

#[test]
fn a_shepherd_roster_that_only_reorders_is_admitted_and_reassigning_is_not() {
    let mut f = flock();
    let (d1, d2) = (operator(&f.env), operator(&f.env));
    // two operators, each with a device
    let mut roster = f.server.board().members().to_vec();
    roster.push(Member {
        name: "op2".into(),
        role: Role::Operator,
        devices: vec![d2.fingerprint()],
    });
    for m in &mut roster {
        if m.name == "op" {
            m.devices = vec![d1.fingerprint()];
        }
    }
    f.server.replace_roster(roster).unwrap();
    let send = |f: &mut Flock, members: Vec<Member>| {
        let replaces = f.server.board().roster_id();
        let (n, s) = f.env.event(
            &f.shep.key,
            Kind::Roster,
            None,
            &[("replaces", replaces)],
            Body::Roster {
                members,
                roots: vec![],
            },
        );
        f.server.admit(n, s)
    };
    // reordered members: admitted
    let mut reordered = f.server.board().members().to_vec();
    reordered.reverse();
    send(&mut f, reordered).unwrap();
    // swapping which operator holds which device, adding or removing one: locked
    let swap = |mut ms: Vec<Member>| {
        let (a, b) = (
            ms.iter().position(|m| m.name == "op").unwrap(),
            ms.iter().position(|m| m.name == "op2").unwrap(),
        );
        let (da, db) = (ms[a].devices.clone(), ms[b].devices.clone());
        ms[a].devices = db;
        ms[b].devices = da;
        ms
    };
    let cur = f.server.board().members().to_vec();
    let mut removed = cur.clone();
    removed
        .iter_mut()
        .find(|m| m.name == "op2")
        .unwrap()
        .devices
        .clear();
    let mut added = cur.clone();
    added
        .iter_mut()
        .find(|m| m.name == "op")
        .unwrap()
        .devices
        .push(d2.fingerprint());
    for (what, ms) in [
        ("reassigned", swap(cur.clone())),
        ("removed", removed),
        ("added", added),
    ] {
        assert!(
            matches!(
                send(&mut f, ms),
                Err(ServerError::Refused(Refusal::DevicesLocked))
            ),
            "{what}"
        );
    }
}

fn resign_genesis(env: &Env, edit: impl FnOnce(&mut Vec<Member>)) {
    let mut g = load_genesis(&env.dir()).unwrap();
    edit(&mut g.node.payload.roster);
    let node = g.node.payload.clone().node();
    let sig = Assertion::sign(&env.server_key(), &node.content_id().unwrap());
    let bytes = to_canonical_dagcbor(&SignedGenesis { node, sig }).unwrap();
    std::fs::write(env.dir().join(GENESIS_FILE), bytes).unwrap();
}

#[test]
fn a_genesis_with_duplicate_member_names_is_refused_by_both_readers() {
    let env = Env::new();
    resign_genesis(&env, |r| {
        let dup = r[0].clone();
        r.push(dup);
    });
    assert!(Server::open(&env.dir()).is_err(), "Server::open");
    assert!(Snapshot::read(&env.dir()).is_err(), "Snapshot::read");
}

#[test]
fn init_refuses_duplicate_member_names() {
    let mut spec = support::spec();
    let dup = spec.roster[0].clone();
    spec.roster.push(dup);
    let dir = tempfile::TempDir::new().unwrap();
    assert!(agent_mesh_flock_server::init(dir.path(), &UserKey::generate(), spec).is_err());
}

/// A second `op` (with a device of the attacker's choosing) ahead of the real
/// one must not be admitted, whoever signs it.
fn roster_with_a_second_op(server: &Server, device: Fingerprint) -> Vec<Member> {
    let mut roster = server.board().members().to_vec();
    roster.insert(
        0,
        Member {
            name: "op".into(),
            role: Role::Operator,
            devices: vec![device],
        },
    );
    roster
}

#[test]
fn a_second_member_of_the_same_name_is_refused_at_admission() {
    let mut f = flock();
    let dev = operator(&f.env);
    let real = operator(&f.env);
    f.list(vec![real.fingerprint()]);
    let roster = roster_with_a_second_op(&f.server, dev.fingerprint());
    let replaces = f.server.board().roster_id();
    let (n, s) = f.env.event(
        &f.shep.key,
        Kind::Roster,
        None,
        &[("replaces", replaces)],
        Body::Roster {
            members: roster.clone(),
            roots: vec![],
        },
    );
    assert!(matches!(
        f.server.admit(n, s),
        Err(ServerError::Refused(Refusal::DuplicateMember))
    ));
    // not even the server may
    assert!(matches!(
        f.server.replace_roster(roster),
        Err(ServerError::Refused(Refusal::DuplicateMember))
    ));
    // and the attacker's device approves nothing
    let w = why(f.approve_with(&dev));
    assert!(w.contains("not a listed operator device"), "{w}");
}

#[test]
fn a_logged_roster_with_duplicate_names_is_refused_on_replay_by_both_readers() {
    use agent_mesh_flock_server::{encode, seal, Frame};
    use std::io::Write;
    let mut f = flock();
    let key = f.env.server_key();
    let roster = roster_with_a_second_op(&f.server, operator(&f.env).fingerprint());
    let replaces = f.server.board().roster_id();
    let prev = f.server.board().head_of(&key.fingerprint().hex());
    let (n, s) = f.env.event(
        &key,
        Kind::Roster,
        prev,
        &[("replaces", replaces)],
        Body::Roster {
            members: roster,
            roots: vec![],
        },
    );
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
    assert!(Server::open(&env.dir()).is_err(), "Server::open");
    assert!(Snapshot::read(&env.dir()).is_err(), "Snapshot::read");
}
