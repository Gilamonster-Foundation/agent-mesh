//! Operator devices: the roster lists them, and only a listed device's
//! signature approves a shepherd hand-off (#127).
#![cfg(unix)]
mod support;

use agent_mesh_flock::{Body, Kind, Member, Refusal, Role};
use agent_mesh_flock_server::{Server, ServerError, Status};
use agent_mesh_protocol::{AgentKey, Fingerprint, UserKey};
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
        Body::Roster { members: roster },
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
        Body::Roster { members: roster },
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
