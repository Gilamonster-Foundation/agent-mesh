//! The human delegate: one designated member, changed only by the server,
//! whose hand-off needs a listed operator device (#127).
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::{Body, Kind, Member, Refusal, Role};
use agent_mesh_flock_server::{Server, ServerError, Status};
use agent_mesh_protocol::AgentKey;
use support::{approval, enroll, operator, sign_approval, Enrolment, Env};

fn why<T: std::fmt::Debug>(r: Result<T, ServerError>) -> String {
    match r {
        Err(ServerError::Session(w)) => w,
        other => panic!("expected a session-rule refusal, got {other:?}"),
    }
}

struct Flock {
    env: Env,
    server: Server,
    shep: Enrolment,
    old: Enrolment,
    new: Enrolment,
}

/// A shepherd, helper `h1` (active) and its pending replacement.
fn flock() -> Flock {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let old = enroll(&mut server, "h1");
    let new = enroll(&mut server, "h1");
    Flock {
        env,
        server,
        shep,
        old,
        new,
    }
}

fn roster(server: &Server, edit: impl Fn(&mut Member)) -> Vec<Member> {
    let mut ms = server.board().members().to_vec();
    ms.iter_mut().for_each(edit);
    ms
}

impl Flock {
    /// The server designates `h1` and lists `dev` as the operator's device.
    fn designate(&mut self, dev: Option<&AgentKey>) {
        let ms = roster(&self.server, |m| {
            m.delegate = m.name == "h1";
            if let (Role::Operator, Some(d)) = (m.role, dev) {
                m.devices = vec![d.fingerprint()];
            }
        });
        self.server.replace_roster(ms).unwrap();
    }
    fn shepherd_roster(&mut self, members: Vec<Member>) -> Result<(), ServerError> {
        let replaces = self.server.board().roster_id();
        let (n, s) = self.env.event(
            &self.shep.key,
            Kind::Roster,
            None,
            &[("replaces", replaces)],
            Body::Roster {
                members,
                roots: vec![],
            },
        );
        self.server.admit(n, s).map(|_| ())
    }
    fn approve_with(&mut self, key: &AgentKey) -> Result<(), ServerError> {
        let ap = approval(&self.env, &self.server, "h1", &self.old, &self.new);
        self.server
            .handoff(ap.clone(), sign_approval(key, &ap))
            .map(|_| ())
    }
    fn approve_as_shepherd(&mut self) -> Result<(), ServerError> {
        let ap = approval(&self.env, &self.server, "h1", &self.old, &self.new);
        let sig = sign_approval(&self.shep.key, &ap);
        self.server.handoff(ap, sig).map(|_| ())
    }
    fn status(&self, e: &Enrolment) -> Status {
        self.server.sessions().get(&e.session).unwrap().status
    }
}

#[test]
fn a_shepherd_cannot_designate_or_undesignate_the_delegate() {
    let mut f = flock();
    let want = roster(&f.server, |m| m.delegate = m.name == "h1");
    assert!(matches!(
        f.shepherd_roster(want),
        Err(ServerError::Refused(Refusal::DelegateLocked))
    ));
    f.designate(None);
    let none = roster(&f.server, |m| m.delegate = false);
    assert!(matches!(
        f.shepherd_roster(none),
        Err(ServerError::Refused(Refusal::DelegateLocked))
    ));
    // moving it to another member is a change too
    let moved = roster(&f.server, |m| m.delegate = m.name == "shep");
    assert!(matches!(
        f.shepherd_roster(moved),
        Err(ServerError::Refused(Refusal::DelegateLocked))
    ));
    // leaving it as it is is fine
    let same = f.server.board().members().to_vec();
    f.shepherd_roster(same).unwrap();
}

#[test]
fn at_most_one_delegate_even_from_the_server() {
    let mut f = flock();
    let two = roster(&f.server, |m| {
        m.delegate = matches!(m.name.as_str(), "h1" | "shep");
    });
    assert!(matches!(
        f.server.replace_roster(two),
        Err(ServerError::Refused(Refusal::MultipleDelegates))
    ));
    let mut spec = support::spec();
    spec.roster.iter_mut().for_each(|m| m.delegate = true);
    let dir = tempfile::TempDir::new().unwrap();
    assert!(agent_mesh_flock_server::init(
        dir.path(),
        &agent_mesh_protocol::UserKey::generate(),
        spec
    )
    .is_err());
}

#[test]
fn a_shepherd_cannot_approve_its_delegates_replacement() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.designate(Some(&dev));
    let w = why(f.approve_as_shepherd());
    assert!(w.contains("delegate"), "{w}");
    assert_eq!(f.status(&f.new), Status::Pending);
}

#[test]
fn a_helper_that_is_not_the_delegate_is_still_approved_by_the_shepherd() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.designate(Some(&dev));
    let ms = roster(&f.server, |m| m.delegate = m.name == "shep");
    f.server.replace_roster(ms).unwrap();
    f.approve_as_shepherd().unwrap();
    assert_eq!(f.status(&f.new), Status::Active);
}

#[test]
fn a_listed_device_approves_the_delegate_handoff_and_a_fresh_reader_agrees() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.designate(Some(&dev));
    f.approve_with(&dev).unwrap();
    assert_eq!(
        (f.status(&f.new), f.status(&f.old)),
        (Status::Active, Status::Ended)
    );
    drop(f.server);
    let again = f.env.open();
    assert_eq!(
        again.sessions().get(&f.new.session).unwrap().status,
        Status::Active
    );
}

#[test]
fn an_unlisted_device_does_not_approve_the_delegate_handoff() {
    let mut f = flock();
    f.designate(None);
    let dev = operator(&f.env);
    let w = why(f.approve_with(&dev));
    assert!(w.contains("not a listed operator device"), "{w}");
    assert_eq!(f.status(&f.new), Status::Pending);
}

#[test]
fn a_removed_approver_is_refused_but_its_earlier_delegate_handoff_replays() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.designate(Some(&dev));
    f.approve_with(&dev).unwrap();
    let third = enroll(&mut f.server, "h1");
    // device removed, and the designation dropped too
    let ms = roster(&f.server, |m| {
        m.devices.clear();
        m.delegate = false;
    });
    f.server.replace_roster(ms).unwrap();
    let ap = approval(&f.env, &f.server, "h1", &f.new, &third);
    let w = why(f.server.handoff(ap.clone(), sign_approval(&dev, &ap)));
    assert!(
        w.contains("not a listed operator device") || w.contains("helper"),
        "{w}"
    );
    assert_eq!(
        f.server.sessions().get(&third.session).unwrap().status,
        Status::Pending
    );
    drop(f.server);
    let again = f.env.open();
    assert_eq!(
        again.sessions().get(&f.new.session).unwrap().status,
        Status::Active
    );
}

#[test]
fn an_approval_for_another_context_or_session_does_not_carry_over() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.designate(Some(&dev));
    let third = enroll(&mut f.server, "h1");
    // signed for old -> third, presented for old -> new
    let signed_for = approval(&f.env, &f.server, "h1", &f.old, &third);
    let sig = sign_approval(&dev, &signed_for);
    let presented = approval(&f.env, &f.server, "h1", &f.old, &f.new);
    assert!(f.server.handoff(presented, sig).is_err());
    assert_eq!(f.status(&f.new), Status::Pending);
}

#[test]
fn a_delegate_approval_is_single_use() {
    let mut f = flock();
    let dev = operator(&f.env);
    f.designate(Some(&dev));
    let ap = approval(&f.env, &f.server, "h1", &f.old, &f.new);
    let sig = sign_approval(&dev, &ap);
    f.server.handoff(ap.clone(), sig.clone()).unwrap();
    assert!(f.server.handoff(ap, sig).is_err());
}
