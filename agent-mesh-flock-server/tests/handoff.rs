//! Hand-off: pending replacements, the single-use approval, zombies.
#![cfg(unix)]
mod support;

use agent_mesh_flock::{Body, EndReason, Kind, Refusal};
use agent_mesh_flock_server::{encode, seal, CrashPlan, Frame, Server, ServerError, Status};
use content_addressable::{ContentAddressable, ContentId};
use support::{
    approval, enroll, id, operator, read_frames, renew_all, sign_approval, Enrolment, Env,
};

fn session_err<T: std::fmt::Debug>(r: Result<T, ServerError>) -> String {
    match r {
        Err(ServerError::Session(why)) => why,
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

/// A shepherd, a helper `h1` (active) and a replacement for `h1` (pending).
fn flock() -> Flock {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let old = enroll(&mut server, "h1");
    let new = enroll(&mut server, "h1");
    assert!(new.pending);
    Flock {
        env,
        server,
        shep,
        old,
        new,
    }
}

impl Flock {
    /// The shepherd approves `from -> to` and the server hands off.
    fn handoff(&mut self, from: &Enrolment, to: &Enrolment) -> Result<(), ServerError> {
        let ap = approval(&self.env, &self.server, "h1", from, to);
        let sig = sign_approval(&self.shep.key, &ap);
        self.server.handoff(ap, sig).map(|_| ())
    }
}

#[test]
fn a_pending_replacement_cannot_sign_before_the_handoff_and_can_after() {
    let mut f = flock();
    let (n, s) = f.env.brief(&f.new.key, None, "lane-a");
    // pending: refused by the table
    assert!(matches!(
        f.server.admit(n, s),
        Err(ServerError::Refused(Refusal::PendingSession))
    ));
    let (old, new) = (clone(&f.old), clone(&f.new));
    f.handoff(&old, &new).unwrap();
    assert_eq!(
        f.server.sessions().get(&f.new.session).unwrap().status,
        Status::Active
    );
    assert_eq!(
        f.server.sessions().get(&f.old.session).unwrap().status,
        Status::Ended
    );
    assert_eq!(f.server.epoch(), 1);
}

/// `Enrolment` holds a key; rebuild one with the same seed and certificate.
fn clone(e: &Enrolment) -> Enrolment {
    Enrolment {
        sk: e.sk.clone(),
        key: agent_mesh_protocol::AgentKey::from_seed_and_cert(
            &e.sk.to_bytes(),
            e.key.cert().clone(),
        )
        .unwrap(),
        session: e.session.clone(),
        pending: e.pending,
    }
}

#[test]
fn the_handoff_is_one_frame_with_its_epoch_bump_and_resumes_at_the_last_head() {
    let mut f = flock();
    let (n, s) = f.env.event(
        &f.old.key,
        Kind::Job,
        None,
        &[],
        Body::Job {
            lane: "lane-a".into(),
            label: "x".into(),
        },
    );
    let last = id(&n);
    f.server.admit(n, s).unwrap();
    let (old, new) = (clone(&f.old), clone(&f.new));
    f.handoff(&old, &new).unwrap();
    let frames = read_frames(&f.env);
    let frame = frames.last().unwrap();
    let kinds: Vec<_> = frame.sealed.iter().map(|s| s.event.payload.kind).collect();
    assert_eq!(kinds, [Kind::Handoff, Kind::Epoch]);
    let Body::Handoff { resume, .. } = &frame.sealed[0].event.payload.body else {
        panic!("handoff body")
    };
    assert_eq!(*resume, last, "resume is the old session's last head");
}

#[test]
fn the_new_sessions_first_event_has_prev_equal_to_the_handoff() {
    let mut f = flock();
    let (old, new) = (clone(&f.old), clone(&f.new));
    f.handoff(&old, &new).unwrap();
    let mut new = new;
    let mut shep = clone(&f.shep);
    renew_all(&mut f.server, &mut [&mut new, &mut shep]);
    let handoff_id = f
        .server
        .board()
        .entries()
        .find(|e| e.event.kind == Kind::Handoff)
        .map(|e| e.id)
        .unwrap();
    // no prev, or a prev that is not the handoff: refused
    let (n, s) = f.env.brief(&new.key, None, "lane-a");
    assert!(f.server.admit(n, s).is_err(), "no prev");
    let (n, s) = f
        .env
        .brief(&new.key, Some(f.server.head_record()), "lane-a");
    assert!(f.server.admit(n, s).is_err(), "some other prev");
    // prev = handoff: admitted (a helper may not brief, so use a job)
    let (n, s) = f.env.event(
        &new.key,
        Kind::Job,
        Some(handoff_id),
        &[],
        Body::Job {
            lane: "lane-a".into(),
            label: "resumed".into(),
        },
    );
    f.server.admit(n, s).unwrap();
}

#[test]
fn a_lost_session_leaves_the_replacement_pending_until_a_handoff() {
    let mut f = flock();
    f.server
        .end_session(&f.old.session, EndReason::Lost)
        .unwrap();
    let mut late = enroll(&mut f.server, "h1");
    assert!(
        late.pending,
        "r4-2: pending even though the member has no live session"
    );
    let mut shep = clone(&f.shep);
    renew_all(&mut f.server, &mut [&mut late, &mut shep]);
    let (n, s) = f.env.event(
        &late.key,
        Kind::Job,
        None,
        &[],
        Body::Job {
            lane: "l".into(),
            label: "x".into(),
        },
    );
    assert!(matches!(
        f.server.admit(n, s),
        Err(ServerError::Refused(Refusal::PendingSession))
    ));
    // the shepherd (renewed) approves the recovery
    f.shep = shep;
    let old = clone(&f.old);
    f.handoff(&old, &late).unwrap();
    assert_eq!(
        f.server.sessions().get(&late.session).unwrap().status,
        Status::Active
    );
}

#[test]
fn a_lost_zombie_cannot_sign_after_the_handoff() {
    let mut f = flock();
    let old = clone(&f.old);
    let new = clone(&f.new);
    f.handoff(&old, &new).unwrap();
    let (n, s) = f.env.event(
        &f.old.key,
        Kind::Job,
        None,
        &[],
        Body::Job {
            lane: "l".into(),
            label: "zombie".into(),
        },
    );
    assert!(matches!(f.server.admit(n, s), Err(ServerError::Signer(_))));
}

#[test]
fn two_competing_replacements_one_is_activated_and_the_other_stays_pending() {
    let mut f = flock();
    let rival = enroll(&mut f.server, "h1");
    let (old, new, rival_c) = (clone(&f.old), clone(&f.new), clone(&rival));
    // approvals for both are in hand; the first to land wins
    let ap_new = approval(&f.env, &f.server, "h1", &old, &new);
    let ap_rival = approval(&f.env, &f.server, "h1", &old, &rival_c);
    let (s1, s2) = (
        sign_approval(&f.shep.key, &ap_new),
        sign_approval(&f.shep.key, &ap_rival),
    );
    f.server.handoff(ap_new, s1).unwrap();
    let why = session_err(f.server.handoff(ap_rival, s2));
    assert!(why.contains("holder"), "{why}");
    let st = |s: &str| f.server.sessions().get(s).unwrap().status;
    assert_eq!(st(&new.session), Status::Active);
    assert_eq!(st(&rival.session), Status::Pending);
    assert_eq!(f.server.epoch(), 1, "the loser bumped nothing");
}

#[test]
fn a_replayed_approval_is_refused() {
    let mut f = flock();
    let (old, new) = (clone(&f.old), clone(&f.new));
    let ap = approval(&f.env, &f.server, "h1", &old, &new);
    let sig = sign_approval(&f.shep.key, &ap);
    f.server.handoff(ap.clone(), sig.clone()).unwrap();
    let before = f.server.admitted();
    session_err(f.server.handoff(ap, sig));
    assert_eq!(f.server.admitted(), before);
}

#[test]
fn only_the_roster_authority_can_approve() {
    let mut f = flock();
    let (old, new) = (clone(&f.old), clone(&f.new));
    let ap = approval(&f.env, &f.server, "h1", &old, &new);
    // a helper session (the old one itself) is not the authority
    let sig = sign_approval(&f.old.key, &ap);
    session_err(f.server.handoff(ap.clone(), sig));
    // a signature over something else
    let other = approval(&f.env, &f.server, "h1", &new, &old);
    let sig = sign_approval(&f.shep.key, &other);
    session_err(f.server.handoff(ap.clone(), sig));
    // a stranger's key
    let stranger = agent_mesh_protocol::AgentKey::issue(
        &agent_mesh_protocol::UserKey::generate(),
        support::meta("op"),
    );
    session_err(f.server.handoff(ap.clone(), sign_approval(&stranger, &ap)));
    // the server's own key does not approve its own hand-offs
    let server_key = f.env.server_key();
    session_err(
        f.server
            .handoff(ap.clone(), sign_approval(&server_key, &ap)),
    );
    assert_eq!(f.server.epoch(), 0);
    // the shepherd can
    f.server
        .handoff(ap.clone(), sign_approval(&f.shep.key, &ap))
        .unwrap();
}

#[test]
fn the_shepherd_replaces_helpers_only() {
    let mut f = flock();
    // protected targets: shepherd, operator and adapter roles, each refused
    for member in ["shep", "op", "herdr"] {
        let a = if member == "shep" {
            clone(&f.shep)
        } else {
            enroll(&mut f.server, member)
        };
        let b = enroll(&mut f.server, member);
        let ap = approval(&f.env, &f.server, member, &a, &b);
        let why = session_err(
            f.server
                .handoff(ap.clone(), sign_approval(&f.shep.key, &ap)),
        );
        assert!(why.contains("helper"), "{member}: {why}");
        assert_eq!(
            f.server.sessions().get(&b.session).unwrap().status,
            Status::Pending
        );
    }
    assert_eq!(f.server.epoch(), 0);
}

#[test]
fn a_user_certified_key_is_not_an_operator_device() {
    let mut f = flock();
    let (old, new) = (clone(&f.old), clone(&f.new));
    let ap = approval(&f.env, &f.server, "h1", &old, &new);
    let before = f.server.board().entries().count();
    let why = session_err(
        f.server
            .handoff(ap.clone(), sign_approval(&operator(&f.env), &ap)),
    );
    assert!(why.contains("not a listed operator device"), "{why}");
    assert_eq!(
        (f.server.epoch(), f.server.board().entries().count()),
        (0, before)
    );
    assert_eq!(
        f.server.sessions().get(&new.session).unwrap().status,
        Status::Pending
    );
    // not even for the shepherd's own role
    let shep2 = enroll(&mut f.server, "shep");
    let shep = clone(&f.shep);
    let ap = approval(&f.env, &f.server, "shep", &shep, &shep2);
    session_err(
        f.server
            .handoff(ap.clone(), sign_approval(&operator(&f.env), &ap)),
    );
}

#[test]
fn a_handoff_without_its_context_is_refused_and_changes_nothing() {
    let mut f = flock();
    let (old, new) = (clone(&f.old), clone(&f.new));
    let mut ap = approval(&f.env, &f.server, "h1", &old, &new);
    ap.payload.context = None;
    let before = f.server.board().entries().count();
    let why = session_err(
        f.server
            .handoff(ap.clone(), sign_approval(&f.shep.key, &ap)),
    );
    assert!(why.contains("context"), "{why}");
    assert_eq!(
        (f.server.epoch(), f.server.board().entries().count()),
        (0, before)
    );
    assert_eq!(
        f.server.sessions().get(&new.session).unwrap().status,
        Status::Pending
    );
    assert_eq!(
        f.server.sessions().get(&old.session).unwrap().status,
        Status::Active
    );
}

#[test]
fn a_foreign_flocks_approval_is_refused() {
    let mut f = flock();
    let (old, new) = (clone(&f.old), clone(&f.new));
    let mut ap = approval(&f.env, &f.server, "h1", &old, &new);
    ap.payload.flock = f.env.flock;
    let other_env = Env::new();
    let foreign = approval(&other_env, &f.server, "h1", &old, &new);
    session_err(
        f.server
            .handoff(foreign.clone(), sign_approval(&f.shep.key, &foreign)),
    );
    // wrong member for the sessions named
    let mut wrong = ap.clone();
    wrong.payload.member = "shep".into();
    session_err(
        f.server
            .handoff(wrong.clone(), sign_approval(&f.shep.key, &wrong)),
    );
    // resume that is not the old session's last head
    let mut stale = ap.clone();
    stale.payload.resume = f.env.flock;
    // (the model refuses an unknown reference before the session rules do)
    assert!(f
        .server
        .handoff(stale.clone(), sign_approval(&f.shep.key, &stale))
        .is_err());
    // a resume that is a real event but not the last head
    let mut old_head = ap.clone();
    old_head.payload.resume = f.server.sessions().get(&f.shep.session).unwrap().start;
    let why = session_err(
        f.server
            .handoff(old_head.clone(), sign_approval(&f.shep.key, &old_head)),
    );
    assert!(why.contains("last head"), "{why}");
    // to is not pending (the holder itself)
    let mut active = ap.clone();
    active.payload.to = f.shep.session.clone();
    session_err(
        f.server
            .handoff(active.clone(), sign_approval(&f.shep.key, &active)),
    );
}

#[test]
fn a_standalone_handoff_is_refused_live_and_a_frame_without_its_bump_fails_open() {
    let mut f = flock();
    let key = f.env.server_key();
    let (old, new) = (clone(&f.old), clone(&f.new));
    let ap = approval(&f.env, &f.server, "h1", &old, &new);
    let sig = sign_approval(&f.shep.key, &ap);
    let (start_old, start_new) = (
        f.server.sessions().get(&old.session).unwrap().start,
        f.server.sessions().get(&new.session).unwrap().start,
    );
    let resume = ap.payload.resume;
    let (n, s) = f.env.event(
        &key,
        Kind::Handoff,
        None,
        &[("from", start_old), ("to", start_new), ("resume", resume)],
        Body::Handoff {
            from: old.session.clone(),
            to: new.session.clone(),
            resume,
            context: support::approval_context(),
            approval: Box::new(ap.clone()),
            approval_sig: Box::new(sig.clone()),
        },
    );
    let why = session_err(f.server.admit(n, s));
    assert!(why.contains("epoch"), "{why}");
    f.server.handoff(ap, sig).unwrap();
    drop(f.server);
    let mut frames = read_frames(&f.env);
    frames.last_mut().unwrap().sealed.truncate(1);
    let bytes: Vec<u8> = frames.iter().flat_map(|fr| encode(fr).unwrap()).collect();
    std::fs::write(f.env.log_path(), &bytes).unwrap();
    assert!(matches!(
        Server::open(&f.env.dir()),
        Err(ServerError::Corrupt { .. })
    ));
    assert_eq!(std::fs::read(f.env.log_path()).unwrap(), bytes);
}

#[test]
fn a_crash_during_the_handoff_leaves_both_events_or_neither_and_the_approval_stays_usable() {
    for plan in [
        CrashPlan::AfterBytes(9),
        CrashPlan::BeforeSync,
        CrashPlan::AfterSync,
    ] {
        let mut f = flock();
        let (old, new) = (clone(&f.old), clone(&f.new));
        let ap = approval(&f.env, &f.server, "h1", &old, &new);
        let sig = sign_approval(&f.shep.key, &ap);
        f.server.plan_crash(Some(plan));
        assert!(f.server.handoff(ap.clone(), sig.clone()).is_err());
        let env = f.env;
        drop(f.server);
        let mut server = env.open();
        let whole = matches!(plan, CrashPlan::BeforeSync | CrashPlan::AfterSync);
        let active = server.sessions().get(&new.session).unwrap().status == Status::Active;
        assert_eq!(
            (active, server.epoch()),
            (whole, u64::from(whole)),
            "{plan:?}"
        );
        if !whole {
            server.handoff(ap, sig).unwrap();
        }
    }
}

#[test]
fn holder_activation_and_the_prev_rule_are_rebuilt_from_the_frames() {
    let mut f = flock();
    let (old, new) = (clone(&f.old), clone(&f.new));
    f.handoff(&old, &new).unwrap();
    let env = f.env;
    drop(f.server);
    let mut server = env.open();
    let mut env = env;
    assert_eq!(
        server.sessions().get(&new.session).unwrap().status,
        Status::Active
    );
    assert_eq!(
        server.sessions().get(&old.session).unwrap().status,
        Status::Ended
    );
    // the old session is no longer the holder: a fresh pending replacement
    // cannot be handed off from it
    let third = enroll(&mut server, "h1");
    let ap = approval(&env, &server, "h1", &old, &third);
    let sig = sign_approval(&f.shep.key, &ap);
    // (the shepherd's certificate is behind the epoch after the bump)
    assert!(server.handoff(ap, sig).is_err());
    let mut new = clone(&new);
    let mut shep = clone(&f.shep);
    let mut third = third;
    renew_all(&mut server, &mut [&mut new, &mut shep, &mut third]);
    let ap = approval(&env, &server, "h1", &old, &third);
    let why = session_err(server.handoff(ap.clone(), sign_approval(&shep.key, &ap)));
    assert!(why.contains("holder"), "{why}");
    // and the new session still must link to the handoff
    let (n, s) = env.event(
        &new.key,
        Kind::Job,
        None,
        &[],
        Body::Job {
            lane: "l".into(),
            label: "x".into(),
        },
    );
    assert!(server.admit(n, s).is_err());
}

/// Append a server-signed `[handoff, epoch]` frame by hand, the way a log
/// edited on disk would carry one. `body_to` and `ref_to` can disagree with the
/// approval the event cites.
fn forged_handoff_frame(f: &mut Flock, body_to: &str, ref_to: Option<ContentId>) -> Frame {
    let key = f.env.server_key();
    let (old, new) = (clone(&f.old), clone(&f.new));
    let ap = approval(&f.env, &f.server, "h1", &old, &new);
    let sig = sign_approval(&f.shep.key, &ap);
    let starts = |s: &str| f.server.sessions().get(s).unwrap().start;
    let (so, sn) = (starts(&old.session), starts(&new.session));
    let resume = ap.payload.resume;
    let (head, index, epoch) = (
        f.server.head_record(),
        f.server.admitted() + 1,
        f.server.epoch(),
    );
    let prev = f.server.board().head_of(&key.fingerprint().hex());
    let (h, hs) = f.env.event(
        &key,
        Kind::Handoff,
        prev,
        &[
            ("from", so),
            ("resume", resume),
            ("to", ref_to.unwrap_or(sn)),
        ],
        Body::Handoff {
            from: old.session.clone(),
            to: body_to.to_owned(),
            resume,
            context: support::approval_context(),
            approval: Box::new(ap),
            approval_sig: Box::new(sig),
        },
    );
    let first = seal(&key, head, index, epoch, h.clone(), hs).unwrap();
    let rec = first.record.content_id().unwrap();
    let (e, es) = f.env.event(
        &key,
        Kind::Epoch,
        Some(h.content_id().unwrap()),
        &[],
        Body::Epoch { epoch: epoch + 1 },
    );
    let second = seal(&key, rec, index + 1, epoch + 1, e, es).unwrap();
    Frame {
        sealed: vec![first, second],
    }
}

#[test]
fn a_handoff_frame_written_by_hand_is_checked_on_replay() {
    use std::io::Write;
    let cases: [(&str, bool); 4] = [
        ("honest", true),
        ("the event names another session than its approval", false),
        ("the references are not the sessions it names", false),
        ("the approval's sessions do not exist", false),
    ];
    for (i, (name, ok)) in cases.into_iter().enumerate() {
        let mut f = flock();
        let rival = enroll(&mut f.server, "h1");
        let new_session = f.new.session.clone();
        let old_start = f.server.sessions().get(&f.old.session).unwrap().start;
        let frame = match i {
            0 => forged_handoff_frame(&mut f, &new_session, None),
            1 => {
                let start = f.server.sessions().get(&rival.session).unwrap().start;
                forged_handoff_frame(&mut f, &rival.session, Some(start))
            }
            2 => forged_handoff_frame(&mut f, &new_session, Some(old_start)),
            _ => forged_handoff_frame(&mut f, "00", None),
        };
        let env = f.env;
        drop(f.server);
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(env.log_path())
            .unwrap();
        log.write_all(&encode(&frame).unwrap()).unwrap();
        drop(log);
        assert_eq!(Server::open(&env.dir()).is_ok(), ok, "{name}");
    }
}

#[test]
fn the_approval_must_be_for_the_members_own_sessions() {
    let mut f = flock();
    // the shepherd's role moving to the helper's pending session, claiming
    // the shepherd as the member
    let (shep, new) = (clone(&f.shep), clone(&f.new));
    let ap = approval(&f.env, &f.server, "shep", &shep, &new);
    let why = session_err(
        f.server
            .handoff(ap.clone(), sign_approval(&f.shep.key, &ap)),
    );
    assert!(why.contains("belong"), "{why}");
    // a session cannot replace itself
    let old = clone(&f.old);
    let ap = approval(&f.env, &f.server, "h1", &old, &old);
    let why = session_err(
        f.server
            .handoff(ap.clone(), sign_approval(&f.shep.key, &ap)),
    );
    assert!(why.contains("pending"), "{why}");
}
