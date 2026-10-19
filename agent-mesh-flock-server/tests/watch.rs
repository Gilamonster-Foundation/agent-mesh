//! The published log, the cursor, the follower and who may open a stream.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::EndReason;
use agent_mesh_flock_server::wire::StreamChallenge;
use agent_mesh_flock_server::{CrashPlan, FollowError, Follower, Head, Resume, Server};
use agent_mesh_protocol::{AgentKey, Assertion};
use content_addressable::ContentAddressable;
use support::{enroll, operator, Env};

/// Admit one more brief from `key`; returns the new admission count.
fn brief(env: &mut Env, server: &mut Server, key: &AgentKey, lane: &str) -> u64 {
    let prev = server.board().head_of(&key.fingerprint().hex());
    let (node, sig) = env.brief(key, prev, lane);
    server.admit(node, sig).unwrap();
    server.admitted()
}

/// Every published frame, oldest first.
fn frames(server: &Server) -> Vec<std::sync::Arc<Vec<agent_mesh_flock_server::Sealed>>> {
    let j = server.journal();
    let mut c = j.cursor_from(None).unwrap();
    let mut out = vec![];
    while c.delivered() < j.len() {
        out.push(c.next_frame().unwrap().0);
    }
    out
}

#[test]
fn an_event_appended_mid_replay_is_delivered_exactly_once() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    for i in 0..3 {
        brief(&mut env, &mut server, &shep.key, &format!("a{i}"));
    }
    let j = server.journal();
    let mut cursor = j.cursor_from(None).unwrap();
    let mut seen = vec![];
    // two frames of the replay, then an append lands mid-replay
    for _ in 0..2 {
        seen.extend(
            cursor
                .next_frame()
                .unwrap()
                .0
                .iter()
                .map(|s| s.record.payload.index),
        );
    }
    brief(&mut env, &mut server, &shep.key, "mid");
    while cursor.delivered() < server.admitted() {
        seen.extend(
            cursor
                .next_frame()
                .unwrap()
                .0
                .iter()
                .map(|s| s.record.payload.index),
        );
    }
    let want: Vec<u64> = (1..=server.admitted()).collect();
    assert_eq!(seen, want, "every index once, in order");
}

#[test]
fn a_cursor_resumes_after_a_signed_head_and_refuses_what_it_cannot_extend() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    for i in 0..3 {
        brief(&mut env, &mut server, &shep.key, &format!("a{i}"));
    }
    let all = frames(&server);
    let head = Head::of(all[2].last().unwrap());
    let mut c = server.journal().cursor_from(Some(&head)).unwrap();
    let next = c.next_frame().unwrap().0;
    assert_eq!(next[0].record.payload.index, head.index() + 1);
    // a head from beyond this history: the server is behind
    let mut ahead = head.clone();
    ahead.record.payload.index = 99;
    assert!(matches!(
        server.journal().cursor_from(Some(&ahead)),
        Err(Resume::Behind { .. })
    ));
    // a head at this index with another record: diverged
    let mut other = head.clone();
    other.record.payload.epoch += 7;
    assert_eq!(
        server.journal().cursor_from(Some(&other)).err(),
        Some(Resume::Diverged)
    );
    // a head in the middle of a frame is not a resume point
    let two_event = all.iter().find(|f| f.len() > 1);
    if let Some(f) = two_event {
        let mid = Head::of(&f[0]);
        assert_eq!(
            server.journal().cursor_from(Some(&mid)).err(),
            Some(Resume::NotABoundary)
        );
    }
}

#[test]
fn an_append_that_dies_before_its_fsync_is_never_published() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let before = server.journal().len();
    server.plan_crash(Some(CrashPlan::BeforeSync));
    let prev = server.board().head_of(&shep.key.fingerprint().hex());
    let (node, sig) = env.brief(&shep.key, prev, "lost");
    assert!(server.admit(node, sig).is_err());
    assert_eq!(server.journal().len(), before);
}

#[test]
fn a_follower_rebuilds_the_flock_and_refuses_a_frame_that_does_not_extend() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    for i in 0..3 {
        brief(&mut env, &mut server, &shep.key, &format!("a{i}"));
    }
    let all = frames(&server);
    let genesis = agent_mesh_flock_server::load_genesis(env.tmp.path())
        .unwrap()
        .node;
    let mut f = Follower::new(&genesis).unwrap();
    for fr in &all {
        f.apply(fr).unwrap();
    }
    assert_eq!(f.admitted(), server.admitted());
    assert_eq!(f.board().flock(), server.flock());
    assert_eq!(
        f.head(),
        Some(&Head::of(all.last().unwrap().last().unwrap()))
    );
    // a gap (skip a frame) does not extend the head
    let mut g = Follower::new(&genesis).unwrap();
    g.apply(&all[0]).unwrap();
    assert!(matches!(
        g.apply(&all[2]),
        Err(FollowError::DoesNotExtend(_))
    ));
    // a repeated frame does not extend it either
    assert!(matches!(
        f.apply(&all[0]),
        Err(FollowError::DoesNotExtend(_))
    ));
}

fn proof(
    key: &AgentKey,
    server: &Server,
    nonce: u8,
) -> (
    Assertion,
    agent_mesh_flock_server::wire::StreamChallenge,
    content_addressable::ContentId,
) {
    let ch = StreamChallenge {
        flock: server.flock(),
        nonce: [nonce; 32],
    };
    let id = ch.id().unwrap();
    (Assertion::sign(key, &id), ch, id)
}

#[test]
fn only_an_active_session_of_a_current_member_opens_a_stream() {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let pending = enroll(&mut server, "shep");
    assert!(pending.pending);
    let (sig, _, id) = proof(&shep.key, &server, 1);
    assert_eq!(server.authorize_stream(&sig, &id).unwrap(), shep.session);
    // a signature over another challenge is no proof for this one
    let (_, _, other_id) = proof(&shep.key, &server, 2);
    assert!(server.authorize_stream(&sig, &other_id).is_err());
    // pending replacement
    let (sig, _, id) = proof(&pending.key, &server, 3);
    assert!(server.authorize_stream(&sig, &id).is_err());
    // certified by the user key, but no session in the log
    let stranger = operator(&env);
    let (sig, _, id) = proof(&stranger, &server, 4);
    assert!(server.authorize_stream(&sig, &id).is_err());
    // a copied certificate: another key presenting the session's cert chain
    let thief = AgentKey::from_seed_and_cert(&[9u8; 32], shep.key.cert().clone());
    assert!(
        thief.is_err(),
        "a cert cannot be paired with a foreign seed"
    );
    // an ended session
    let h1 = enroll(&mut server, "h1");
    server.end_session(&h1.session, EndReason::Closed).unwrap();
    let (sig, _, id) = proof(&h1.key, &server, 5);
    assert!(server.authorize_stream(&sig, &id).is_err());
}

/// Copy the flock's files, so a second server can diverge from the first.
fn copy_flock(env: &Env, to: &std::path::Path) {
    for e in std::fs::read_dir(env.tmp.path()).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

#[test]
fn an_altered_prefix_with_an_unchanged_last_event_does_not_extend_the_head() {
    use agent_mesh_flock::{Body, Kind};
    let mut env = Env::new();
    let mut a = env.open();
    let shep = enroll(&mut a, "shep");
    let h1 = enroll(&mut a, "h1");
    let alt = tempfile::TempDir::new().unwrap();
    copy_flock(&env, alt.path());
    let mut b = Server::open(alt.path()).unwrap();

    // `shep` writes X on A and X' on B; `h1` then writes the very same Y on
    // both (its chain does not pass through X), then each writes one more.
    let write = |env: &mut Env, s: &mut Server, who: &AgentKey, kind, body: Body, at: u64| {
        env.at = at;
        let prev = s.board().head_of(&who.fingerprint().hex());
        let (node, sig) = env.event(who, kind, prev, &[], body);
        let id = node.content_id().unwrap();
        s.admit(node, sig).unwrap();
        id
    };
    let brief = |lane: &str| Body::Brief {
        to: "h1".into(),
        lane: lane.into(),
    };
    let job = Body::Job {
        lane: "j".into(),
        label: "same".into(),
    };
    write(&mut env, &mut a, &shep.key, Kind::Brief, brief("x"), 100);
    write(
        &mut env,
        &mut b,
        &shep.key,
        Kind::Brief,
        brief("x-altered"),
        100,
    );
    let ya = write(&mut env, &mut a, &h1.key, Kind::Job, job.clone(), 101);
    let yb = write(&mut env, &mut b, &h1.key, Kind::Job, job, 101);
    assert_eq!(ya, yb, "fixture: the last event is the same event");
    write(&mut env, &mut a, &shep.key, Kind::Brief, brief("z"), 102);
    write(&mut env, &mut b, &shep.key, Kind::Brief, brief("z"), 102);

    let (fa, fb) = (frames(&a), frames(&b));
    let at_y = fa
        .iter()
        .position(|f| f.last().unwrap().record.payload.index == a.admitted() - 1)
        .unwrap();
    let head_y = Head::of(fa[at_y].last().unwrap());
    let theirs = Head::of(fb[at_y].last().unwrap());
    assert_eq!(
        fa[at_y].last().unwrap().event.content_id().unwrap(),
        fb[at_y].last().unwrap().event.content_id().unwrap()
    );
    assert_ne!(
        head_y.id().unwrap(),
        theirs.id().unwrap(),
        "the prefix changed the record"
    );

    // the server refuses to resume from A's head on B's history ...
    assert_eq!(
        b.journal().cursor_from(Some(&head_y)).err(),
        Some(Resume::Diverged)
    );
    // ... and a follower at A's head refuses B's next frame by itself
    let genesis = agent_mesh_flock_server::load_genesis(env.tmp.path())
        .unwrap()
        .node;
    let mut f = Follower::new(&genesis).unwrap();
    for fr in &fa[..=at_y] {
        f.apply(fr).unwrap();
    }
    assert!(matches!(
        f.apply(&fb[at_y + 1]),
        Err(FollowError::DoesNotExtend(_))
    ));
    f.apply(&fa[at_y + 1]).unwrap();
}

#[test]
fn a_member_the_roster_dropped_may_not_open_a_stream_though_its_session_is_still_active() {
    use agent_mesh_flock::{Body, Kind, Member, Role};
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    let (_, _, id) = proof(&h1.key, &server, 1);
    let keep: Vec<Member> = ["shep", "herdr", "op"]
        .iter()
        .map(|n| Member {
            name: (*n).into(),
            role: match *n {
                "shep" => Role::Shepherd,
                "herdr" => Role::Adapter,
                _ => Role::Operator,
            },
            devices: vec![],
        })
        .collect();
    let prev = server.board().head_of(&shep.key.fingerprint().hex());
    let replaces = server.board().roster_id();
    let (node, sig) = env.event(
        &shep.key,
        Kind::Roster,
        prev,
        &[("replaces", replaces)],
        Body::Roster {
            members: keep,
            roots: vec![],
        },
    );
    server.admit(node, sig).unwrap();
    // removal-driven epoch bumps are a later step: the session is still
    // Active in the table, but the stream must follow the roster
    assert_eq!(
        server.sessions().get(&h1.session).unwrap().status,
        agent_mesh_flock_server::Status::Active
    );
    let (sig, _, id2) = proof(&h1.key, &server, 1);
    let _ = id;
    assert!(server.authorize_stream(&sig, &id2).is_err());
}

#[test]
fn recovery_syncs_a_complete_unsynced_frame_before_it_is_published() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let before = server.admitted();
    server.plan_crash(Some(CrashPlan::BeforeSync));
    let prev = server.board().head_of(&shep.key.fingerprint().hex());
    let (node, sig) = env.brief(&shep.key, prev, "unsynced");
    assert!(server.admit(node, sig).is_err());
    drop(server);
    // the whole frame is on disk, never fsynced; a restart finds it
    let server = env.open();
    assert_eq!(server.admitted(), before + 1);
    assert!(
        server.log_syncs() >= 1,
        "the recovered prefix was published without an fsync"
    );
    assert_eq!(server.journal().len(), before + 1);
}
