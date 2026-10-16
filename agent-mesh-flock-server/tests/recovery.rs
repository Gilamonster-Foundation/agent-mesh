//! Crash at every write point, torn tails, corruption, forged chains.
mod support;

use agent_mesh_flock::Kind;
use agent_mesh_flock_server::{
    cert_cid, encode, seal, CrashPlan, Frame, Sealed, Server, ServerError, ServerOnly,
};
use content_addressable::ContentId;
use std::io::Write;
use support::{id, Env};

fn corrupt_at(e: Result<Server, ServerError>) -> bool {
    matches!(e, Err(ServerError::Corrupt { .. } | ServerError::Signer(_)))
}

fn append_raw(env: &Env, frames: &[Sealed]) {
    for s in frames {
        let bytes = encode(&Frame {
            sealed: vec![s.clone()],
        })
        .unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(env.log_path())
            .unwrap();
        f.write_all(&bytes).unwrap();
    }
}

fn reopen(env: &Env) -> Result<Server, ServerError> {
    Server::open(&env.dir(), Box::new(ServerOnly))
}

#[test]
fn a_crash_at_every_write_point_leaves_the_frame_whole_or_gone() {
    let frame_len = {
        let mut env = Env::new();
        let mut s = env.open();
        let (n, sig) = env.server_event("probe");
        s.admit(n, sig).unwrap();
        env.log_len() as usize
    };
    let mut plans: Vec<CrashPlan> = [0, 1, 4, 7, 8, 9, frame_len / 2, frame_len - 1]
        .into_iter()
        .map(CrashPlan::AfterBytes)
        .collect();
    plans.extend([CrashPlan::BeforeSync, CrashPlan::AfterSync]);
    for plan in plans {
        let mut env = Env::new();
        let mut s = env.open();
        let (n0, s0) = env.server_event("first");
        s.admit(n0, s0).unwrap();
        let good = env.log_len();
        let (n1, s1) = env.server_event("second");
        let cid = id(&n1);
        s.plan_crash(Some(plan));
        assert!(s.admit(n1.clone(), s1.clone()).is_err(), "{plan:?}");
        assert!(
            matches!(s.admit(n1.clone(), s1.clone()), Err(ServerError::Poisoned)),
            "a crashed server stops"
        );
        drop(s);

        let s = reopen(&env).unwrap();
        let whole = matches!(plan, CrashPlan::BeforeSync | CrashPlan::AfterSync);
        // the event is in the board exactly when its record is: one frame
        assert_eq!(s.board().get(&cid).is_some(), whole, "{plan:?}");
        assert_eq!(s.admitted(), if whole { 2 } else { 1 }, "{plan:?}");
        if !whole {
            assert_eq!(env.log_len(), good, "{plan:?}: torn tail cut");
        }
        drop(s);
        // the client's retry lands exactly once either way
        let mut s = reopen(&env).unwrap();
        let r = s.admit(n1, s1).unwrap();
        assert_eq!((r.index, r.duplicate), (2, whole), "{plan:?}");
        assert_eq!(s.admitted(), 2);
    }
}

#[test]
fn a_short_write_and_a_truncated_final_frame_are_cut_off() {
    for keep in [3usize, 8, 20] {
        let mut env = Env::new();
        let mut s = env.open();
        let (n0, s0) = env.server_event("one");
        s.admit(n0, s0).unwrap();
        let good = env.log_len();
        let (n1, s1) = env.server_event("two");
        s.admit(n1, s1).unwrap();
        drop(s);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(env.log_path())
            .unwrap();
        f.set_len(good + keep as u64).unwrap();
        let s = reopen(&env).unwrap();
        assert_eq!(s.admitted(), 1, "keep {keep}");
        assert_eq!(env.log_len(), good);
    }
}

#[test]
fn damage_in_committed_history_fails_closed() {
    let mut env = Env::new();
    let mut s = env.open();
    for note in ["one", "two", "three"] {
        let (n, sig) = env.server_event(note);
        s.admit(n, sig).unwrap();
    }
    drop(s);
    let clean = std::fs::read(env.log_path()).unwrap();
    // a flipped byte in the first frame's payload, its header, and the last
    // frame's payload (complete, so not a torn tail)
    for at in [20, 5, clean.len() - 10] {
        let mut bytes = clean.clone();
        bytes[at] ^= 1;
        std::fs::write(env.log_path(), &bytes).unwrap();
        assert!(corrupt_at(reopen(&env)), "flip at {at}");
        assert_eq!(
            std::fs::read(env.log_path()).unwrap(),
            bytes,
            "not repaired"
        );
    }
}

#[test]
fn state_is_rebuilt_from_the_retained_frames() {
    let mut env = Env::new();
    let shep = env.session("shep", false);
    let mut s = env.open();
    let (a, sa) = env.brief(&shep, None, "lane-a");
    let a_id = id(&a);
    s.admit(a, sa).unwrap();
    let (n, sig) = env.server_event("inv");
    s.admit(n, sig).unwrap();
    drop(s);
    let s = Server::open(&env.dir(), Box::new(env.sessions.clone())).unwrap();
    assert_eq!(s.admitted(), 2);
    assert_eq!(s.epoch(), 0);
    assert_eq!(s.board().head_of(&shep.fingerprint().hex()), Some(a_id));
    assert!(s.board().lanes().iter().any(|l| l.lane == "lane-a"));
}

/// Build the server-signed frame for `event` at the given position.
fn forged(env: &mut Env, prev: ContentId, index: u64, epoch: u64, kind: Kind) -> Sealed {
    let key = env.server_key();
    let (node, sig) = env.event(
        &key,
        kind,
        None,
        &[],
        agent_mesh_flock::Body::Server {
            note: format!("{index}"),
        },
    );
    seal(&key, prev, index, epoch, node, sig).unwrap()
}

#[test]
fn a_member_built_chain_extending_a_real_head_is_refused() {
    let mut env = Env::new();
    let mut s = env.open();
    let (n, sig) = env.server_event("real");
    s.admit(n, sig).unwrap();
    drop(s);
    let head = {
        let s = reopen(&env).unwrap();
        s.head_record()
    };
    // a session certified by the server signs the record itself
    let member = env.session("shep", false);
    let (node, sig) = env.event(
        &member,
        Kind::Brief,
        None,
        &[],
        agent_mesh_flock::Body::Brief {
            to: "h1".into(),
            lane: "x".into(),
        },
    );
    let sealed = seal(&member, head, 2, 0, node, sig).unwrap();
    append_raw(&env, &[sealed]);
    let e = Server::open(&env.dir(), Box::new(env.sessions.clone()));
    assert!(corrupt_at(e), "records lack the server's signature");
}

#[test]
fn server_signed_fixtures_with_a_broken_chain_are_refused() {
    for case in ["skipped", "repeated", "unbound-root"] {
        let mut env = Env::new();
        let root = env.flock;
        let first = match case {
            "skipped" => forged(&mut env, root, 2, 0, Kind::Invite),
            "unbound-root" => forged(
                &mut env,
                ContentId::from_canonical_bytes(b"x"),
                1,
                0,
                Kind::Invite,
            ),
            _ => forged(&mut env, root, 1, 0, Kind::Invite),
        };
        append_raw(&env, &[first.clone()]);
        if case == "repeated" {
            let prev = {
                use content_addressable::ContentAddressable;
                first.record.content_id().unwrap()
            };
            let again = forged(&mut env, prev, 1, 0, Kind::Invite);
            append_raw(&env, &[again]);
        }
        assert!(corrupt_at(reopen(&env)), "{case}");
    }
}

#[test]
fn epoch_must_follow_the_logged_transitions() {
    use content_addressable::ContentAddressable;
    // rises without an epoch event
    let mut env = Env::new();
    let root = env.flock;
    let s1 = forged(&mut env, root, 1, 1, Kind::Invite);
    append_raw(&env, &[s1]);
    assert!(corrupt_at(reopen(&env)), "rise without epoch event");

    // jumps by two on an epoch event
    let mut env = Env::new();
    let root = env.flock;
    let s1 = forged(&mut env, root, 1, 2, Kind::Epoch);
    append_raw(&env, &[s1]);
    assert!(corrupt_at(reopen(&env)), "jump");

    // decreases after a legal bump
    let mut env = Env::new();
    let root = env.flock;
    let s1 = forged(&mut env, root, 1, 1, Kind::Epoch);
    let prev = s1.record.content_id().unwrap();
    let s2 = forged(&mut env, prev, 2, 0, Kind::Invite);
    append_raw(&env, &[s1, s2]);
    assert!(corrupt_at(reopen(&env)), "decrease");

    // a legal bump is accepted and the epoch is rebuilt
    let mut env = Env::new();
    let root = env.flock;
    let s1 = forged(&mut env, root, 1, 1, Kind::Epoch);
    append_raw(&env, &[s1]);
    assert_eq!(reopen(&env).unwrap().epoch(), 1);
    let _ = cert_cid; // exported for step 4 verifiers
}
