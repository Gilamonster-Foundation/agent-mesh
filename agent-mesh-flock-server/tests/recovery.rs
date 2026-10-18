//! Crash at every write point, torn tails, corruption, forged chains.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::Kind;
use agent_mesh_flock_server::{
    cert_cid, encode, seal, CrashPlan, Frame, Sealed, Server, ServerError,
};
use content_addressable::{ContentAddressable, ContentId};
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
    Server::open(&env.dir())
}

#[test]
fn a_crash_at_every_write_point_leaves_the_frame_whole_or_gone() {
    // header, mid-payload, last byte, whole-but-unsynced, synced-but-unreplied
    for plan in 0..10 {
        let mut env = Env::new();
        let mut s = env.open();
        let (n0, s0) = env.server_event("first");
        s.admit(n0, s0).unwrap();
        let good = env.log_len();
        let (n1, s1) = env.server_event("second");
        let cid = id(&n1);
        // the exact bytes the server will write: signing is deterministic
        let full = encode(&Frame {
            sealed: vec![seal(
                &env.server_key(),
                s.head_record(),
                2,
                0,
                n1.clone(),
                s1.clone(),
            )
            .unwrap()],
        })
        .unwrap()
        .len();
        let plan = match plan {
            0..=5 => CrashPlan::AfterBytes([0, 1, 4, 7, 8, 9][plan]),
            6 => CrashPlan::AfterBytes(full / 2),
            7 => CrashPlan::AfterBytes(full - 1),
            8 => CrashPlan::BeforeSync,
            _ => CrashPlan::AfterSync,
        };
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
    let mut s = env.open();
    let shep = env.session(&mut s, "shep");
    let base = s.admitted();
    let (a, sa) = env.brief(&shep, None, "lane-a");
    let a_id = id(&a);
    s.admit(a, sa).unwrap();
    let (n, sig) = env.server_event("inv");
    s.admit(n, sig).unwrap();
    drop(s);
    let s = Server::open(&env.dir()).unwrap();
    assert_eq!(s.admitted(), base + 2);
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
        match kind {
            Kind::Epoch => agent_mesh_flock::Body::Epoch { epoch },
            _ => agent_mesh_flock::Body::Invite {
                member: "h1".into(),
                verifier: content_addressable::RawContentId::from_content(
                    format!("{index}").as_bytes(),
                ),
            },
        },
    );
    seal(&key, prev, index, epoch, node, sig).unwrap()
}

#[test]
fn a_member_built_chain_extending_a_real_head_is_refused() {
    let mut env = Env::new();
    let mut s = env.open();
    // a session certified by the server signs the record itself
    let member = env.session(&mut s, "shep");
    let (head, next) = (s.head_record(), s.admitted() + 1);
    drop(s);
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
    let sealed = seal(&member, head, next, 0, node, sig).unwrap();
    append_raw(&env, &[sealed]);
    let e = Server::open(&env.dir());
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
        append_raw(&env, std::slice::from_ref(&first));
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

#[test]
fn a_record_must_name_the_event_and_certificate_it_carries() {
    // event swapped under an intact record
    let mut env = Env::new();
    let root = env.flock;
    let mut s1 = forged(&mut env, root, 1, 0, Kind::Invite);
    let other = forged(&mut env, root, 1, 0, Kind::Invite);
    s1.event = other.event;
    s1.event_sig = other.event_sig;
    append_raw(&env, &[s1]);
    assert!(corrupt_at(reopen(&env)), "event swapped");

    // a record that names another certificate than the one that signed
    let mut env = Env::new();
    let root = env.flock;
    let mut s1 = forged(&mut env, root, 1, 0, Kind::Invite);
    s1.record.payload.cert = ContentId::from_canonical_bytes(b"another cert");
    s1.record_sig =
        agent_mesh_protocol::Assertion::sign(&env.server_key(), &s1.record.content_id().unwrap());
    append_raw(&env, &[s1]);
    assert!(corrupt_at(reopen(&env)), "certificate swapped");
}

#[test]
fn a_corrupt_prefix_plus_a_torn_tail_is_refused_and_left_untouched() {
    let mut env = Env::new();
    let mut s = env.open();
    let shep = env.session(&mut s, "shep");
    let (a, sa) = env.brief(&shep, None, "victim-text");
    let a_id = id(&a);
    s.admit(a, sa).unwrap();
    let (b, sb) = env.brief(&shep, Some(a_id), "other");
    s.admit(b, sb).unwrap();
    drop(s);
    let mut bytes = std::fs::read(env.log_path()).unwrap();
    // flip one bit inside the first event's text: still canonical, but the
    // event no longer matches its record
    let from = b"victim-text";
    let at = bytes.windows(from.len()).position(|w| w == from).unwrap();
    bytes[at] ^= 1;
    bytes.extend_from_slice(&[0, 0, 1]); // a torn append
    std::fs::write(env.log_path(), &bytes).unwrap();
    assert!(corrupt_at(reopen(&env)));
    assert_eq!(
        std::fs::read(env.log_path()).unwrap(),
        bytes,
        "nothing repaired before the prefix verifies"
    );
}

#[test]
fn a_torn_refusal_tail_is_cut_only_after_verification() {
    let mut env = Env::new();
    let mut s = env.open();
    let shep = env.session(&mut s, "shep");
    let (a, sa) = env.brief(&shep, None, "l");
    let a_id = id(&a);
    s.admit(a, sa).unwrap();
    let (b, sb) = env.brief(&shep, Some(a_id), "m");
    s.admit(b, sb).unwrap();
    let (f, sf) = env.brief(&shep, Some(a_id), "n");
    assert!(s.admit(f, sf).is_err());
    drop(s);
    let path = env.dir().join(agent_mesh_flock_server::REFUSALS_FILE);
    let good = std::fs::read(&path).unwrap();
    // torn tail on the refusals: cut after verification
    let mut torn = good.clone();
    torn.extend_from_slice(&[0, 0, 1]);
    std::fs::write(&path, &torn).unwrap();
    let s = Server::open(&env.dir()).unwrap();
    assert_eq!(s.refusals().len(), 1);
    drop(s);
    assert_eq!(std::fs::read(&path).unwrap(), good);
    // a corrupt main log leaves a torn refusals tail alone too
    std::fs::write(&path, &torn).unwrap();
    let mut log = std::fs::read(env.log_path()).unwrap();
    let n = log.len();
    log[n - 20] ^= 1;
    std::fs::write(env.log_path(), &log).unwrap();
    assert!(Server::open(&env.dir()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), torn);
}
