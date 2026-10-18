//! `Snapshot`: a verified prefix of the log, read beside a live server.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock_server::{CrashPlan, Snapshot};
use std::sync::atomic::{AtomicBool, Ordering};
use support::Env;

#[test]
fn a_snapshot_reads_beside_the_servers_lock_and_matches_it() {
    let mut env = Env::new();
    let mut s = env.open(); // holds the exclusive lock
    let (n, sig) = env.server_event("one");
    s.admit(n, sig).unwrap();
    let snap = Snapshot::read(&env.dir()).expect("no lock needed");
    assert_eq!(snap.admitted(), s.admitted());
    assert_eq!(snap.epoch(), s.epoch());
    assert!(!snap.torn());
    assert_eq!(snap.board().flock(), s.flock());
}

#[test]
fn a_torn_tail_is_left_unread_and_unrepaired() {
    let mut env = Env::new();
    let mut s = env.open();
    let (n0, s0) = env.server_event("one");
    s.admit(n0, s0).unwrap();
    let (n1, s1) = env.server_event("two");
    s.plan_crash(Some(CrashPlan::AfterBytes(20)));
    assert!(s.admit(n1, s1).is_err());
    drop(s);
    let before = std::fs::read(env.log_path()).unwrap();

    let snap = Snapshot::read(&env.dir()).unwrap();

    assert_eq!(snap.admitted(), 1);
    assert!(snap.torn());
    assert_eq!(
        std::fs::read(env.log_path()).unwrap(),
        before,
        "repairs nothing"
    );
}

#[test]
fn reading_while_the_log_grows_always_gives_a_verified_prefix() {
    let mut env = Env::new();
    let mut s = env.open();
    let events: Vec<_> = (0..40)
        .map(|i| env.server_event(&format!("n{i}")))
        .collect();
    let dir = env.dir();
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for (n, sig) in events {
                s.admit(n, sig).unwrap();
            }
            done.store(true, Ordering::SeqCst);
        });
        let mut last = 0;
        loop {
            let finished = done.load(Ordering::SeqCst);
            let snap = Snapshot::read(&dir).expect("every read replays clean");
            let n = snap.admitted();
            assert!(n >= last, "a later read never sees less");
            assert_eq!(snap.board().entries().count() as u64, n, "board == prefix");
            last = n;
            if finished {
                assert_eq!(n, 40, "after the writer is done, the whole log");
                break;
            }
        }
    });
}
