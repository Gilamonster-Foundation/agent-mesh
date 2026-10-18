//! Admission through the server: duplicates, signers, forks, races.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::{Body, Kind, Member, Refusal, Role};
use agent_mesh_flock_server::{ServerError, REFUSALS_FILE};
use std::sync::{Arc, Mutex};
use support::{id, Env};

#[test]
fn the_server_admits_its_own_event_and_indexes_from_one() {
    let mut env = Env::new();
    let mut server = env.open();
    let (n, s) = env.server_event("a");
    let r = server.admit(n, s).unwrap();
    assert_eq!((r.index, r.duplicate), (1, false));
    let (n, s) = env.server_event("b");
    assert_eq!(server.admit(n, s).unwrap().index, 2);
    assert_eq!(server.admitted(), 2);
}

#[test]
fn an_unknown_signer_is_refused_and_writes_nothing() {
    let mut env = Env::new();
    let mut server = env.open();
    let stranger = agent_mesh_protocol::AgentKey::issue(
        &agent_mesh_protocol::UserKey::generate(),
        support::meta("x"),
    );
    let (n, s) = env.brief(&stranger, None, "lane-a");
    let before = env.log_len();
    assert!(matches!(server.admit(n, s), Err(ServerError::Signer(_))));
    assert_eq!(env.log_len(), before);
    assert_eq!(server.admitted(), 0);
}

#[test]
fn a_refused_event_is_refused_by_the_table_and_writes_nothing() {
    let mut env = Env::new();
    let mut server = env.open();
    let h1 = env.session(&mut server, "h1");
    let (n, s) = env.brief(&h1, None, "lane-a"); // a helper may not brief
    let before = env.log_len();
    assert!(matches!(
        server.admit(n, s),
        Err(ServerError::Refused(Refusal::NotAllowed))
    ));
    assert_eq!(env.log_len(), before);
}

#[test]
fn a_fork_attempt_is_refused_and_logged() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = env.session(&mut server, "shep");
    let (a, sa) = env.brief(&shep, None, "lane-a");
    let a_id = id(&a);
    server.admit(a, sa).unwrap();
    let (b, sb) = env.brief(&shep, Some(a_id), "lane-b");
    server.admit(b, sb).unwrap();
    let (fork, sf) = env.brief(&shep, Some(a_id), "lane-c");
    let fork_id = id(&fork);
    let (len, count) = (env.log_len(), server.admitted());
    assert!(matches!(
        server.admit(fork, sf),
        Err(ServerError::Refused(Refusal::WriterFork))
    ));
    assert_eq!((env.log_len(), server.admitted()), (len, count));
    assert!(server.board().get(&fork_id).is_none());
    let r = server.refusals();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].record.payload.event, fork_id);
    assert_eq!(
        r[0].record.payload.reason,
        agent_mesh_flock_server::Reason::WriterFork
    );
}

#[test]
fn retrying_a_committed_node_returns_its_index_after_its_session_ended() {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = env.session(&mut server, "shep");
    let (n, s) = env.brief(&shep, None, "lane-a");
    let first = server.admit(n.clone(), s.clone()).unwrap();
    server
        .end_session(
            &shep.fingerprint().hex(),
            agent_mesh_flock::EndReason::Closed,
        )
        .unwrap();
    let len = env.log_len();
    let again = server.admit(n, s).unwrap();
    assert_eq!((again.index, again.duplicate), (first.index, true));
    assert_eq!(env.log_len(), len, "a retry writes nothing");
}

#[test]
fn two_racing_roster_replacements_exactly_one_wins() {
    let mut env = Env::new();
    let key = env.server_key();
    let server = Arc::new(Mutex::new(env.open()));
    let flock = env.flock;
    let roster = |extra: &str| Body::Roster {
        members: vec![Member {
            name: extra.into(),
            role: Role::Helper,
            devices: vec![],
        }],
    };
    let a = env.event(
        &key,
        Kind::Roster,
        None,
        &[("replaces", flock)],
        roster("a"),
    );
    let b = env.event(
        &key,
        Kind::Roster,
        None,
        &[("replaces", flock)],
        roster("b"),
    );
    let handles: Vec<_> = [a, b]
        .into_iter()
        .map(|(n, s)| {
            let server = Arc::clone(&server);
            std::thread::spawn(move || server.lock().unwrap().admit(n, s))
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results
        .iter()
        .any(|r| matches!(r, Err(ServerError::Refused(Refusal::StaleRoster)))));
    // the winner replaced the whole roster, so it dropped names: roster + epoch
    assert_eq!(server.lock().unwrap().admitted(), 2);
}

#[test]
fn a_second_server_on_the_same_log_refuses_to_start() {
    let env = Env::new();
    let _first = env.open();
    let second = agent_mesh_flock_server::Server::open(&env.dir());
    assert!(matches!(second, Err(ServerError::Locked)));
}

/// A server with an admitted `a`, `b` (child of `a`) and three forks of `a`
/// refused. Returns the env (log paths) and the dropped server's refusal count.
fn three_refusals() -> Env {
    let mut env = Env::new();
    let mut server = env.open();
    let shep = env.session(&mut server, "shep");
    let (a, sa) = env.brief(&shep, None, "lane-a");
    let a_id = id(&a);
    server.admit(a, sa).unwrap();
    let (b, sb) = env.brief(&shep, Some(a_id), "lane-b");
    server.admit(b, sb).unwrap();
    for lane in ["c1", "c2", "c3"] {
        let (f, sf) = env.brief(&shep, Some(a_id), lane);
        assert!(server.admit(f, sf).is_err());
    }
    assert_eq!(server.refusals().len(), 3);
    drop(server);
    env
}

fn reopen(env: &Env) -> Result<agent_mesh_flock_server::Server, ServerError> {
    agent_mesh_flock_server::Server::open(&env.dir())
}

/// Split a log file into its whole frames.
fn frames(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        out.push(bytes[at..at + 8 + len].to_vec());
        at += 8 + len;
    }
    out
}

#[test]
fn a_refusal_is_a_typed_signed_record_that_consumes_no_index() {
    let env = three_refusals();
    let server = reopen(&env).unwrap();
    let r = server.refusals();
    assert_eq!(r.len(), 3);
    assert!(r
        .iter()
        .all(|e| e.record.payload.reason == agent_mesh_flock_server::Reason::WriterFork));
    // invite + session-start for the shepherd, then two briefs
    assert!(r.iter().all(|e| e.record.payload.admitted == 4));
    assert_eq!(server.admitted(), 4, "refusals take no admission index");
}

#[test]
fn a_refusal_chain_continues_across_a_restart() {
    let mut env = three_refusals();
    let mut server = reopen(&env).unwrap();
    let key = env.server_key();
    // a server-class event the table refuses (a brief is not a server kind)
    let (n, s) = env.brief(&key, None, "x");
    assert!(server.admit(n, s).is_err());
    assert_eq!(server.refusals().len(), 4);
    drop(server);
    assert_eq!(reopen(&env).unwrap().refusals().len(), 4);
}

#[test]
fn editing_a_refusal_reason_fails_open() {
    let env = three_refusals();
    let path = env.dir().join(REFUSALS_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    let from = b"writer-fork";
    let at = bytes
        .windows(from.len())
        .position(|w| w == from)
        .expect("typed reason");
    bytes[at..at + from.len()].copy_from_slice(b"bad-parents");
    std::fs::write(&path, bytes).unwrap();
    assert!(reopen(&env).is_err());
}

#[test]
fn removing_or_reordering_an_interior_refusal_fails_open() {
    let env = three_refusals();
    let path = env.dir().join(REFUSALS_FILE);
    let f = frames(&std::fs::read(&path).unwrap());
    assert_eq!(f.len(), 3);
    for (name, order) in [("removed", vec![0, 2]), ("reordered", vec![1, 0, 2])] {
        let bytes: Vec<u8> = order.iter().flat_map(|&i| f[i].clone()).collect();
        std::fs::write(&path, bytes).unwrap();
        assert!(reopen(&env).is_err(), "{name}");
    }
    // a first refusal that is not rooted at genesis
    let bytes: Vec<u8> = f[1].clone();
    std::fs::write(&path, bytes).unwrap();
    assert!(reopen(&env).is_err(), "unrooted");
}
