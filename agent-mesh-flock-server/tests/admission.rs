//! Admission through the server: duplicates, signers, forks, races.
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
    let h1 = env.session("h1", false);
    let mut server = env.open();
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
    let shep = env.session("shep", false);
    let mut server = env.open();
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
    let journal = std::fs::read_to_string(env.dir().join(REFUSALS_FILE)).unwrap();
    assert!(journal.contains(&fork_id.to_string()) && journal.contains("WriterFork"));
}

#[test]
fn retrying_a_committed_node_returns_its_index_after_its_session_ended() {
    let mut env = Env::new();
    let shep = env.session("shep", false);
    let mut server = env.open();
    let (n, s) = env.brief(&shep, None, "lane-a");
    let first = server.admit(n.clone(), s.clone()).unwrap();
    env.sessions.end(&shep);
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
    assert_eq!(server.lock().unwrap().admitted(), 1);
}

#[test]
fn a_second_server_on_the_same_log_refuses_to_start() {
    let env = Env::new();
    let _first = env.open();
    let second = agent_mesh_flock_server::Server::open(
        &env.dir(),
        Box::new(agent_mesh_flock_server::ServerOnly),
    );
    assert!(matches!(second, Err(ServerError::Locked)));
}
