//! The fold: determinism and the attempt states.

mod fixture;

use agent_mesh_flock::{AttemptState, Board, Body, Kind, Outcome};
use fixture::Fx;

#[test]
fn two_readers_folding_the_same_log_get_the_same_board() {
    let mut fx = Fx::new();
    let a = fx.brief("h1", "a");
    fx.emit("h1", Kind::Ack, Body::Ack, &[("of", a)]);
    let q = fx.emit(
        "h1",
        Kind::Ask,
        Body::Ask {
            lane: Some("a".into()),
            text: "?".into(),
        },
        &[("about", a)],
    );
    fx.emit(
        "op",
        Kind::Answer,
        Body::Answer { text: "y".into() },
        &[("ask", q)],
    );
    fx.emit(
        "h1",
        Kind::Result,
        Body::Result {
            outcome: Outcome::Completed,
        },
        &[("brief", a)],
    );
    fx.brief("h2", "b");

    let one = Board::fold(&fx.genesis, &fx.log).unwrap();
    let two = Board::fold(&fx.genesis, &fx.log).unwrap();
    assert_eq!(one.flock(), two.flock());
    assert_eq!(one.lanes(), two.lanes());
    assert_eq!(
        one.entries().collect::<Vec<_>>(),
        two.entries().collect::<Vec<_>>()
    );
    assert_eq!(one.lanes(), fx.board.lanes(), "the live board is the fold");
}

#[test]
fn attempt_state_is_the_first_row_that_applies() {
    let mut fx = Fx::new();
    let a = fx.brief("h1", "a");
    assert_eq!(fx.board.attempt(&a).unwrap().state, AttemptState::Submitted);
    fx.emit("h1", Kind::Ack, Body::Ack, &[("of", a)]);
    assert_eq!(fx.board.attempt(&a).unwrap().state, AttemptState::Working);
    let q = fx.emit(
        "h1",
        Kind::Ask,
        Body::Ask {
            lane: None,
            text: "?".into(),
        },
        &[("about", a)],
    );
    assert_eq!(
        fx.board.attempt(&a).unwrap().state,
        AttemptState::InputRequired
    );
    // a relay does not close the ask
    fx.emit(
        "h2",
        Kind::RelayedAnswer,
        Body::RelayedAnswer { text: "y".into() },
        &[("ask", q)],
    );
    assert_eq!(
        fx.board.attempt(&a).unwrap().state,
        AttemptState::InputRequired
    );
    fx.emit(
        "op",
        Kind::Answer,
        Body::Answer { text: "y".into() },
        &[("ask", q)],
    );
    assert_eq!(fx.board.attempt(&a).unwrap().state, AttemptState::Working);
    fx.emit(
        "h1",
        Kind::Result,
        Body::Result {
            outcome: Outcome::Failed,
        },
        &[("brief", a)],
    );
    assert_eq!(fx.board.attempt(&a).unwrap().state, AttemptState::Failed);
}

#[test]
fn a_result_with_an_open_job_shows_completed_job_open() {
    let mut fx = Fx::new();
    let a = fx.brief("h1", "a");
    let job = fx.emit(
        "h1",
        Kind::Job,
        Body::Job {
            lane: "a".into(),
            label: "push".into(),
        },
        &[],
    );
    fx.emit(
        "h1",
        Kind::Result,
        Body::Result {
            outcome: Outcome::Completed,
        },
        &[("brief", a)],
    );
    assert_eq!(fx.board.attempt(&a).unwrap().label(), "completed, job open");
    fx.emit(
        "h1",
        Kind::JobEnd,
        Body::JobEnd {
            code: Some(0),
            signal: None,
        },
        &[("job", job)],
    );
    assert_eq!(fx.board.attempt(&a).unwrap().label(), "completed");
}

#[test]
fn a_lane_shows_its_latest_attempt_and_keeps_the_older() {
    let mut fx = Fx::new();
    let first = fx.brief("h1", "a");
    fx.emit(
        "h1",
        Kind::Result,
        Body::Result {
            outcome: Outcome::Failed,
        },
        &[("brief", first)],
    );
    let second = fx.brief("h2", "a");
    let lanes = fx.board.lanes();
    assert_eq!(lanes.len(), 1);
    assert_eq!(lanes[0].latest.brief, second);
    assert_eq!(lanes[0].older.len(), 1);
    assert_eq!(lanes[0].older[0].brief, first);
    assert_eq!(lanes[0].older[0].state, AttemptState::Failed);
}

#[test]
fn a_second_result_stays_visible_as_a_conflict() {
    let mut fx = Fx::new();
    let a = fx.brief("h1", "a");
    fx.emit(
        "h1",
        Kind::Result,
        Body::Result {
            outcome: Outcome::Completed,
        },
        &[("brief", a)],
    );
    let dup = fx.emit(
        "h1",
        Kind::Result,
        Body::Result {
            outcome: Outcome::Failed,
        },
        &[("brief", a)],
    );
    let view = fx.board.attempt(&a).unwrap();
    assert_eq!(view.state, AttemptState::Completed);
    assert_eq!(view.conflicts, vec![dup]);
}

#[test]
fn a_log_with_a_refused_event_does_not_fold() {
    let mut fx = Fx::new();
    fx.brief("h1", "a");
    let mut bad = fx.log[0].clone();
    bad.signer = fx.signer("h1", false); // a helper signing a brief
    let err = Board::fold(&fx.genesis, &[bad]).unwrap_err();
    assert_eq!(err.position, 0);
}

/// The genesis id depends on the server certificate, whose key is generated
/// per run, so it cannot be pinned; its derivation can be checked.
#[test]
fn genesis_id_binds_every_payload_field() {
    use content_addressable::ContentAddressable;
    let fx = Fx::new();
    let id = fx.genesis.content_id().unwrap();
    assert_eq!(id, fx.flock, "flock_id = CID(genesis)");
    assert!(fx.genesis.parents.is_empty(), "genesis has no parents");
    let mut salted = fx.genesis.clone();
    salted.payload.salt = "t".into();
    assert_ne!(salted.content_id().unwrap(), id);
    let mut renamed = fx.genesis.clone();
    renamed.payload.name = "other".into();
    assert_ne!(renamed.content_id().unwrap(), id);
    let mut rekinded = fx.genesis.clone();
    rekinded.payload.kind = "not-genesis".into();
    assert_ne!(rekinded.content_id().unwrap(), id);
    let mut reroster = fx.genesis.clone();
    reroster.payload.roster.pop();
    assert_ne!(reroster.content_id().unwrap(), id);
    // another server certificate (generated key), same everything else
    let mut reserved = fx.genesis.clone();
    reserved.payload.server_cert = fx.key("other-server").cert().clone();
    assert_ne!(reserved.content_id().unwrap(), id);
}

/// A writer fork is refused: it takes no index, moves no head, and changes
/// no attempt. (A forked brief must not become the lane's latest attempt, a
/// forked ack must not make an untouched attempt `working`.)
#[test]
fn a_refused_fork_changes_nothing_and_does_not_fold() {
    use agent_mesh_flock::{LogEntry, Refusal, Verdict};

    let mut fx = Fx::new();
    let a = fx.brief("h1", "a");
    let first_head = fx.board.head_of(&fx.fp("shep")).unwrap();
    fx.brief("h2", "b");
    let untouched = fx.board.attempt(&a).unwrap();
    let before = (
        fx.board.entries().count(),
        fx.board.head_of(&fx.fp("shep")),
        fx.board.lanes(),
    );

    // Forks of the shepherd's chain: a brief and (from h1) an ack.
    let mut forked_brief = fx.event(
        "shep",
        Kind::Brief,
        Body::Brief {
            to: "h2".into(),
            lane: "b".into(),
        },
        &[],
    );
    forked_brief.prev = Some(first_head);
    let forked_brief = LogEntry {
        node: forked_brief.node(),
        signer: fx.signer("shep", false),
    };
    assert_eq!(
        fx.board.apply(&forked_brief),
        Verdict::Refuse(Refusal::WriterFork)
    );

    fx.emit(
        "h1",
        Kind::Job,
        Body::Job {
            lane: "z".into(),
            label: "x".into(),
        },
        &[],
    );
    let h1_first = fx.board.head_of(&fx.fp("h1")).unwrap();
    fx.emit(
        "h1",
        Kind::Job,
        Body::Job {
            lane: "y".into(),
            label: "x".into(),
        },
        &[],
    );
    let mut forked_ack = fx.event("h1", Kind::Ack, Body::Ack, &[("of", a)]);
    forked_ack.prev = Some(h1_first);
    let forked_ack = LogEntry {
        node: forked_ack.node(),
        signer: fx.signer("h1", false),
    };
    let heads = fx.board.head_of(&fx.fp("h1"));
    let entries = fx.board.entries().count();
    assert_eq!(
        fx.board.apply(&forked_ack),
        Verdict::Refuse(Refusal::WriterFork)
    );

    assert_eq!(fx.board.entries().count(), entries, "no index consumed");
    assert_eq!(fx.board.head_of(&fx.fp("h1")), heads, "head unmoved");
    assert_eq!(
        fx.board.attempt(&a).unwrap(),
        untouched,
        "attempt unchanged"
    );
    assert_eq!(before.1, fx.board.head_of(&fx.fp("shep")));
    assert_eq!(before.2, fx.board.lanes(), "lanes unchanged by either fork");
    assert_eq!(
        before.0 + 2,
        fx.board.entries().count(),
        "only the two real jobs"
    );

    // A log containing the fork is not an admitted log.
    let mut log = fx.log.clone();
    log.push(forked_brief);
    let err = Board::fold(&fx.genesis, &log).unwrap_err();
    assert_eq!(err.position, log.len() - 1);
    assert_eq!(err.refusal, Refusal::WriterFork);
}
