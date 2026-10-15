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
        Body::JobEnd { code: 0 },
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

#[test]
fn genesis_id_is_pinned() {
    use content_addressable::ContentAddressable;
    let fx = Fx::new();
    let id = fx.genesis.content_id().unwrap().to_string();
    assert_eq!(
        id, "bafyr4ifcrlakazmfoct46dap2t3uqba4jsiuttm7rdg3gmnnigga3pk464",
        "flock_id: {id}"
    );
}
