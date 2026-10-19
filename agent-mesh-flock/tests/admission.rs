//! Every row of the admission table, accepted and refused.

mod fixture;

use agent_mesh_flock::{Body, ConflictKind, Kind, Outcome, Refusal, Verdict};
use content_addressable::ContentAddressable;
use fixture::Fx;

fn job(lane: &str) -> Body {
    Body::Job {
        lane: lane.into(),
        label: "push".into(),
    }
}
fn ask(lane: Option<&str>) -> Body {
    Body::Ask {
        lane: lane.map(Into::into),
        text: "publish?".into(),
    }
}
fn answer() -> Body {
    Body::Answer { text: "yes".into() }
}
fn result(outcome: Outcome) -> Body {
    Body::Result { outcome }
}

#[test]
fn brief_and_review_are_the_shepherds() {
    let mut fx = Fx::new();
    let b = Body::Brief {
        to: "h1".into(),
        lane: "a".into(),
    };
    assert_eq!(
        fx.judge("shep", Kind::Brief, b.clone(), &[]),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge("h1", Kind::Brief, b, &[]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
    let r = Body::Review {
        to: "rev".into(),
        lane: "a".into(),
        head: "h".into(),
    };
    assert_eq!(
        fx.judge("shep", Kind::Review, r.clone(), &[]),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge("herdr", Kind::Review, r, &[]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
}

#[test]
fn ack_is_the_addressees_never_the_adapters() {
    let mut fx = Fx::new();
    let brief = fx.brief("h1", "a");
    assert_eq!(
        fx.judge("h1", Kind::Ack, Body::Ack, &[("of", brief)]),
        Verdict::Admit
    );
    // an un-addressed member
    assert_eq!(
        fx.judge("h2", Kind::Ack, Body::Ack, &[("of", brief)]),
        Verdict::Refuse(Refusal::NotAddressee)
    );
    // the adapter, for a brief addressed to someone else
    assert_eq!(
        fx.judge("herdr", Kind::Ack, Body::Ack, &[("of", brief)]),
        Verdict::Refuse(Refusal::AdapterCannotAck)
    );
    // and for a brief addressed to the adapter itself
    let to_adapter = fx.brief("herdr", "b");
    assert_eq!(
        fx.judge("herdr", Kind::Ack, Body::Ack, &[("of", to_adapter)]),
        Verdict::Refuse(Refusal::AdapterCannotAck)
    );
}

#[test]
fn result_closes_the_brief_and_a_second_is_a_conflict() {
    let mut fx = Fx::new();
    let brief = fx.brief("h1", "a");
    assert_eq!(
        fx.judge(
            "h2",
            Kind::Result,
            result(Outcome::Completed),
            &[("brief", brief)]
        ),
        Verdict::Refuse(Refusal::NotAddressee)
    );
    let first = fx.emit(
        "h1",
        Kind::Result,
        result(Outcome::Completed),
        &[("brief", brief)],
    );
    assert_eq!(fx.board.closer_of(&brief), Some(first));
    assert_eq!(
        fx.judge(
            "h1",
            Kind::Result,
            result(Outcome::Failed),
            &[("brief", brief)]
        ),
        Verdict::Conflict(ConflictKind::SecondCloser { first })
    );
    // the conflict never replaces the first closer
    fx.emit(
        "h1",
        Kind::Result,
        result(Outcome::Failed),
        &[("brief", brief)],
    );
    assert_eq!(fx.board.closer_of(&brief), Some(first));
}

#[test]
fn verdict_head_must_equal_the_reviews() {
    let mut fx = Fx::new();
    let review = fx.review("rev", "a", "abc123");
    let wrong = Body::Verdict {
        head: "other".into(),
        approved: true,
    };
    assert_eq!(
        fx.judge("rev", Kind::Verdict, wrong, &[("review", review)]),
        Verdict::Refuse(Refusal::HeadMismatch)
    );
    let right = Body::Verdict {
        head: "abc123".into(),
        approved: true,
    };
    assert_eq!(
        fx.judge("h1", Kind::Verdict, right.clone(), &[("review", review)]),
        Verdict::Refuse(Refusal::NotAddressee)
    );
    let first = fx.emit("rev", Kind::Verdict, right.clone(), &[("review", review)]);
    assert_eq!(
        fx.judge("rev", Kind::Verdict, right, &[("review", review)]),
        Verdict::Conflict(ConflictKind::SecondCloser { first })
    );
}

#[test]
fn job_end_is_the_job_authors() {
    let mut fx = Fx::new();
    let j = fx.emit("h1", Kind::Job, job("a"), &[]);
    let end = Body::JobEnd {
        code: Some(0),
        signal: None,
    };
    assert_eq!(
        fx.judge("h2", Kind::JobEnd, end.clone(), &[("job", j)]),
        Verdict::Refuse(Refusal::NotAddressee)
    );
    let first = fx.emit("h1", Kind::JobEnd, end.clone(), &[("job", j)]);
    assert_eq!(
        fx.judge("h1", Kind::JobEnd, end, &[("job", j)]),
        Verdict::Conflict(ConflictKind::SecondCloser { first })
    );
}

#[test]
fn a_job_end_says_exactly_one_of_an_exit_code_and_a_signal() {
    let mut fx = Fx::new();
    let j = fx.emit("h1", Kind::Job, job("a"), &[]);
    let end = |code, signal| Body::JobEnd { code, signal };
    for (code, signal) in [(None, None), (Some(1), Some(9))] {
        assert_eq!(
            fx.judge("h1", Kind::JobEnd, end(code, signal), &[("job", j)]),
            Verdict::Refuse(Refusal::BadExit),
            "{code:?} {signal:?}"
        );
    }
    // killed by a signal: admitted, and it closes the job
    fx.emit("h1", Kind::JobEnd, end(None, Some(9)), &[("job", j)]);
}

#[test]
fn relayed_answer_leaves_the_ask_open_and_an_operator_answer_closes_it() {
    let mut fx = Fx::new();
    let q = fx.emit("h1", Kind::Ask, ask(None), &[]);
    let relayed = Body::RelayedAnswer { text: "yes".into() };
    assert_eq!(
        fx.judge("h2", Kind::RelayedAnswer, relayed.clone(), &[("ask", q)]),
        Verdict::Admit
    );
    fx.emit("h2", Kind::RelayedAnswer, relayed, &[("ask", q)]);
    assert_eq!(fx.board.closer_of(&q), None, "relay closes nothing");
    // a member session cannot answer
    assert_eq!(
        fx.judge("h2", Kind::Answer, answer(), &[("ask", q)]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
    let closer = fx.emit("op", Kind::Answer, answer(), &[("ask", q)]);
    assert_eq!(fx.board.closer_of(&q), Some(closer));
}

#[test]
fn operator_keys_answer_only_and_chain_from_nothing() {
    let mut fx = Fx::new();
    let b = Body::Brief {
        to: "h1".into(),
        lane: "a".into(),
    };
    assert_eq!(
        fx.judge("op", Kind::Brief, b, &[]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
    let q = fx.emit("h1", Kind::Ask, ask(None), &[]);
    let mut ev = fx.event("op", Kind::Answer, answer(), &[("ask", q)]);
    ev.prev = Some(q);
    // `prev` is not `refs`; operator answers carry none
    let node = ev.node();
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &node, &fx.signer("op", false)),
        Verdict::Refuse(Refusal::BadPrev)
    );
}

#[test]
fn adapter_signs_status_and_nudged_only() {
    let mut fx = Fx::new();
    let status = Body::Status {
        text: "idle".into(),
    };
    let nudged = Body::Nudged {
        target: "h1".into(),
    };
    assert_eq!(
        fx.judge("herdr", Kind::Status, status.clone(), &[]),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge("herdr", Kind::Nudged, nudged.clone(), &[]),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge("h1", Kind::Status, status, &[]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
    assert_eq!(
        fx.judge("shep", Kind::Nudged, nudged, &[]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
}

#[test]
fn a_pending_session_signs_nothing() {
    let mut fx = Fx::new();
    let node = fx.event("h1", Kind::Job, job("a"), &[]).node();
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &node, &fx.signer("h1", true)),
        Verdict::Refuse(Refusal::PendingSession)
    );
}

#[test]
fn refs_stay_in_the_lane_and_the_kind() {
    let mut fx = Fx::new();
    let brief = fx.brief("h1", "a");
    assert_eq!(
        fx.judge("h1", Kind::Ask, ask(Some("a")), &[("about", brief)]),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge("h1", Kind::Ask, ask(Some("b")), &[("about", brief)]),
        Verdict::Refuse(Refusal::CrossLane)
    );
    let review = fx.review("rev", "a", "h");
    assert_eq!(
        fx.judge(
            "h1",
            Kind::Result,
            result(Outcome::Completed),
            &[("brief", review)]
        ),
        Verdict::Refuse(Refusal::WrongRefKind("brief"))
    );
    assert_eq!(
        fx.judge("h1", Kind::Result, result(Outcome::Completed), &[]),
        Verdict::Refuse(Refusal::MissingRef("brief"))
    );
    assert!(matches!(
        fx.judge("h1", Kind::Job, job("a"), &[("brief", brief)]),
        Verdict::Refuse(Refusal::UnexpectedRef(_))
    ));
    let unknown = fx.flock; // exists as a CID, but is not an admitted event
    assert_eq!(
        fx.judge(
            "h1",
            Kind::Result,
            result(Outcome::Completed),
            &[("brief", unknown)]
        ),
        Verdict::Refuse(Refusal::UnknownRef("brief"))
    );
}

#[test]
fn roster_replacement_names_the_current_roster() {
    let mut fx = Fx::new();
    let body = Body::Roster {
        members: fx.board.members().to_vec(),
    };
    let genesis = fx.flock;
    assert_eq!(
        fx.judge("shep", Kind::Roster, body.clone(), &[("replaces", genesis)]),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge(
            "server",
            Kind::Roster,
            body.clone(),
            &[("replaces", genesis)]
        ),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge("h1", Kind::Roster, body.clone(), &[("replaces", genesis)]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
    let first = fx.emit("shep", Kind::Roster, body.clone(), &[("replaces", genesis)]);
    assert_eq!(fx.board.roster_id(), first);
    // a racing replacement still naming the old roster is stale
    assert_eq!(
        fx.judge("server", Kind::Roster, body, &[("replaces", genesis)]),
        Verdict::Refuse(Refusal::StaleRoster)
    );
}

#[test]
fn server_kinds_are_the_servers() {
    let mut fx = Fx::new();
    let note = Body::Epoch { epoch: 1 };
    assert_eq!(
        fx.judge("server", Kind::Epoch, note.clone(), &[]),
        Verdict::Admit
    );
    assert_eq!(
        fx.judge("shep", Kind::Epoch, note.clone(), &[]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
    assert_eq!(
        fx.judge(
            "server",
            Kind::Brief,
            Body::Brief {
                to: "h1".into(),
                lane: "a".into()
            },
            &[]
        ),
        Verdict::Refuse(Refusal::NotAllowed)
    );
    assert_eq!(
        fx.judge("op", Kind::Epoch, note, &[]),
        Verdict::Refuse(Refusal::NotAllowed)
    );
}

#[test]
fn identity_and_structure_checks() {
    let mut fx = Fx::new();
    let b = Body::Brief {
        to: "h1".into(),
        lane: "a".into(),
    };
    // author must be the signer
    let mut ev = fx.event("shep", Kind::Brief, b.clone(), &[]);
    ev.author = fx.fp("h1");
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &ev.node(), &fx.signer("shep", false)),
        Verdict::Refuse(Refusal::AuthorMismatch)
    );
    // another flock
    let mut ev = fx.event("shep", Kind::Brief, b.clone(), &[]);
    ev.flock = content_addressable::MerkleNode::genesis("other")
        .content_id()
        .unwrap();
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &ev.node(), &fx.signer("shep", false)),
        Verdict::Refuse(Refusal::WrongFlock)
    );
    // body from another kind
    assert_eq!(
        fx.judge("shep", Kind::Review, b.clone(), &[]),
        Verdict::Refuse(Refusal::BodyKindMismatch)
    );
    // a node whose parents are not prev + refs
    let ev = fx.event("shep", Kind::Brief, b, &[]);
    let node = content_addressable::MerkleNode::new(ev, [fx.flock]);
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &node, &fx.signer("shep", false)),
        Verdict::Refuse(Refusal::BadParents)
    );
}

#[test]
fn duplicates_return_their_index_and_forks_are_refused() {
    let mut fx = Fx::new();
    let first = fx.brief("h1", "a");
    let second = fx.brief("h2", "b");
    assert_eq!(fx.board.get(&first).unwrap().index, 1);
    assert_eq!(fx.board.get(&second).unwrap().index, 2);
    let replay = fx.log[0].clone();
    assert_eq!(fx.board.apply(&replay), Verdict::Duplicate(1));

    // a second child of `first`'s position: prev = first, but head moved on
    let mut ev = fx.event(
        "shep",
        Kind::Brief,
        Body::Brief {
            to: "h1".into(),
            lane: "c".into(),
        },
        &[],
    );
    ev.prev = Some(first);
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &ev.node(), &fx.signer("shep", false)),
        Verdict::Refuse(Refusal::WriterFork)
    );
    // a prev nobody admitted is not a chain at all
    let mut ev = fx.event(
        "shep",
        Kind::Brief,
        Body::Brief {
            to: "h1".into(),
            lane: "c".into(),
        },
        &[],
    );
    ev.prev = Some(fx.flock);
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &ev.node(), &fx.signer("shep", false)),
        Verdict::Refuse(Refusal::BadPrev)
    );
}

fn pane(pane: &str, tab: &str) -> Body {
    Body::Pane {
        pane: pane.into(),
        tab: tab.into(),
    }
}

#[test]
fn any_active_session_may_say_which_pane_it_is_in_and_nobody_else() {
    let mut fx = Fx::new();
    for who in ["shep", "h1", "herdr"] {
        let id = fx.emit(who, Kind::Pane, pane("w1:p2", "w1:t1"), &[]);
        // a second claim chains onto the first; the later one stands
        assert_eq!(
            fx.judge(who, Kind::Pane, pane("w1:p3", "w1:t1"), &[]),
            Verdict::Admit
        );
        let _ = id;
    }
    // the server and the operator are not in a pane
    for who in ["server", "op"] {
        assert_eq!(
            fx.judge(who, Kind::Pane, pane("w1:p2", "w1:t1"), &[]),
            Verdict::Refuse(Refusal::NotAllowed),
            "{who}"
        );
    }
    // a pending replacement signs nothing
    let node = fx.event("h1", Kind::Pane, pane("a", "b"), &[]).node();
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &node, &fx.signer("h1", true)),
        Verdict::Refuse(Refusal::PendingSession)
    );
}

#[test]
fn a_pane_claim_is_a_short_printable_id_and_takes_no_references() {
    let mut fx = Fx::new();
    let bad = [
        pane("", "w1:t1"),
        pane("w1:p2", ""),
        pane(&"x".repeat(129), "t"),
        pane("w1:p2\n", "t"),
        pane("w1:p2", "t\u{1b}[31m"),
    ];
    for b in bad {
        assert_eq!(
            fx.judge("h1", Kind::Pane, b, &[]),
            Verdict::Refuse(Refusal::BadClaim)
        );
    }
    let brief = fx.brief("h1", "a");
    assert_eq!(
        fx.judge("h1", Kind::Pane, pane("w1:p2", "t"), &[("of", brief)]),
        Verdict::Refuse(Refusal::UnexpectedRef("of".into()))
    );
}

#[test]
fn an_operator_key_the_roster_does_not_list_may_not_answer() {
    let mut fx = Fx::new();
    let q = fx.emit("h1", Kind::Ask, ask(None), &[]);
    let ev = fx.event("op", Kind::Answer, answer(), &[("ask", q)]);
    // same body and author, but the signer is another operator-class key
    let mut stranger = fx.signer("op", false);
    stranger.fingerprint = fx.key("op2").fingerprint();
    let mut ev = ev;
    ev.author = stranger.fingerprint.hex();
    assert_eq!(
        agent_mesh_flock::admit(&fx.board, &ev.node(), &stranger),
        Verdict::Refuse(Refusal::NotAListedDevice)
    );
}
