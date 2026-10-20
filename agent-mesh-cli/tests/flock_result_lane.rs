//! `amesh flock result|verdict`: the target is resolved from the verified log
//! (`--lane`), and one that is already closed is refused before anything is
//! sent, so a fix round cannot close the wrong brief by accident.
#![cfg(unix)]

mod harness;
use agent_mesh_flock::Kind;
use agent_mesh_flock_server::Snapshot;
use harness::*;
use std::process::Output;

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn kinds(f: &Flock, k: Kind) -> usize {
    Snapshot::read(&f.dir)
        .unwrap()
        .board()
        .entries()
        .filter(|e| e.event.kind == k)
        .count()
}

/// shep briefs h1 on lane `l1`; h1 takes it and closes it.
fn first_round(f: &Flock, shep: &Sess, h1: &Sess) -> String {
    let b1 = f.emit(shep, &["brief", "--to", "h1", "--lane", "l1"]);
    f.emit(h1, &["take", &b1]);
    f.emit(h1, &["result", &b1, "--outcome", "completed"]);
    b1
}

#[test]
fn a_result_for_the_old_closed_brief_is_refused_naming_the_open_one_and_sends_nothing() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    let b1 = first_round(&f, &shep, &h1);
    let b2 = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]); // the fix round
    let before = f.log(&shep);

    let o = f.run(Some(&h1), &["result", &b1, "--outcome", "completed"]);
    assert!(!o.status.success());
    let why = err(&o);
    assert!(why.contains("already closed"), "{why}");
    assert!(why.contains(&b1) && why.contains(&b2), "names both: {why}");
    assert!(why.contains("--lane l1"), "{why}");
    assert_eq!(f.log(&shep), before, "a conflict event was sent");
}

#[test]
fn result_by_lane_closes_the_members_open_brief() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    first_round(&f, &shep, &h1);
    let b2 = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    f.emit(&h1, &["take", &b2]);
    f.emit(&h1, &["result", "--lane", "l1", "--outcome", "completed"]);
    let snap = Snapshot::read(&f.dir).unwrap();
    let closer = snap
        .board()
        .entries()
        .filter(|e| e.event.kind == Kind::Result && e.conflict.is_none())
        .last()
        .unwrap();
    assert_eq!(
        closer.event.refs.get("brief").map(ToString::to_string),
        Some(b2)
    );
    assert_eq!(kinds(&f, Kind::Result), 2, "no stray conflict result");
    assert!(f.ok(&shep, &["status"]).contains("completed"));
}

#[test]
fn the_lane_cases_that_cannot_work_are_refused_with_the_reason() {
    let f = flock();
    let (shep, h1, h2) = (f.session("shep"), f.session("h1"), f.session("h2"));
    let b1 = first_round(&f, &shep, &h1);
    // nothing open: only the closed one
    let o = f.run(
        Some(&h1),
        &["result", "--lane", "l1", "--outcome", "completed"],
    );
    assert!(!o.status.success());
    assert!(
        err(&o).contains("no open brief") && err(&o).contains(&b1),
        "{}",
        err(&o)
    );
    // nothing addressed there at all
    let o = f.run(
        Some(&h1),
        &["result", "--lane", "nope", "--outcome", "completed"],
    );
    assert!(err(&o).contains("nothing is addressed"), "{}", err(&o));
    // a brief for someone else in the lane is not this member's
    let other = f.emit(&shep, &["brief", "--to", "h2", "--lane", "l1"]);
    let o = f.run(
        Some(&h1),
        &["result", "--lane", "l1", "--outcome", "completed"],
    );
    assert!(!o.status.success(), "h1 closed h2's brief?");
    // the CLI's own answer: h1 has nothing open there (not an admission refusal)
    assert!(err(&o).contains("no open brief"), "{}", err(&o));
    assert!(!err(&o).contains(&other), "{}", err(&o));
    // several open: named, not guessed
    let (x, y) = (
        f.emit(&shep, &["brief", "--to", "h1", "--lane", "twice"]),
        f.emit(&shep, &["brief", "--to", "h1", "--lane", "twice"]),
    );
    let o = f.run(
        Some(&h1),
        &["result", "--lane", "twice", "--outcome", "completed"],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("2 open briefs") && err(&o).contains(&x) && err(&o).contains(&y));
    drop(h2);
}

#[test]
fn an_open_brief_by_id_still_works_and_so_does_naming_neither_or_both() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    let b = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    f.emit(&h1, &["take", &b]);
    assert!(!f
        .run(Some(&h1), &["result", "--outcome", "completed"])
        .status
        .success());
    assert!(!f
        .run(
            Some(&h1),
            &["result", &b, "--lane", "l1", "--outcome", "completed"]
        )
        .status
        .success());
    f.emit(&h1, &["result", &b, "--outcome", "completed"]);
}

#[test]
fn the_check_works_with_only_a_session_socket() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    let b1 = first_round(&f, &shep, &h1);
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    // no --dir/--name: the flock is found from the session's own directory
    let o = amesh(f.home.path())
        .args([
            "flock",
            "result",
            &b1,
            "--outcome",
            "completed",
            "--session",
        ])
        .arg(&h1.sock)
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(err(&o).contains("already closed"), "{}", err(&o));
}

#[test]
fn verdict_has_the_same_guards() {
    let f = flock();
    let (shep, rev) = (f.session("shep"), f.session("rev"));
    let r1 = f.emit(
        &shep,
        &["review", "--to", "rev", "--lane", "l1", "--head", "aaa"],
    );
    f.emit(&rev, &["take", &r1]);
    f.emit(&rev, &["verdict", &r1, "--head", "aaa", "--reject"]);
    let r2 = f.emit(
        &shep,
        &["review", "--to", "rev", "--lane", "l1", "--head", "bbb"],
    );
    f.emit(&rev, &["take", &r2]);
    let before = f.log(&shep);

    let o = f.run(Some(&rev), &["verdict", &r1, "--head", "aaa", "--approve"]);
    assert!(!o.status.success());
    assert!(
        err(&o).contains("already closed") && err(&o).contains(&r2),
        "{}",
        err(&o)
    );
    assert_eq!(f.log(&shep), before);

    f.emit(
        &rev,
        &["verdict", "--lane", "l1", "--head", "bbb", "--approve"],
    );
    assert_eq!(kinds(&f, Kind::Verdict), 2);
    let o = f.run(
        Some(&rev),
        &["verdict", "--lane", "l1", "--head", "bbb", "--approve"],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("no open review"), "{}", err(&o));
}
