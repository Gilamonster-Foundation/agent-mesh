//! `amesh flock` join / inbox / status / log / brief / review / take /
//! result / verdict / run, as real processes: a server and one session per
//! member. Nothing here signs: every write goes through a session's socket.
#![cfg(unix)]

mod harness;
use harness::*;

#[test]
fn a_lane_runs_end_to_end_through_the_sessions() {
    let f = flock();
    let (shep, h1, rev) = (f.session("shep"), f.session("h1"), f.session("rev"));
    let joined = f.ok(&h1, &["join"]);
    assert!(joined.contains("member:  h1") && joined.contains("state:   active (in the log)"));

    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    assert!(
        f.ok(&h1, &["inbox"]).contains(&brief),
        "the brief is in h1's inbox"
    );
    assert!(f.ok(&rev, &["inbox"]).is_empty(), "and in nobody else's");
    assert!(f.ok(&shep, &["status"]).contains("submitted"));

    f.emit(&h1, &["take", &brief]);
    assert!(f.ok(&shep, &["status"]).contains("working"));
    assert!(f.ok(&h1, &["inbox"]).contains("working"));

    f.emit(&h1, &["result", &brief, "--outcome", "completed"]);
    assert!(f.ok(&shep, &["status"]).contains("completed"));
    assert!(
        f.ok(&h1, &["inbox"]).is_empty(),
        "a closed brief leaves the inbox"
    );

    let review = f.emit(
        &shep,
        &["review", "--to", "rev", "--lane", "l1", "--head", "abc"],
    );
    assert!(f.ok(&rev, &["inbox"]).contains(&review));
    f.emit(&rev, &["take", &review]);
    f.emit(&rev, &["verdict", &review, "--head", "abc", "--approve"]);
    assert!(f.ok(&rev, &["inbox"]).is_empty());

    let log = f.log(&shep);
    for kind in [
        "brief",
        "ack",
        "result",
        "review",
        "verdict",
        "session-start",
    ] {
        assert!(log.contains(kind), "{kind} missing from:\n{log}");
    }
    assert!(log.contains(&brief), "log shows full content ids");
    assert_eq!(f.ok(&shep, &["log", "--from", "1000"]), "");
}

#[test]
fn a_forged_ack_is_refused_by_the_server_and_leaves_the_log_alone() {
    let f = flock();
    let (shep, h1, h2) = (f.session("shep"), f.session("h1"), f.session("h2"));
    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    let before = f.log(&shep);

    // h2 was not addressed: the CLI sends it, admission says no
    let o = f.run(Some(&h2), &["take", &brief]);
    assert!(!o.status.success());
    let why = String::from_utf8_lossy(&o.stderr);
    assert!(why.contains("refused"), "{why}");
    assert_eq!(f.log(&shep), before);

    // a result from the wrong member, and a verdict with neither flag
    assert!(!f
        .run(Some(&h2), &["result", &brief, "--outcome", "completed"])
        .status
        .success());
    assert!(!f
        .run(Some(&h1), &["verdict", &brief, "--head", "x"])
        .status
        .success());
    // not a content id, not an outcome
    assert!(!f.run(Some(&h1), &["take", "nonsense"]).status.success());
    assert!(!f
        .run(Some(&h1), &["result", &brief, "--outcome", "meh"])
        .status
        .success());
    assert_eq!(f.log(&shep), before);
}

#[test]
fn announcing_outside_a_herdr_pane_is_refused() {
    let f = flock();
    let h1 = f.session("h1");
    let o = f.run(Some(&h1), &["join", "--announce"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not in a herdr pane"));
}

#[test]
fn announcing_inside_a_herdr_pane_writes_a_pane_claim() {
    let f = flock();
    let h1 = f.session_in("h1", Some(("p-7", "t-1")));
    let out = f.ok(&h1, &["join", "--announce"]);
    assert!(out.contains("announced"), "{out}");
    assert!(f.log(&h1).contains("pane"), "the claim is in the log");
}

#[test]
fn finding_the_session_never_guesses_and_ignores_dead_sockets() {
    let f = flock();
    let (shep, mut h1) = (f.session("shep"), f.session("h1"));

    // two live sessions and no --session: an error that names both
    let o = f.run(None, &["join"]);
    assert!(!o.status.success());
    let why = String::from_utf8_lossy(&o.stderr);
    assert!(why.contains("several live sessions"), "{why}");
    assert!(why.contains(shep.sock.to_str().unwrap()) && why.contains(h1.sock.to_str().unwrap()));

    // kill -9 leaves the socket file behind: it does not count
    h1.proc.0.kill().unwrap();
    h1.proc.0.wait().unwrap();
    assert!(h1.sock.exists(), "a killed session leaves its socket file");
    let o = f.run(None, &["join"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("member:  shep"));

    // no flock named at all
    let o = amesh(f.home.path())
        .args(["flock", "join"])
        .env_remove("AMESH_FLOCK_SESSION")
        .output()
        .unwrap();
    assert!(!o.status.success());
}

#[test]
fn a_session_from_another_flock_is_not_this_flocks_inbox() {
    let a = flock();
    let b = flock();
    let sa = a.session("h1");
    let o = amesh(b.home.path())
        .args(["flock", "inbox", "--dir"])
        .arg(&b.dir)
        .arg("--session")
        .arg(&sa.sock)
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("another flock"));
}

#[test]
fn a_verdict_needs_exactly_one_of_approve_or_reject() {
    let f = flock();
    let (shep, rev) = (f.session("shep"), f.session("rev"));
    let review = f.emit(
        &shep,
        &["review", "--to", "rev", "--lane", "l1", "--head", "abc"],
    );
    f.emit(&rev, &["take", &review]);
    let before = f.log(&shep);
    // a valid verdict would be admitted, so only the flag check can refuse these
    let neither = f.run(Some(&rev), &["verdict", &review, "--head", "abc"]);
    assert!(String::from_utf8_lossy(&neither.stderr).contains("exactly one"));
    assert!(!f
        .run(
            Some(&rev),
            &["verdict", &review, "--head", "abc", "--approve", "--reject"]
        )
        .status
        .success());
    assert_eq!(f.log(&shep), before);
    f.emit(&rev, &["verdict", &review, "--head", "abc", "--reject"]);
    assert!(f.log(&shep).contains("rejected abc"));
}

#[test]
fn naming_one_flock_never_writes_to_another_through_any_selector() {
    let (a, b) = (flock(), flock());
    let (a_shep, b_shep) = (a.session("shep"), b.session("shep"));
    let (a_before, b_before) = (a.log(&a_shep), b.log(&b_shep));
    let brief = ["brief", "--to", "h1", "--lane", "task"];

    // explicit --session of A while naming B
    let o = aimed(&b, Some(&a_shep.sock), None, &brief);
    assert!(!o.status.success(), "explicit socket");
    assert!(String::from_utf8_lossy(&o.stderr).contains("another flock"));
    // AMESH_FLOCK_SESSION of A while naming B
    let o = aimed(&b, None, Some(&a_shep.sock), &brief);
    assert!(!o.status.success(), "environment socket");
    // announce and join are writers too
    assert!(
        !aimed(&b, Some(&a_shep.sock), None, &["join", "--announce"])
            .status
            .success()
    );
    assert_eq!(a.log(&a_shep), a_before, "A untouched");
    assert_eq!(b.log(&b_shep), b_before, "B untouched");

    // a foreign socket found under B/run/: discovery must not accept it
    let c = flock(); // a flock with no live session of its own
    std::os::unix::fs::symlink(&a_shep.sock, c.dir.join("run").join("session-foreign.sock"))
        .unwrap();
    let o = aimed(&c, None, None, &brief);
    assert!(!o.status.success(), "foreign socket under run/");
    assert_eq!(a.log(&a_shep), a_before, "A untouched by the symlink");

    // with a session of its own as well, the foreign one is ignored, not chosen
    let c_shep = c.session("shep");
    let o = aimed(&c, None, None, &brief);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(a.log(&a_shep), a_before, "A still untouched");
    assert!(c.log(&c_shep).contains("brief"), "it went to C");
}

#[test]
fn with_no_flock_named_the_session_alone_decides() {
    let a = flock();
    let shep = a.session("shep");
    let mut c = amesh(a.home.path());
    c.args(["flock", "brief", "--to", "h1", "--lane", "t", "--session"])
        .arg(&shep.sock)
        .env_remove("AMESH_FLOCK_SESSION");
    assert!(c.output().unwrap().status.success());
    assert!(a.log(&shep).contains("brief"));
}

#[test]
fn join_labels_the_enrollment_flag_and_reads_the_current_state_from_the_log() {
    let f = flock();
    let _first = f.session("h1");
    let second = f.session("h1"); // a replacement: pending until a hand-off
    let out = f.ok(&second, &["join"]);
    assert!(out.contains("enrolled: pending (at enrollment"), "{out}");
    assert!(out.contains("state:   pending (in the log)"), "{out}");
    // without a flock named there is no log to ask: say so, do not guess
    let mut c = amesh(f.home.path());
    c.args(["flock", "join", "--session"])
        .arg(&second.sock)
        .env_remove("AMESH_FLOCK_SESSION");
    let out = String::from_utf8(c.output().unwrap().stdout).unwrap();
    assert!(out.contains("state:   unknown"), "{out}");
}

#[test]
fn run_records_how_the_command_really_ended() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);

    // killed by signal 9: the log says so, and we exit like a shell would
    let o = f.run(
        Some(&h1),
        &["run", "--lane", "l1", "--", "sh", "-c", "kill -9 $$"],
    );
    assert_eq!(
        code(&o),
        Some(137),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(f.log(&shep).contains("signal 9"), "{}", f.log(&shep));
    assert!(
        !f.ok(&shep, &["status"]).contains("job open"),
        "the job is closed"
    );

    // an exit code passes through, and the command's own output is untouched
    let o = f.run(
        Some(&h1),
        &["run", "--lane", "l1", "--", "sh", "-c", "echo hi; exit 3"],
    );
    assert_eq!(code(&o), Some(3));
    assert_eq!(String::from_utf8_lossy(&o.stdout), "hi\n");
    assert!(f.log(&shep).contains("exit 3"));

    let o = f.run(
        Some(&h1),
        &["run", "--lane", "l1", "--label", "ok", "--", "true"],
    );
    assert_eq!(code(&o), Some(0));
    assert!(f.log(&shep).contains("lane l1 ok"));
    assert!(f.log(&shep).contains("exit 0"));

    // a command that cannot start still closes its job, as 127
    let o = f.run(
        Some(&h1),
        &["run", "--lane", "l1", "--", "/no/such/command"],
    );
    assert_eq!(code(&o), Some(1)); // an error from amesh
    assert!(String::from_utf8_lossy(&o.stderr).contains("cannot run"));
    assert!(f.log(&shep).contains("exit 127"));
    assert!(!f.ok(&shep, &["status"]).contains("job open"));
}

#[test]
fn run_never_starts_the_command_for_a_session_of_another_flock() {
    let (a, b) = (flock(), flock());
    let a_h1 = a.session("h1");
    let marker = a.home.path().join("ran");
    let o = aimed(
        &b,
        Some(&a_h1.sock),
        None,
        &[
            "run",
            "--lane",
            "l",
            "--",
            "touch",
            marker.to_str().unwrap(),
        ],
    );
    assert!(!o.status.success());
    assert!(!marker.exists(), "the command must not have run");
}
