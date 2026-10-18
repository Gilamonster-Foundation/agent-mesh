//! `amesh flock watch` and the session's `ProveStream`, as real processes.
//! No sleeps: every wait is a blocking read or a process exit.
#![cfg(unix)]

mod harness;
use agent_mesh_flock_server::wire::StreamChallenge;
use agent_mesh_flock_session::{call, CtlReq, CtlResp};
use harness::*;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn words(s: &str) -> usize {
    s.lines().filter(|l| !l.trim().is_empty()).count()
}

#[test]
fn watch_once_shows_each_event_exactly_once_across_runs() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);

    let first = f.ok(&h1, &["watch", "--once"]);
    assert!(first.contains(&brief), "{first}");
    assert!(first.contains("-- caught up at "), "{first}");
    let n = words(&first);

    // nothing new: the reader resumed from its saved head, so only the marker
    let again = f.ok(&h1, &["watch", "--once"]);
    assert!(!again.contains(&brief), "shown twice:\n{again}");
    assert_eq!(words(&again), 1, "{again}");

    // one more event: exactly that one
    f.emit(&h1, &["take", &brief]);
    let next = f.ok(&h1, &["watch", "--once"]);
    assert_eq!(
        words(&next),
        2,
        "the ack and the marker, nothing else:
{next}"
    );
    assert!(next.contains(" ack "), "{next}");
    assert!(n >= 2);

    // --from shows saved events again, from that index
    let from = f.ok(&h1, &["watch", "--once", "--from", "1"]);
    assert!(from.contains(&brief) && from.contains(" ack "), "{from}");
}

#[test]
fn a_following_watch_prints_new_events_and_stops_when_its_session_ends() {
    let f = flock();
    let (shep, h1) = (f.session("shep"), f.session("h1"));
    let mut w = Command::new(assert_cmd::cargo::cargo_bin("amesh"));
    w.arg("--home").arg(f.home.path());
    w.args(["flock", "watch", "--dir"])
        .arg(&f.dir)
        .arg("--session")
        .arg(&h1.sock);
    w.env_remove("AMESH_FLOCK_SESSION");
    let mut child = w
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "ended before caught up"
        );
        if line.contains("-- caught up at ") {
            break;
        }
    }
    // a live event arrives on the open stream
    let brief = f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    loop {
        line.clear();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "ended before the brief"
        );
        if line.contains(&brief) {
            break;
        }
    }
    // the watching session says goodbye: the server closes its stream
    call(&h1.sock, &CtlReq::End).unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success());
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert!(err.contains("stream closed"), "{err}");
    drop(h1);
}

#[test]
fn the_session_signs_a_challenge_for_its_own_flock_and_only_that() {
    let a = flock();
    let b = flock();
    let sess = a.session("h1");
    let CtlResp::Who {
        flock: mine,
        session: mine_id,
        ..
    } = call(&sess.sock, &CtlReq::Whoami).unwrap()
    else {
        panic!("not Who")
    };
    let other = {
        let CtlResp::Who { flock, .. } = call(&b.session("h1").sock, &CtlReq::Whoami).unwrap()
        else {
            panic!("not Who")
        };
        flock
    };
    assert_ne!(mine, other);
    let own = StreamChallenge {
        flock: mine,
        nonce: [7; 32],
    };
    match call(
        &sess.sock,
        &CtlReq::ProveStream {
            challenge: own.clone(),
        },
    )
    .unwrap()
    {
        CtlResp::Proof(p) => {
            // by this session's key (that it covers exactly that id is the
            // server's check when the stream opens: see the watch tests)
            assert_eq!(p.author().agent_fingerprint().hex(), mine_id);
        }
        other => panic!("{other:?}"),
    }
    let foreign = StreamChallenge {
        flock: other,
        nonce: [7; 32],
    };
    let err = call(&sess.sock, &CtlReq::ProveStream { challenge: foreign }).unwrap_err();
    assert!(err.to_string().contains("another flock"), "{err}");
}

#[test]
fn watch_names_its_flock_and_refuses_another_flocks_session() {
    let (a, b) = (flock(), flock());
    let a_h1 = a.session("h1");
    let o = aimed(&b, Some(&a_h1.sock), None, &["watch", "--once"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("another flock"));
}

#[test]
fn a_watch_still_opens_after_an_epoch_bump_with_no_emit_in_between() {
    let f = flock();
    let (shep, h1, rev) = (f.session("shep"), f.session("h1"), f.session("rev"));
    f.ok(&h1, &["watch", "--once"]);
    // an unrelated member leaves: authority shrinks, the epoch rises
    call(&rev.sock, &CtlReq::End).unwrap();
    // h1 never emitted, yet its next watch must renew before it proves
    let out = f.ok(&h1, &["watch", "--once"]);
    assert!(out.contains("session-end"), "{out}");
    drop(shep);
}

#[test]
fn a_member_name_never_chooses_where_reader_state_lives() {
    use std::os::unix::fs::PermissionsExt as _;
    let outside = tempfile::tempdir().unwrap();
    let absolute = outside.path().join("abs-target");
    let abs = absolute.to_str().unwrap().to_owned();
    for name in ["../../escaped".to_owned(), abs] {
        let f = flock_with(&["shep:shepherd", &format!("{name}:helper")]);
        let s = f.session(&name);
        f.ok(&s, &["watch", "--once"]);
        let flocks = f.home.path().join("flocks");
        let names: Vec<_> = std::fs::read_dir(&flocks)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["f"], "nothing beside the flock for {name}");
        assert!(!absolute.exists(), "nothing created at {name}");
        let ours: Vec<_> = std::fs::read_dir(f.dir.join("watch"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(ours.len(), 1, "{ours:?}");
        let one = ours[0].to_str().unwrap();
        assert!(!one.contains('/') && !one.contains(".."), "{one}");
        let _ = std::fs::Permissions::from_mode(0o700);
    }
}

#[test]
fn an_existing_reader_directory_that_others_can_enter_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let f = flock();
    let h1 = f.session("h1");
    f.ok(&h1, &["watch", "--once"]);
    let watch = f.dir.join("watch");
    let member = std::fs::read_dir(&watch)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    for loose in [&member, &watch] {
        let before = std::fs::metadata(loose).unwrap().permissions();
        std::fs::set_permissions(loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        let o = f.run(Some(&h1), &["watch", "--once"]);
        assert!(!o.status.success(), "{}", loose.display());
        assert!(String::from_utf8_lossy(&o.stderr).contains("only its owner"));
        std::fs::set_permissions(loose, before).unwrap();
    }
    f.ok(&h1, &["watch", "--once"]);
}
