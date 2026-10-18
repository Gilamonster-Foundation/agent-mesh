//! The feed against a real server and a real session: the view's model is the
//! log's model, resumes from what it saved, follows live, and says so when the
//! stream goes away. Waits are blocking reads and joins, never sleeps.
#![cfg(unix)]

mod support;

use agent_mesh_flock_server::{bind_private, serve, Serving, Snapshot};
use agent_mesh_flock_session::{call, run, CtlReq, Policy, Session};
use agent_mesh_tui::feed::{Feed, Outcome};
use agent_mesh_tui::model::{fold, Link, Source};
use content_addressable::ContentAddressable as _;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::JoinHandle;
use support::busy;

/// A served flock with one session of `watcher` listening on a control socket.
struct Live {
    dir: tempfile::TempDir,
    serving: Option<Serving>,
    serve_sock: PathBuf,
    ctl: PathBuf,
    session: Option<JoinHandle<()>>,
    h2_token: String,
}

fn live() -> Live {
    let (mut f, _) = busy();
    let watcher_token = f.server.invite("watcher").unwrap().token;
    let h2_token = f.server.invite("h2").unwrap().token;
    let support::Fixture { dir, server, .. } = f;
    let serve_sock = dir.path().join("run").join("serve.sock");
    let serving = serve(server, bind_private(&serve_sock).unwrap()).unwrap();
    let ctl = dir.path().join("run").join("session-watcher.sock");
    let listener = bind_private(&ctl).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let sock = serve_sock.clone();
    let session = std::thread::spawn(move || {
        run(
            &sock,
            &watcher_token,
            "watcher",
            Policy::AllowUnlocked,
            &listener,
            None,
            |_| {
                let _ = ready_tx.send(());
            },
        )
        .unwrap();
    });
    ready_rx.recv().unwrap();
    Live {
        dir,
        serving: Some(serving),
        serve_sock,
        ctl,
        session: Some(session),
        h2_token,
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = call(&self.ctl, &CtlReq::End);
        if let Some(s) = self.session.take() {
            let _ = s.join();
        }
        if let Some(s) = self.serving.take() {
            s.stop();
        }
    }
}

fn disk_model(l: &Live) -> agent_mesh_tui::model::Model {
    let genesis = agent_mesh_flock_server::load_genesis(l.dir.path())
        .unwrap()
        .node;
    let snap = Snapshot::read(l.dir.path()).unwrap();
    let id = genesis.content_id().unwrap();
    fold(
        &Source::of_snapshot(&genesis.payload.name, id, &snap),
        Link::Live,
    )
}

#[test]
fn the_fed_model_is_the_logs_model_and_a_second_run_shows_nothing_twice() {
    let l = live();
    let mut feed = Feed::open(l.dir.path(), &l.ctl).unwrap();
    let mut links = vec![];
    assert_eq!(
        feed.run(true, &mut |m| links.push(m.header.link)),
        Outcome::Done
    );
    assert!(links.len() > 1, "the replay arrives frame by frame");
    // not live until it is caught up
    assert!(matches!(links[0], Link::Stale { .. }), "{:?}", links[0]);
    assert_eq!(links.last(), Some(&Link::Live));
    // the reader's directory is named by an id, never by the member
    let names: Vec<_> = std::fs::read_dir(l.dir.path().join("tui"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 1);
    assert!(!names[0].contains("watcher"), "{names:?}");
    assert_eq!(feed.model(Link::Live), disk_model(&l));
    drop(feed);

    // reopened: it resumes from its saved head, so only the marker arrives
    let mut feed = Feed::open(l.dir.path(), &l.ctl).unwrap();
    let mut seen = 0;
    assert_eq!(feed.run(true, &mut |_| seen += 1), Outcome::Done);
    assert_eq!(seen, 1, "nothing is replayed twice");
    assert_eq!(feed.model(Link::Live), disk_model(&l));
}

#[test]
fn a_following_feed_sees_a_live_event_then_says_so_when_the_stream_goes() {
    let mut l = live();
    let mut feed = Feed::open(l.dir.path(), &l.ctl).unwrap();
    let (tx, rx) = mpsc::channel();
    let runner = std::thread::spawn(move || {
        let outcome = feed.run(false, &mut |m| {
            let _ = tx.send(m);
        });
        (outcome, feed)
    });
    // wait for the replay to be delivered: the model has every event on disk
    let on_disk = disk_model(&l).header.verified;
    loop {
        let m = rx.recv().expect("the feed ended during the replay");
        if m.header.verified >= on_disk {
            break;
        }
    }
    // the next thing the feed sends is the caught-up marker, and it is live
    let caught = rx
        .recv()
        .expect("the feed ended before the caught-up marker");
    assert_eq!(caught.header.link, Link::Live, "caught up means live");
    // a member's session starts after the feed is caught up: it arrives live
    let sock = l.serve_sock.clone();
    let h2 = Session::enroll(&sock, &l.h2_token, "h2", Policy::AllowUnlocked).unwrap();
    loop {
        let m = rx.recv().expect("the feed ended before the live event");
        if m.members
            .iter()
            .any(|r| r.name == "h2" && r.session == "active")
        {
            assert_eq!(m.header.link, Link::Live, "an event after the replay");
            break;
        }
    }
    // the server goes away: the feed stops and the view says it is stale
    l.serving.take().unwrap().stop();
    let (outcome, feed) = runner.join().unwrap();
    assert!(matches!(outcome, Outcome::Down(_)), "{outcome:?}");
    assert!(matches!(feed.stale(), Link::Stale { since } if since > 0));
    drop(h2);
}

#[test]
fn a_session_of_another_flock_is_refused_before_anything_is_read() {
    let (a, b) = (live(), live());
    let err = match Feed::open(a.dir.path(), &b.ctl) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("opened a feed with another flock's session"),
    };
    assert!(err.contains("another flock"), "{err}");
    assert!(
        !a.dir.path().join("tui").exists(),
        "nothing was created for it"
    );
}

#[test]
fn the_binary_prints_one_frame_with_once_and_fails_loudly_without_a_session() {
    let l = live();
    let bin = env!("CARGO_BIN_EXE_amesh-tui");
    let out = std::process::Command::new(bin)
        .args(["--once", "--dir"])
        .arg(l.dir.path())
        .arg("--session")
        .arg(&l.ctl)
        .env_remove("AMESH_FLOCK_SESSION")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    for want in [
        "flock fx",
        "7 members",
        "log ✓",
        "live",
        "MEMBER",
        "herdr",
        "idle",
    ] {
        assert!(text.contains(want), "{want} missing from:\n{text}");
    }
    // a socket that is not a session: an error and a non-zero exit, no frame
    let bad = std::process::Command::new(bin)
        .args(["--once", "--dir"])
        .arg(l.dir.path())
        .arg("--session")
        .arg(l.dir.path().join("run").join("nope.sock"))
        .env_remove("AMESH_FLOCK_SESSION")
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(bad.stdout.is_empty());
}

#[test]
fn a_reader_directory_others_can_enter_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let l = live();
    let tui = l.dir.path().join("tui");
    std::fs::create_dir(&tui).unwrap();
    std::fs::set_permissions(&tui, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = match Feed::open(l.dir.path(), &l.ctl) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("opened over a loose directory"),
    };
    assert!(err.contains("only its owner"), "{err}");
}
