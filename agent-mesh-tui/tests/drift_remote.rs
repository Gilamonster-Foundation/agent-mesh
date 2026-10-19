//! "Changed since cited" for a root this host does not map: asked of the
//! flock's server through a session, as a remote attach does.
#![cfg(unix)]

mod support;

use agent_mesh_flock::FileRef;
use content_addressable::RawContentId;

fn cite(root: &str, path: &str, bytes: &[u8]) -> FileRef {
    FileRef {
        root: root.into(),
        path: path.into(),
        id: RawContentId::from_content(bytes),
    }
}

fn unavailable(s: &agent_mesh_tui::drift::FileState) -> &str {
    match s {
        agent_mesh_tui::drift::FileState::Unavailable(why) => why,
        other => panic!("expected unavailable, got {other:?}"),
    }
}

use agent_mesh_flock_server::{bind_private, serve, Serving};
use agent_mesh_flock_session::{call, run, CtlReq, Policy};
use agent_mesh_tui::drift::{check_all_via, FileState, Remote, Roots};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc;

/// A served flock that maps `notes` to a directory, and a session of
/// `watcher` on a control socket: what the view's `--session` is.
struct Home {
    _dir: tempfile::TempDir,
    notes: PathBuf,
    serve_sock: PathBuf,
    ctl: PathBuf,
    serving: Option<Serving>,
    session: Option<std::thread::JoinHandle<()>>,
}

fn home() -> Home {
    let (mut f, _) = support::busy();
    let token = f.server.invite("watcher").unwrap().token;
    let notes = f.path().join("files-notes");
    std::fs::create_dir(&notes).unwrap();
    f.server
        .serve_roots(BTreeMap::from([("notes".to_owned(), notes.clone())]))
        .unwrap();
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
            &token,
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
    Home {
        _dir: dir,
        notes,
        serve_sock,
        ctl,
        serving: Some(serving),
        session: Some(session),
    }
}

impl Drop for Home {
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

fn drift(
    h: &Home,
    roots: &Roots,
    files: &[agent_mesh_flock::FileRef],
) -> agent_mesh_tui::drift::Drift {
    let remote = Remote {
        serve: &h.serve_sock,
        ctl: &h.ctl,
    };
    check_all_via(roots, Some(remote), files)
}

fn state<'a>(d: &'a agent_mesh_tui::drift::Drift, f: &agent_mesh_flock::FileRef) -> &'a FileState {
    &d[&agent_mesh_tui::drift::key(f)]
}

#[test]
fn a_root_this_host_does_not_map_is_asked_of_the_server() {
    let h = home();
    std::fs::write(h.notes.join("a.md"), b"as cited").unwrap();
    let same = cite("notes", "a.md", b"as cited");
    let moved = cite("notes", "a.md", b"cited earlier");
    let gone = cite("notes", "gone.md", b"x");
    let outside = cite("notes", "../a.md", b"x");
    let d = drift(
        &h,
        &Roots::default(),
        &[same.clone(), moved.clone(), gone.clone(), outside.clone()],
    );
    assert_eq!(state(&d, &same), &FileState::Same);
    assert_eq!(
        state(&d, &moved),
        &FileState::Changed {
            current: content_addressable::RawContentId::from_content(b"as cited")
        }
    );
    assert_eq!(unavailable(state(&d, &gone)), "missing");
    assert_eq!(unavailable(state(&d, &outside)), "outside the root");
}

#[test]
fn a_root_mapped_here_is_read_here_not_asked() {
    let h = home();
    std::fs::write(h.notes.join("a.md"), b"on the home host").unwrap();
    let local = tempfile::tempdir().unwrap();
    std::fs::write(local.path().join("a.md"), b"on this host").unwrap();
    let mut roots = Roots::default();
    roots.insert("notes", local.path().to_owned());
    let f = cite("notes", "a.md", b"on this host");
    let d = drift(&h, &roots, std::slice::from_ref(&f));
    assert_eq!(state(&d, &f), &FileState::Same);
}

#[test]
fn without_a_server_to_ask_an_unmapped_root_is_not_mapped() {
    let f = cite("notes", "a.md", b"x");
    let d = check_all_via(&Roots::default(), None, std::slice::from_ref(&f));
    assert_eq!(unavailable(state(&d, &f)), "root not mapped");
}

#[test]
fn a_server_that_cannot_be_reached_says_so_for_each_file() {
    let h = home();
    let nowhere = h.notes.join("no.sock");
    let remote = Remote {
        serve: &nowhere,
        ctl: &h.ctl,
    };
    let f = cite("notes", "a.md", b"x");
    let g = cite("notes", "b.md", b"y");
    let d = check_all_via(&Roots::default(), Some(remote), &[f.clone(), g.clone()]);
    for x in [&f, &g] {
        assert!(
            unavailable(state(&d, x)).starts_with("the flock's server:"),
            "{:?}",
            state(&d, x)
        );
    }
}
