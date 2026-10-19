//! The cited-file service: what a member of the flock may read from a root
//! the roster declares, and everything it may not.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp, MAX_FILE};
use agent_mesh_flock_server::{bind_private, serve_with_attach, Serving};
use agent_mesh_protocol::{AgentKey, Assertion};
use content_addressable::RawContentId;
use std::collections::BTreeMap;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use support::{enroll, Enrolment, Env};

struct Rig {
    env: Env,
    serving: Serving,
    attach: PathBuf,
    /// The directory `notes` maps to.
    notes: PathBuf,
    /// Next to it, with a name that starts the same.
    secret: PathBuf,
    shep: Enrolment,
}

fn rig() -> Rig {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let notes = env.tmp.path().join("files").join("notes");
    let secret = env.tmp.path().join("files").join("notes-secret");
    std::fs::create_dir_all(&notes).unwrap();
    std::fs::create_dir_all(&secret).unwrap();
    std::fs::write(secret.join("key"), b"do not serve").unwrap();
    server
        .serve_roots(BTreeMap::from([("notes".to_owned(), notes.clone())]))
        .unwrap();
    let dir = env.tmp.path().join("run");
    let (owner, attach) = (dir.join("serve.sock"), dir.join("attach.sock"));
    let serving = serve_with_attach(
        server,
        bind_private(&owner).unwrap(),
        bind_private(&attach).unwrap(),
    )
    .unwrap();
    Rig {
        env,
        serving,
        attach,
        notes,
        secret,
        shep,
    }
}

/// A connection that has asked for a challenge and proved with `key`.
fn proved(r: &Rig, key: &AgentKey) -> (UnixStream, Resp) {
    let mut c = UnixStream::connect(&r.attach).unwrap();
    write_msg(&mut c, &Req::WatchBegin).unwrap();
    let Some(Resp::StreamChallenge(ch)) = read_msg::<Resp>(&mut c).unwrap() else {
        panic!("challenge")
    };
    let proof = Assertion::sign(key, &ch.id().unwrap());
    write_msg(
        &mut c,
        &Req::Prove {
            proof: Box::new(proof),
        },
    )
    .unwrap();
    let ans = read_msg::<Resp>(&mut c).unwrap().expect("an answer");
    (c, ans)
}

fn member(r: &Rig) -> UnixStream {
    let (c, ans) = proved(r, &r.shep.key);
    assert!(matches!(ans, Resp::Proved), "{ans:?}");
    c
}

fn call(c: &mut UnixStream, req: &Req) -> Resp {
    write_msg(c, req).unwrap();
    read_msg::<Resp>(c).unwrap().expect("an answer")
}

fn stat(c: &mut UnixStream, path: &str) -> Resp {
    call(
        c,
        &Req::FileStat {
            root: "notes".into(),
            path: path.into(),
        },
    )
}

fn fetch(c: &mut UnixStream, path: &str, id: RawContentId) -> Resp {
    call(
        c,
        &Req::File {
            root: "notes".into(),
            path: path.into(),
            id,
        },
    )
}

fn id_of(b: &[u8]) -> RawContentId {
    RawContentId::from_content(b)
}

fn unavailable(r: &Resp) -> &str {
    match r {
        Resp::Unavailable { reason } => reason,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn a_member_reads_a_cited_file_whose_bytes_still_hash_to_the_id() {
    let r = rig();
    std::fs::create_dir(r.notes.join("sub")).unwrap();
    std::fs::write(r.notes.join("sub").join("a.md"), b"hello").unwrap();
    let mut c = member(&r);
    let Resp::FileId { id } = stat(&mut c, "sub/a.md") else {
        panic!("stat")
    };
    assert_eq!(id, id_of(b"hello"));
    // the same connection serves more than one request
    match fetch(&mut c, "sub/a.md", id) {
        Resp::File { bytes } => assert_eq!(bytes, b"hello"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn changed_bytes_are_reported_and_never_served() {
    let r = rig();
    let file = r.notes.join("a.md");
    std::fs::write(&file, b"as cited").unwrap();
    let mut c = member(&r);
    let cited = id_of(b"as cited");
    std::fs::write(&file, b"edited since").unwrap();
    match fetch(&mut c, "a.md", cited) {
        Resp::ChangedSinceCited { current } => assert_eq!(current, id_of(b"edited since")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_connection_that_has_not_proved_membership_gets_no_file() {
    let r = rig();
    std::fs::write(r.notes.join("a.md"), b"x").unwrap();
    let mut c = UnixStream::connect(&r.attach).unwrap();
    for resp in [stat(&mut c, "a.md"), fetch(&mut c, "a.md", id_of(b"x"))] {
        assert!(matches!(resp, Resp::Err(_)), "{resp:?}");
    }
}

#[test]
fn a_key_that_is_not_a_session_of_the_flock_cannot_prove() {
    let r = rig();
    std::fs::write(r.notes.join("a.md"), b"x").unwrap();
    let stranger = AgentKey::issue(
        &agent_mesh_protocol::UserKey::generate(),
        support::meta("stranger"),
    );
    let (mut c, ans) = proved(&r, &stranger);
    assert!(matches!(ans, Resp::Err(_)), "{ans:?}");
    assert!(matches!(stat(&mut c, "a.md"), Resp::Err(_)));
}

#[test]
fn a_challenge_proves_once() {
    let r = rig();
    let mut c = UnixStream::connect(&r.attach).unwrap();
    write_msg(&mut c, &Req::WatchBegin).unwrap();
    let Some(Resp::StreamChallenge(ch)) = read_msg::<Resp>(&mut c).unwrap() else {
        panic!("challenge")
    };
    let bad = Assertion::sign(
        &AgentKey::issue(
            &agent_mesh_protocol::UserKey::generate(),
            support::meta("x"),
        ),
        &ch.id().unwrap(),
    );
    assert!(matches!(
        call(
            &mut c,
            &Req::Prove {
                proof: Box::new(bad)
            }
        ),
        Resp::Err(_)
    ));
    // the right proof on the spent challenge is no use
    let good = Assertion::sign(&r.shep.key, &ch.id().unwrap());
    assert!(matches!(
        call(
            &mut c,
            &Req::Prove {
                proof: Box::new(good)
            }
        ),
        Resp::Err(_)
    ));
}

#[test]
fn a_session_that_stops_being_a_member_loses_the_files() {
    let r = rig();
    std::fs::write(r.notes.join("a.md"), b"x").unwrap();
    let mut c = member(&r);
    assert!(matches!(stat(&mut c, "a.md"), Resp::FileId { .. }));
    // the roster drops shep: its connection is already proved, and must stop
    // reading
    r.serving
        .with_server(|s| {
            let keep = s
                .board()
                .members()
                .iter()
                .filter(|m| m.name != "shep")
                .cloned()
                .collect();
            s.replace_roster(keep)
        })
        .unwrap();
    assert!(matches!(stat(&mut c, "a.md"), Resp::Err(_)));
}

#[test]
fn paths_that_leave_the_root_are_refused() {
    let r = rig();
    std::fs::write(r.notes.join("a.md"), b"x").unwrap();
    let mut c = member(&r);
    let outside = r
        .env
        .tmp
        .path()
        .join("files")
        .join("notes-secret")
        .join("key");
    for (what, path) in [
        ("dotdot", "../notes-secret/key".to_owned()),
        ("dotdot inside", "sub/../../notes-secret/key".to_owned()),
        ("absolute", outside.display().to_string()),
        ("absolute root", "/etc/passwd".to_owned()),
    ] {
        let resp = stat(&mut c, &path);
        assert_eq!(unavailable(&resp), "outside the root", "{what}");
        let resp = fetch(&mut c, &path, id_of(b"do not serve"));
        assert_eq!(unavailable(&resp), "outside the root", "{what}");
    }
    for bad in ["", "a\0b"] {
        assert_eq!(unavailable(&stat(&mut c, bad)), "not a usable path");
    }
}

#[test]
fn a_symlink_out_of_the_root_is_refused_file_or_directory() {
    let r = rig();
    // a file link, a directory link, a link to a sibling whose name starts
    // like the root's, and a link in the middle of a longer path
    symlink(r.secret.join("key"), r.notes.join("file-link")).unwrap();
    symlink(&r.secret, r.notes.join("dir-link")).unwrap();
    symlink("../notes-secret", r.notes.join("rel-link")).unwrap();
    std::fs::create_dir(r.notes.join("d")).unwrap();
    symlink(&r.secret, r.notes.join("d").join("deep")).unwrap();
    let mut c = member(&r);
    for path in [
        "file-link",
        "dir-link/key",
        "rel-link/key",
        "d/deep/key",
        "rel-link",
    ] {
        let resp = stat(&mut c, path);
        assert!(
            matches!(&resp, Resp::Unavailable { reason } if reason == "outside the root"),
            "{path}: {resp:?}"
        );
        let resp = fetch(&mut c, path, id_of(b"do not serve"));
        assert!(matches!(resp, Resp::Unavailable { .. }), "{path}: {resp:?}");
    }
}

#[test]
fn a_link_that_stays_inside_the_root_is_followed() {
    let r = rig();
    std::fs::write(r.notes.join("real.md"), b"real").unwrap();
    symlink("real.md", r.notes.join("alias.md")).unwrap();
    let mut c = member(&r);
    let Resp::FileId { id } = stat(&mut c, "alias.md") else {
        panic!("alias")
    };
    assert_eq!(id, id_of(b"real"));
}

#[test]
fn only_a_regular_file_is_served() {
    let r = rig();
    std::fs::create_dir(r.notes.join("dir")).unwrap();
    let fifo = r.notes.join("fifo");
    let c_fifo = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
    let mut c = member(&r);
    // the fifo has no writer: opening it for reading must not wait for one
    for path in ["dir", "fifo", "."] {
        assert_eq!(
            unavailable(&stat(&mut c, path)),
            "not a regular file",
            "{path}"
        );
    }
}

#[test]
fn missing_unknown_root_and_unmapped_root_say_so() {
    let r = rig();
    let mut c = member(&r);
    assert_eq!(unavailable(&stat(&mut c, "nope.md")), "missing");
    assert_eq!(unavailable(&stat(&mut c, "a/nope.md")), "missing");
    let other = call(
        &mut c,
        &Req::FileStat {
            root: "elsewhere".into(),
            path: "a.md".into(),
        },
    );
    assert_eq!(unavailable(&other), "unknown root");
}

#[test]
fn a_root_the_roster_declares_but_this_host_does_not_map_is_unknown() {
    let r = rig();
    std::fs::write(r.notes.join("a.md"), b"x").unwrap();
    // the roster keeps `notes`; this host now maps only `other`
    r.serving
        .with_server(|s| s.serve_roots(BTreeMap::from([("other".to_owned(), r.notes.clone())])))
        .unwrap();
    let mut c = member(&r);
    assert_eq!(unavailable(&stat(&mut c, "a.md")), "unknown root");
    let still = r.serving.with_server(|s| s.board().roots().to_vec());
    assert_eq!(still, ["notes".to_owned(), "other".to_owned()]);
}

#[test]
fn the_size_limit_is_one_message() {
    let r = rig();
    let at = vec![7u8; MAX_FILE];
    let over = vec![7u8; MAX_FILE + 1];
    std::fs::write(r.notes.join("at"), &at).unwrap();
    std::fs::write(r.notes.join("over"), &over).unwrap();
    let mut c = member(&r);
    // exactly the limit is served, and its answer fits the message limit
    let Resp::FileId { id } = stat(&mut c, "at") else {
        panic!("at")
    };
    match fetch(&mut c, "at", id) {
        Resp::File { bytes } => assert_eq!(bytes.len(), MAX_FILE),
        other => panic!("{other:?}"),
    }
    assert_eq!(unavailable(&stat(&mut c, "over")), "too large");
    assert_eq!(
        unavailable(&fetch(&mut c, "over", id_of(&over))),
        "too large"
    );
}

#[test]
fn the_log_never_holds_a_path() {
    let r = rig();
    let log = std::fs::read(r.env.log_path()).unwrap();
    let path = r.notes.to_str().unwrap().as_bytes();
    assert!(!log.windows(path.len()).any(|w| w == path));
    // but the name it declared is there, as a roster event
    assert!(log.windows(5).any(|w| w == b"notes"));
}
