//! "Changed since cited": the file check, on real files. The three answers,
//! every way a path can try to leave its root, and that nothing is written.
#![cfg(unix)]

use agent_mesh_flock::FileRef;
use agent_mesh_tui::drift::{check, FileState, Roots, MAX_BYTES};
use content_addressable::RawContentId;
use std::os::unix::fs::symlink;
use std::path::Path;

fn cite(root: &str, path: &str, bytes: &[u8]) -> FileRef {
    FileRef {
        root: root.into(),
        path: path.into(),
        id: RawContentId::from_content(bytes),
    }
}

struct World {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    outside: std::path::PathBuf,
    roots: Roots,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("work");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("src/a.rs"), b"fn a() {}").unwrap();
    std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
    let mut roots = Roots::default();
    roots.insert("work", root.clone());
    World {
        _tmp: tmp,
        root,
        outside,
        roots,
    }
}

fn unavailable(s: &FileState) -> &str {
    match s {
        FileState::Unavailable(why) => why,
        other => panic!("expected unavailable, got {other:?}"),
    }
}

#[test]
fn bytes_as_cited_are_the_same() {
    let w = world();
    assert_eq!(
        check(&w.roots, &cite("work", "src/a.rs", b"fn a() {}")),
        FileState::Same
    );
}

#[test]
fn edited_bytes_are_changed_and_say_what_they_are_now() {
    let w = world();
    let cited = cite("work", "src/a.rs", b"fn a() {}");
    std::fs::write(w.root.join("src/a.rs"), b"fn a() { 1 }").unwrap();
    assert_eq!(
        check(&w.roots, &cited),
        FileState::Changed {
            current: RawContentId::from_content(b"fn a() { 1 }")
        }
    );
}

#[test]
fn what_cannot_be_read_is_unavailable_and_says_why() {
    let w = world();
    let unmapped = check(&w.roots, &cite("elsewhere", "src/a.rs", b"fn a() {}"));
    assert_eq!(unavailable(&unmapped), "root not mapped");
    let missing = check(&w.roots, &cite("work", "src/gone.rs", b"x"));
    assert_eq!(unavailable(&missing), "file missing");
    let dir = check(&w.roots, &cite("work", "src", b"x"));
    assert_eq!(unavailable(&dir), "not a regular file");
    let mut gone = Roots::default();
    gone.insert("work", w.root.join("no-such-dir"));
    assert_eq!(
        unavailable(&check(&gone, &cite("work", "src/a.rs", b"x"))),
        "root missing"
    );
}

#[test]
fn a_path_that_leaves_its_root_is_never_read() {
    let w = world();
    let secret = b"secret".as_slice();
    // `..` even when it stays inside, an absolute path even when it points
    // inside, and an empty path: refused before any file is opened
    for path in [
        "../outside/secret.txt",
        "src/../src/a.rs",
        w.root.join("src/a.rs").to_str().unwrap(),
        w.outside.join("secret.txt").to_str().unwrap(),
        "",
    ] {
        let s = check(&w.roots, &cite("work", path, secret));
        assert_eq!(unavailable(&s), "path leaves its root", "{path:?}");
    }
}

#[test]
fn a_symlink_that_leads_out_of_the_root_is_never_followed() {
    let w = world();
    // a file link and a directory link, both inside the root, both leading out
    symlink(w.outside.join("secret.txt"), w.root.join("link.txt")).unwrap();
    symlink(&w.outside, w.root.join("linkdir")).unwrap();
    // even though the cited id is exactly the secret's: it must not match
    for path in ["link.txt", "linkdir/secret.txt"] {
        let s = check(&w.roots, &cite("work", path, b"secret"));
        assert_eq!(unavailable(&s), CROSSES, "{path}");
    }
    // a dangling link is a link too
    symlink(w.root.join("nowhere"), w.root.join("dangling")).unwrap();
    assert_eq!(
        unavailable(&check(&w.roots, &cite("work", "dangling", b"x"))),
        CROSSES
    );
}

const CROSSES: &str = "path leaves its root or crosses a link";

#[test]
fn a_link_that_stays_inside_the_root_is_not_followed_either() {
    let w = world();
    symlink(w.root.join("src/a.rs"), w.root.join("alias.rs")).unwrap();
    symlink("src", w.root.join("srclink")).unwrap();
    for path in ["alias.rs", "srclink/a.rs"] {
        let s = check(&w.roots, &cite("work", path, b"fn a() {}"));
        assert_eq!(unavailable(&s), CROSSES, "{path}");
    }
}

/// A directory on the path becomes a link to outside after the root was
/// opened and before the file is: the case a checked pathname loses. The
/// cited id is the outside file's, so a follow would say `Same`.
#[test]
fn a_directory_swapped_for_a_link_after_the_root_is_open_is_unavailable() {
    let w = world();
    std::fs::create_dir(w.outside.join("src")).unwrap();
    std::fs::write(w.outside.join("src/a.rs"), b"outside bytes").unwrap();
    let f = cite("work", "src/a.rs", b"outside bytes");
    let s = agent_mesh_tui::drift::check_with(&w.roots, &f, &mut || {
        std::fs::rename(w.root.join("src"), w.root.join("src.old")).unwrap();
        symlink(w.outside.join("src"), w.root.join("src")).unwrap();
    });
    assert_eq!(unavailable(&s), CROSSES);
}

/// The mapped root itself (or an ancestor of it) is replaced by a link to
/// elsewhere after it was opened: what is read is still the directory that
/// was opened.
#[test]
fn the_root_swapped_for_a_link_after_it_is_open_still_reads_the_opened_directory() {
    let w = world();
    std::fs::create_dir_all(w.outside.join("src")).unwrap();
    std::fs::write(w.outside.join("src/a.rs"), b"outside bytes").unwrap();
    let f = cite("work", "src/a.rs", b"outside bytes");
    let s = agent_mesh_tui::drift::check_with(&w.roots, &f, &mut || {
        let moved = w.root.with_file_name("work.old");
        std::fs::rename(&w.root, moved).unwrap();
        symlink(&w.outside, &w.root).unwrap();
    });
    assert_eq!(
        s,
        FileState::Changed {
            current: RawContentId::from_content(b"fn a() {}")
        }
    );
}

#[test]
fn a_fifo_is_not_opened_for_reading_and_a_huge_file_is_not_hashed() {
    let w = world();
    let fifo = w.root.join("pipe");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    // a blocking open would hang here: the test finishing is the proof
    assert_eq!(
        unavailable(&check(&w.roots, &cite("work", "pipe", b"x"))),
        "not a regular file"
    );
    let big = w.root.join("big");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(MAX_BYTES + 1)
        .unwrap();
    assert_eq!(
        unavailable(&check(&w.roots, &cite("work", "big", b"x"))),
        "file too big to check"
    );
}

fn listing(dir: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
    let mut v: Vec<_> = walk(dir);
    v.sort();
    v
}

fn walk(dir: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
    let mut out = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let m = std::fs::symlink_metadata(e.path()).unwrap();
        out.push((
            e.path().display().to_string(),
            m.len(),
            m.modified().unwrap(),
        ));
        if m.is_dir() {
            out.extend(walk(&e.path()));
        }
    }
    out
}

#[test]
fn checking_writes_nothing_creates_nothing_and_touches_nothing() {
    let w = world();
    symlink(w.outside.join("secret.txt"), w.root.join("link.txt")).unwrap();
    let before = (listing(&w.root), listing(&w.outside));
    for (path, bytes) in [
        ("src/a.rs", b"fn a() {}".as_slice()),
        ("src/a.rs", b"other"),
        ("src/never-made.rs", b"x"),
        ("link.txt", b"secret"),
        ("../outside/secret.txt", b"secret"),
    ] {
        let _ = check(&w.roots, &cite("work", path, bytes));
    }
    assert_eq!((listing(&w.root), listing(&w.outside)), before);
}

#[test]
fn a_root_spec_is_name_equals_path() {
    assert_eq!(
        Roots::parse("work=/a/b=c").unwrap(),
        ("work".to_owned(), "/a/b=c".into())
    );
    for bad in ["work", "=x", "work="] {
        assert!(Roots::parse(bad).is_err(), "{bad}");
    }
}
