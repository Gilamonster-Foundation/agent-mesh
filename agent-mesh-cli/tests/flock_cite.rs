//! `amesh flock brief|review --cite root:path`: the CLI hashes a file under a
//! declared, locally mapped root and the event carries it; the TUI's own check
//! then calls it the same until the file is edited.
#![cfg(unix)]

mod harness;
use agent_mesh_flock::Kind;
use agent_mesh_flock_server::Snapshot;
use agent_mesh_tui::drift::{check, FileState, Roots};
use content_addressable::RawContentId;
use harness::*;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Stdio;
use tempfile::TempDir;

/// A served flock whose roster declares the root `notes` (mapped to `files`).
fn rooted(files: &Path) -> Flock {
    let home = TempDir::new().unwrap();
    assert!(amesh(home.path()).arg("keygen").status().unwrap().success());
    let mut init = amesh(home.path());
    init.args(["flock", "init", "--name", "f"]);
    for m in ["shep:shepherd", "h1:helper", "rev:reviewer"] {
        init.args(["--member", m]);
    }
    assert!(init.stdout(Stdio::null()).status().unwrap().success());
    let dir = home.path().join("flocks").join("f");
    let mut serve = amesh(home.path())
        .args(["flock", "serve", "--dir"])
        .arg(&dir)
        .arg("--root")
        .arg(format!("notes={}", files.display()))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(serve.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.starts_with("serving"), "{line}");
    Flock {
        home,
        dir,
        _serve: Proc(serve),
    }
}

fn cited(f: &Flock) -> Vec<agent_mesh_flock::FileRef> {
    Snapshot::read(&f.dir)
        .unwrap()
        .board()
        .entries()
        .filter(|e| matches!(e.event.kind, Kind::Brief | Kind::Review))
        .flat_map(|e| e.event.files.clone())
        .collect()
}

fn roots(dir: &Path) -> Roots {
    let mut r = Roots::default();
    r.insert("notes", dir.to_owned());
    r
}

fn map(dir: &Path) -> String {
    format!("notes={}", dir.display())
}

#[test]
fn a_cited_brief_carries_the_file_and_the_tui_calls_it_unchanged_until_it_is_edited() {
    let files = TempDir::new().unwrap();
    std::fs::write(files.path().join("lane.md"), b"the lane file").unwrap();
    let f = rooted(files.path());
    let shep = f.session("shep");
    let out = f.run(
        Some(&shep),
        &[
            "brief",
            "--to",
            "h1",
            "--lane",
            "l1",
            "--cite",
            "notes:lane.md",
            "--root",
            &map(files.path()),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let c = cited(&f);
    assert_eq!(c.len(), 1);
    assert_eq!(
        (c[0].root.as_str(), c[0].path.as_str()),
        ("notes", "lane.md")
    );
    assert_eq!(c[0].id, RawContentId::from_content(b"the lane file"));

    // the TUI's check: ✓ now, ⚠ after an edit
    assert_eq!(check(&roots(files.path()), &c[0]), FileState::Same);
    std::fs::write(files.path().join("lane.md"), b"edited").unwrap();
    assert!(matches!(
        check(&roots(files.path()), &c[0]),
        FileState::Changed { .. }
    ));
}

#[test]
fn a_review_cites_files_too_and_a_repeated_cite_is_carried_once() {
    let files = TempDir::new().unwrap();
    std::fs::write(files.path().join("a.md"), b"a").unwrap();
    std::fs::create_dir(files.path().join("sub")).unwrap();
    std::fs::write(files.path().join("sub").join("b.md"), b"b").unwrap();
    let f = rooted(files.path());
    let shep = f.session("shep");
    let out = f.run(
        Some(&shep),
        &[
            "review",
            "--to",
            "rev",
            "--lane",
            "l1",
            "--head",
            "abc",
            "--cite",
            "notes:a.md",
            "--cite",
            "notes:sub/b.md",
            "--cite",
            "notes:a.md",
            "--root",
            &map(files.path()),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let c = cited(&f);
    let paths: Vec<_> = c.iter().map(|x| x.path.as_str()).collect();
    assert_eq!(paths, ["a.md", "sub/b.md"]);
}

#[test]
fn a_bad_cite_is_refused_before_anything_is_sent() {
    let files = TempDir::new().unwrap();
    std::fs::write(files.path().join("ok.md"), b"ok").unwrap();
    std::fs::create_dir(files.path().join("dir")).unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret"), b"s").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret"), files.path().join("out-link"))
        .unwrap();
    std::os::unix::fs::symlink(files.path().join("ok.md"), files.path().join("in-link")).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(files.path().join("pipe"))
        .status()
        .unwrap()
        .success());
    // one byte over the limit, sparse (no disk is written)
    let big = std::fs::File::create(files.path().join("big")).unwrap();
    big.set_len(agent_mesh_flock_server::MAX_CITED_BYTES + 1)
        .unwrap();
    let f = rooted(files.path());
    let shep = f.session("shep");
    let before = f.log(&shep);
    let m = map(files.path());
    let other = TempDir::new().unwrap();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec!["--cite", "zzz:ok.md", "--root", "zzz=/tmp"],
            "does not declare",
        ),
        (vec!["--cite", "notes:ok.md"], "not mapped"),
        (vec!["--cite", "notes"], "root:path"),
        (
            vec!["--cite", "notes:../x", "--root", &m],
            "leaves its root",
        ),
        (
            vec!["--cite", "notes:/etc/hostname", "--root", &m],
            "leaves its root",
        ),
        (vec!["--cite", "notes:out-link", "--root", &m], "link"),
        (vec!["--cite", "notes:in-link", "--root", &m], "link"),
        (
            vec!["--cite", "notes:missing.md", "--root", &m],
            "no such file",
        ),
        (
            vec!["--cite", "notes:dir", "--root", &m],
            "not a regular file",
        ),
        (
            vec!["--cite", "notes:pipe", "--root", &m],
            "not a regular file",
        ),
        // one bad cite among good ones sends nothing
        (
            vec![
                "--cite",
                "notes:ok.md",
                "--cite",
                "notes:missing.md",
                "--root",
                &m,
            ],
            "no such file",
        ),
    ];
    for (extra, why) in cases {
        let mut args = vec!["brief", "--to", "h1", "--lane", "l1"];
        args.extend(&extra);
        let o = f.run(Some(&shep), &args);
        assert!(!o.status.success(), "{extra:?} was accepted");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains(why), "{extra:?}: wanted {why:?}, got {err}");
        assert_eq!(f.log(&shep), before, "{extra:?} reached the log");
    }
    drop(other);
}

#[test]
fn a_brief_without_a_cite_still_carries_no_files() {
    let files = TempDir::new().unwrap();
    let f = rooted(files.path());
    let shep = f.session("shep");
    f.emit(&shep, &["brief", "--to", "h1", "--lane", "l1"]);
    assert!(cited(&f).is_empty());
}
