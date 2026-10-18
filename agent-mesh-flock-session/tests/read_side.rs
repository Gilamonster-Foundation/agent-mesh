//! The read side of a flock (verify, follow, watch) must be buildable with no
//! writer in its resolved dependencies: `serve` (the server, its sockets and
//! key file) and `emit` (the session's signer). Enforced from cargo's own
//! per-package resolution (`cargo tree -p … --format "{p}|{f}"`), not from
//! `cargo metadata`, which unifies features across the whole workspace (the
//! CLI turns the writer on) and would always see it.

use std::path::Path;
use std::process::Command;

/// `package -> enabled features`, one entry per node of `cargo tree`'s normal
/// (non-dev) closure for the selected package.
fn features(selection: &[&str]) -> Vec<(String, Vec<String>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let out = Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["tree", "--locked", "-e", "normal", "--prefix", "none"])
        .args(["--format", "{p}|{f}"])
        .args(selection)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| {
            let (pkg, feats) = l.split_once('|')?;
            let feats = feats.trim_end_matches(" (*)");
            Some((
                pkg.split_whitespace().next()?.to_owned(),
                feats
                    .split(',')
                    .filter(|f| !f.is_empty())
                    .map(str::to_owned)
                    .collect(),
            ))
        })
        .collect()
}

fn has(tree: &[(String, Vec<String>)], package: &str, feature: &str) -> bool {
    tree.iter()
        .any(|(p, f)| p == package && f.iter().any(|x| x == feature))
}

/// Just the flock crates, for messages a person can read.
fn ours(tree: &[(String, Vec<String>)]) -> Vec<&(String, Vec<String>)> {
    tree.iter()
        .filter(|(p, _)| p.starts_with("agent-mesh-flock"))
        .collect()
}

fn present(tree: &[(String, Vec<String>)], package: &str) -> bool {
    tree.iter().any(|(p, _)| p == package)
}

#[test]
fn the_session_crates_read_side_resolves_without_the_writer() {
    let tree = features(&["-p", "agent-mesh-flock-session", "--no-default-features"]);
    assert!(
        present(&tree, "agent-mesh-flock-server"),
        "{:?}",
        ours(&tree)
    );
    assert!(
        !has(&tree, "agent-mesh-flock-server", "serve"),
        "the server's writer is in the read side's closure: {:?}",
        ours(&tree)
    );
    assert!(
        !has(&tree, "agent-mesh-flock-session", "emit"),
        "{:?}",
        ours(&tree)
    );
}

#[test]
fn the_server_crates_read_side_resolves_without_the_writer() {
    let tree = features(&["-p", "agent-mesh-flock-server", "--no-default-features"]);
    assert!(
        !has(&tree, "agent-mesh-flock-server", "serve"),
        "{:?}",
        ours(&tree)
    );
}

#[test]
fn the_check_can_see_the_writer_when_it_is_on() {
    // positive controls: the same query reports the features when they are on,
    // so the two tests above are not passing because the query sees nothing
    let session = features(&["-p", "agent-mesh-flock-session"]);
    assert!(
        has(&session, "agent-mesh-flock-session", "emit"),
        "{:?}",
        ours(&session)
    );
    assert!(
        has(&session, "agent-mesh-flock-server", "serve"),
        "{:?}",
        ours(&session)
    );
    let cli = features(&["-p", "agent-mesh-cli"]);
    assert!(
        has(&cli, "agent-mesh-flock-server", "serve"),
        "{:?}",
        ours(&cli)
    );
    // the CLI's flock-session dependency is cfg(unix): no session crate on Windows
    #[cfg(unix)]
    assert!(
        has(&cli, "agent-mesh-flock-session", "emit"),
        "{:?}",
        ours(&cli)
    );
}
