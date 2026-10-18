//! The read side of a flock (verify, follow, watch) must be buildable with no
//! writer in its resolved dependencies: `serve` (the server, its sockets and
//! key file) and `emit` (the session's signer). Enforced from cargo's own
//! per-package resolution (`cargo tree -p … --format "{p}|{f}"`), not from
//! `cargo metadata`, which unifies features across the whole workspace (the
//! CLI turns the writer on) and would always see it.

use std::path::Path;
use tests_common::readside::{features, has, ours, present};

fn tree(selection: &[&str]) -> Vec<(String, Vec<String>)> {
    features(
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap(),
        selection,
    )
}

#[test]
fn the_session_crates_read_side_resolves_without_the_writer() {
    let tree = tree(&["-p", "agent-mesh-flock-session", "--no-default-features"]);
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
    let tree = tree(&["-p", "agent-mesh-flock-server", "--no-default-features"]);
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
    let session = tree(&["-p", "agent-mesh-flock-session"]);
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
    let cli = tree(&["-p", "agent-mesh-cli"]);
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
