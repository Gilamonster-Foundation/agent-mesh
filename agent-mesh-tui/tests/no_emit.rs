//! The TUI is read-only, and that is enforced, not claimed.
//!
//! - resolution: cargo's own per-package resolution for `-p agent-mesh-tui`
//!   enables neither the server's `serve` nor the session's `emit`;
//! - API: a scratch crate that depends on this crate and on the flock crates
//!   without the writer cannot name any writer API (signing, requests that
//!   change the log). If this crate ever enabled a writer feature, cargo would
//!   unify it into that scratch crate and the lines would resolve: red.
//!
//! The helpers are shared with the session crate's own proofs.
#![cfg(unix)]

use std::path::Path;
use tests_common::readside::{assert_no_writer_apis, features, has, ours, present};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

#[test]
fn the_tuis_normal_closure_has_no_writer_feature() {
    let tree = features(root(), &["-p", "agent-mesh-tui"]);
    assert!(
        present(&tree, "agent-mesh-flock-server"),
        "{:?}",
        ours(&tree)
    );
    assert!(
        present(&tree, "agent-mesh-flock-session"),
        "{:?}",
        ours(&tree)
    );
    assert!(
        !has(&tree, "agent-mesh-flock-server", "serve"),
        "{:?}",
        ours(&tree)
    );
    assert!(
        !has(&tree, "agent-mesh-flock-session", "emit"),
        "{:?}",
        ours(&tree)
    );
}

#[test]
fn a_consumer_of_the_tui_cannot_name_a_writer_api() {
    assert_no_writer_apis(
        root(),
        &[("agent-mesh-tui", Path::new(env!("CARGO_MANIFEST_DIR")))],
    );
}
