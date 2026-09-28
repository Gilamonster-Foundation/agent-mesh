//! Regression for agent-mesh PR #101 review round 2, P2: a bare relative
//! destination (a filename with no directory component) failed to reserve
//! on Unix. `Path::parent()` returns `Some("")` for those, not `None`
//! (<https://doc.rust-lang.org/std/path/struct.Path.html#method.parent>),
//! and the staging-directory computation only substituted `.` for a
//! *missing* parent, not an *empty* one, so `File::open("")` failed after
//! the rename had already succeeded.
//!
//! This is a dedicated integration-test binary, not a `#[test]` alongside
//! `sequence.rs`'s other tests, because it must `chdir` — process-global
//! state — into a scratch directory. Cargo gives each integration-test
//! file its own process, so this can't race another test's cwd.

#[cfg(unix)]
use agent_mesh_bus::sequence::{FileSequenceReservations, SequenceReservations};

#[test]
#[cfg(unix)]
fn a_bare_relative_destination_reserves_through_the_real_sync_path() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let store = FileSequenceReservations::new("agent.seq");
    store.reserve(1024).unwrap();
    assert_eq!(store.reserved().unwrap(), 1024);
}
