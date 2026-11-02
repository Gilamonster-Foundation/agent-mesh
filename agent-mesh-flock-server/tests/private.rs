//! Keeping other Unix users off the sockets.
#![cfg(unix)]

use agent_mesh_flock_server::{bind_private, peer_ok, private_dir, uid_allowed};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use tempfile::TempDir;

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn another_uid_is_not_allowed() {
    assert!(uid_allowed(1000, 1000));
    assert!(!uid_allowed(1001, 1000));
    assert!(!uid_allowed(0, 1000));
}

#[test]
fn a_private_dir_is_created_0700_and_a_loose_or_foreign_one_is_refused() {
    let t = TempDir::new().unwrap();
    let d = t.path().join("run");
    private_dir(&d).unwrap();
    assert_eq!(mode(&d), 0o700);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(private_dir(&d).is_err());
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o705)).unwrap();
    assert!(private_dir(&d).is_err());
    // a symlink to a good directory is not a private directory
    let good = t.path().join("good");
    private_dir(&good).unwrap();
    let link = t.path().join("link");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    assert!(private_dir(&link).is_err());
}

#[test]
fn bind_makes_a_0600_socket_replaces_a_stale_one_and_same_user_peers_pass() {
    let t = TempDir::new().unwrap();
    let p = t.path().join("run").join("s.sock");
    let l = bind_private(&p).unwrap();
    assert_eq!(mode(&p), 0o600);
    let c = UnixStream::connect(&p).unwrap();
    let (s, _) = l.accept().unwrap();
    peer_ok(&s).unwrap();
    drop((l, c, s));
    // the file is left behind by a dead server; a new bind takes it over
    bind_private(&p).unwrap();
    // a loose parent refuses the bind
    let loose = t.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(bind_private(&loose.join("s.sock")).is_err());
}
