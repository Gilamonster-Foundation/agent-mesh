//! Another Unix user can't use the sockets. Needs root to become that user,
//! so both tests are `#[ignore]`d; CI runs this binary under `sudo --ignored`.
#![cfg(unix)]

use agent_mesh_flock::{Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{bind_private, init, serve, InitSpec, Server};
use agent_mesh_protocol::UserKey;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use tempfile::TempDir;

const NOBODY: u32 = 65534;
const SOCK: &str = "AMESH_TEST_OTHER_USER_SOCK";

/// Runs as the other user: try the socket and say what happened.
#[test]
#[ignore = "run by other_user_cannot_use_the_socket"]
fn child_connects() {
    let Ok(sock) = std::env::var(SOCK) else {
        return;
    };
    let out = match UnixStream::connect(&sock) {
        Err(e) => format!("DENIED {:?}", e.kind()),
        Ok(mut c) => {
            let _ = write_msg(&mut c, &Req::Hello);
            match read_msg::<Resp>(&mut c) {
                Ok(Some(_)) => "SERVED".to_owned(),
                _ => "DROPPED".to_owned(),
            }
        }
    };
    println!("RESULT {out}");
}

/// The test binary, staged where the other user can execute it: the
/// checkout and its `target/` may sit under a home only the owner can enter.
fn stage_binary(into: &std::path::Path) -> std::path::PathBuf {
    std::fs::set_permissions(into, std::fs::Permissions::from_mode(0o755)).unwrap();
    let staged = into.join("other_user_test");
    std::fs::copy(std::env::current_exe().unwrap(), &staged).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
    staged
}

fn other_user(exe: &std::path::Path, sock: &std::path::Path) -> String {
    let out = Command::new(exe)
        .args(["--ignored", "--exact", "child_connects", "--nocapture"])
        .env(SOCK, sock)
        .uid(NOBODY)
        .gid(NOBODY)
        .output()
        .expect("the test binary must be runnable by the other user");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("RESULT ").map(str::to_owned))
        .unwrap_or_else(|| panic!("child said nothing: {out:?}"))
}

#[test]
#[ignore = "needs root: run under sudo with --ignored"]
fn other_user_cannot_use_the_socket() {
    // SAFETY: geteuid has no preconditions.
    assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
    let tmp = TempDir::new().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = TempDir::new().unwrap();
    let exe = stage_binary(bin.path());
    let spec = InitSpec {
        name: "f".into(),
        roster: vec![Member {
            name: "shep".into(),
            role: Role::Shepherd,
            devices: vec![],
        }],
        salt: "00".into(),
        host: "h".into(),
        issued_at: "t".into(),
    };
    init(tmp.path(), &UserKey::generate(), spec).unwrap();
    let sock = tmp.path().join("run").join("serve.sock");
    let serving = serve(
        Server::open(tmp.path()).unwrap(),
        bind_private(&sock).unwrap(),
    )
    .unwrap();

    // the directory keeps the other user out
    assert_eq!(other_user(&exe, &sock), "DENIED PermissionDenied");

    // even with the directory and the socket opened up, the server drops
    // the connection after reading the peer's uid
    std::fs::set_permissions(
        sock.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(other_user(&exe, &sock), "DROPPED");

    serving.stop();
}
