//! With `mlock` denied, enrollment fails before any secret exists or any
//! byte goes to the server. One test per file: the rlimit is per process.
#![cfg(target_os = "linux")]

use agent_mesh_flock_session::{Policy, Session, SessionError};
use rustix::process::{getrlimit, setrlimit, Resource};
use std::os::unix::net::UnixListener;
use tempfile::TempDir;

#[test]
fn a_denied_lock_stops_enrollment_before_it_connects() {
    let tmp = TempDir::new().unwrap();
    let sock = tmp.path().join("s.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut lim = getrlimit(Resource::Memlock);
    lim.current = Some(0);
    setrlimit(Resource::Memlock, lim).unwrap();

    let err = match Session::enroll(&sock, "token", "shep", Policy::Locked) {
        Err(e) => e,
        Ok(_) => panic!("enrolled with unlockable memory"),
    };
    assert!(matches!(err, SessionError::Unprotected(_)), "{err}");
    let accepted = listener.accept();
    assert_eq!(
        accepted.unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "the client connected to the server before it could protect its key"
    );
}
