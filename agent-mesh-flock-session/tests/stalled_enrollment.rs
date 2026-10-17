//! The seed must be in locked memory while enrollment waits on the server.
//! One test per file: `VmLck` is per process.
#![cfg(target_os = "linux")]

use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_session::{Policy, Session};
use content_addressable::ContentId;
use std::os::unix::net::UnixListener;
use tempfile::TempDir;

fn vm_lck_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmLck:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap()
}

#[test]
fn a_session_waiting_for_its_challenge_already_holds_its_seed_in_locked_memory() {
    let tmp = TempDir::new().unwrap();
    let sock = tmp.path().join("s.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    assert_eq!(vm_lck_kb(), 0, "fixture: nothing locked yet");
    let client = std::thread::spawn({
        let sock = sock.clone();
        move || Session::enroll(&sock, "token", "shep", Policy::Locked).map(|_| ())
    });
    let (mut conn, _) = listener.accept().unwrap();
    let flock = ContentId::from_canonical_bytes(b"f");
    assert!(matches!(read_msg(&mut conn).unwrap(), Some(Req::Hello)));
    write_msg(&mut conn, &Resp::Hello { flock, epoch: 0 }).unwrap();
    // EnrollBegin has arrived: the client holds a generated key and now waits
    // on us. We never answer.
    assert!(matches!(
        read_msg(&mut conn).unwrap(),
        Some(Req::EnrollBegin { .. })
    ));
    assert!(vm_lck_kb() > 0, "the seed waited on the network unlocked");
    drop(conn); // let the client fail and finish
    assert!(client.join().unwrap().is_err());
}
