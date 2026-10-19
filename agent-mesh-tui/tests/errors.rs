//! The final error report is text too: it can carry a reason a session or
//! server supplied, or a path the operator was handed. Whatever the binary
//! prints on failure must reach the terminal as inert text, before the
//! terminal is even initialised and in both modes.
#![cfg(unix)]

mod support;

use agent_mesh_flock_server::wire::{read_msg, write_msg};
use agent_mesh_flock_session::{CtlReq, CtlResp};
use std::os::unix::net::UnixListener;
use std::process::{Command, Output};
use support::Fixture;

/// OSC 52 + BEL, a carriage return, a tab and U+009B.
const PAYLOAD: &str = "A\x1b]52;c;Y2xpcGJvYXJk\x07B\rC\tD\u{9b}31mE";

fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_amesh-tui"))
        .args(args)
        .env_remove("AMESH_FLOCK_SESSION")
        .output()
        .unwrap()
}

/// Nothing a terminal would act on, and the escaped spelling is there.
fn assert_inert(out: &Output, spelled: &str) {
    assert!(!out.status.success());
    let err = &out.stderr;
    for b in [0x1b, 0x07, 0x0d] {
        assert!(
            !err.contains(&b),
            "byte {b:#x} in stderr: {:?}",
            String::from_utf8_lossy(err)
        );
    }
    assert!(
        !err.windows(2).any(|w| w == [0xc2, 0x9b]),
        "a C1 CSI reached stderr"
    );
    let text = String::from_utf8_lossy(err);
    assert!(text.contains(spelled), "{spelled} not in:\n{text}");
}

#[test]
fn a_session_that_answers_with_terminal_commands_is_reported_inert_in_both_modes() {
    let f = Fixture::new();
    let sock = f.path().join("run").join("mock.sock");
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&sock).unwrap();
    // a private mock session: whatever it is asked, it answers with the payload
    let serving = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut conn, _) = listener.accept().unwrap();
            let _: Option<CtlReq> = read_msg(&mut conn).unwrap();
            write_msg(&mut conn, &CtlResp::Err(PAYLOAD.into())).unwrap();
        }
    });
    for once in [true, false] {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "--dir".as_ref(),
            f.path().as_os_str(),
            "--session".as_ref(),
            sock.as_os_str(),
        ];
        if once {
            args.push("--once".as_ref());
        }
        assert_inert(&run(&args), "\\x1b]52;c;Y2xpcGJvYXJk\\x07");
    }
    serving.join().unwrap();
}

#[test]
fn a_directory_name_with_terminal_commands_is_reported_inert_in_both_modes() {
    let outside = tempfile::tempdir().unwrap();
    let dir = outside.path().join(format!("gone{PAYLOAD}"));
    let sock = outside.path().join("s.sock");
    for once in [true, false] {
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "--dir".as_ref(),
            dir.as_os_str(),
            "--session".as_ref(),
            sock.as_os_str(),
        ];
        if once {
            args.push("--once".as_ref());
        }
        assert_inert(&run(&args), "\\x1b]52;c;Y2xpcGJvYXJk\\x07");
    }
}
