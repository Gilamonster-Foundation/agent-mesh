//! The attach socket: what a remote host's bridge may ask of the server, and
//! nothing else. Every entry is tried on it, so a request added later without
//! a decision shows up here.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{bind_private, serve, serve_with_attach, Serving};
use agent_mesh_protocol::agent_key::PossessionChallenge;
use agent_mesh_protocol::{AgentKey, Assertion, CertChain};
use content_addressable::{ContentAddressable as _, ContentId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rand::rngs::OsRng;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use support::Env;

const NOT_OFFERED: &str = "not offered on the attach socket";

struct Rig {
    env: Env,
    serving: Option<Serving>,
    owner: PathBuf,
    attach: PathBuf,
}

fn rig() -> Rig {
    let env = Env::new();
    let dir = env.tmp.path().join("run");
    let (owner, attach) = (dir.join("serve.sock"), dir.join("attach.sock"));
    let serving = serve_with_attach(
        env.open(),
        bind_private(&owner).unwrap(),
        bind_private(&attach).unwrap(),
    )
    .unwrap();
    Rig {
        env,
        serving: Some(serving),
        owner,
        attach,
    }
}

fn ask(sock: &PathBuf, req: &Req) -> Resp {
    let mut c = UnixStream::connect(sock).unwrap();
    write_msg(&mut c, req).unwrap();
    read_msg::<Resp>(&mut c).unwrap().expect("an answer")
}

fn refused_as_not_offered(r: &Resp) -> bool {
    matches!(r, Resp::Err(why) if why.contains(NOT_OFFERED))
}

fn a_cert() -> CertChain {
    let user = agent_mesh_protocol::UserKey::generate();
    AgentKey::issue(&user, support::meta("x")).cert().clone()
}

fn a_challenge() -> PossessionChallenge {
    PossessionChallenge {
        issuer_pubkey: [1; 32],
        subject_pubkey: [2; 32],
        nonce: [3; 32],
    }
}

fn a_proof() -> Signature {
    Signature::from_bytes(&[4; 64])
}

fn an_event(env: &mut Env) -> Req {
    let key = env.server_key();
    let (node, sig) = env.event(
        &key,
        Kind::Brief,
        None,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "x".into(),
        },
    );
    Req::Admit { node, sig }
}

#[test]
fn the_attach_socket_is_private_to_its_owner() {
    let r = rig();
    let mode = std::fs::metadata(&r.attach).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let dir = std::fs::metadata(r.attach.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(dir & 0o077, 0, "nobody else can enter its directory");
}

#[test]
fn minting_an_invite_is_the_owners_alone() {
    let r = rig();
    let invite = || Req::Invite {
        member: "shep".into(),
    };
    assert!(matches!(ask(&r.owner, &invite()), Resp::Invited { .. }));
    let refused = ask(&r.attach, &invite());
    assert!(refused_as_not_offered(&refused), "{refused:?}");
}

#[test]
fn genesis_is_served_on_both_and_hashes_to_the_flock_id() {
    let r = rig();
    let Resp::Hello { flock, .. } = ask(&r.attach, &Req::Hello) else {
        panic!("hello")
    };
    for sock in [&r.attach, &r.owner] {
        let Resp::Genesis(g) = ask(sock, &Req::Genesis) else {
            panic!("genesis on {}", sock.display())
        };
        assert_eq!(g.node.content_id().unwrap(), flock);
        assert_eq!(g.node.content_id().unwrap(), r.env.flock);
    }
}

/// Every request the remote class offers reaches its handler: whatever it
/// answers, it is not "not offered". One assertion per entry, so a removal
/// names the entry.
#[test]
fn each_entry_a_remote_session_needs_is_offered_on_the_attach_socket() {
    let mut r = rig();
    let cases: Vec<(&str, Req)> = vec![
        ("hello", Req::Hello),
        ("genesis", Req::Genesis),
        (
            "enroll-begin",
            Req::EnrollBegin {
                token: "nope".into(),
                member: "shep".into(),
                pubkey: [9; 32],
            },
        ),
        (
            "enroll-finish",
            Req::EnrollFinish {
                challenge: a_challenge(),
                proof: a_proof(),
            },
        ),
        ("renew", Req::Renew { last: a_cert() }),
        (
            "renew-finish",
            Req::RenewFinish {
                challenge: a_challenge(),
                proof: a_proof(),
            },
        ),
        (
            "head",
            Req::Head {
                session: "x".into(),
            },
        ),
        ("admit", an_event(&mut r.env)),
        ("watch-begin", Req::WatchBegin),
        (
            "prove",
            Req::Prove {
                proof: Box::new(Assertion::sign(
                    &AgentKey::issue(
                        &agent_mesh_protocol::UserKey::generate(),
                        support::meta("x"),
                    ),
                    &ContentId::from_canonical_bytes(b"x"),
                )),
            },
        ),
        (
            "file-stat",
            Req::FileStat {
                root: "notes".into(),
                path: "a".into(),
            },
        ),
        (
            "file",
            Req::File {
                root: "notes".into(),
                path: "a".into(),
                id: content_addressable::RawContentId::from_content(b"x"),
            },
        ),
        ("end", Req::End),
    ];
    for (name, req) in cases {
        let got = ask(&r.attach, &req);
        assert!(
            !refused_as_not_offered(&got),
            "{name} must be offered: {got:?}"
        );
    }
    // `watch` needs a challenge first; on its own connection it still reaches
    // its handler
    let mut c = UnixStream::connect(&r.attach).unwrap();
    write_msg(
        &mut c,
        &Req::Watch {
            from: None,
            proof: Box::new(Assertion::sign(
                &AgentKey::issue(
                    &agent_mesh_protocol::UserKey::generate(),
                    support::meta("x"),
                ),
                &ContentId::from_canonical_bytes(b"x"),
            )),
        },
    )
    .unwrap();
    let got = read_msg::<Resp>(&mut c).unwrap().unwrap();
    assert!(
        !refused_as_not_offered(&got),
        "watch must be offered: {got:?}"
    );
}

#[test]
fn a_remote_session_enrolls_emits_and_proves_a_stream_through_the_attach_socket() {
    use agent_mesh_flock_server::wire::StreamChallenge;
    let mut r = rig();
    let Resp::Invited { token } = ask(
        &r.owner,
        &Req::Invite {
            member: "shep".into(),
        },
    ) else {
        panic!("invite")
    };
    // the key is made on this side of the socket and never leaves it
    let sk = SigningKey::generate(&mut OsRng);
    let mut conn = UnixStream::connect(&r.attach).unwrap();
    write_msg(
        &mut conn,
        &Req::EnrollBegin {
            token,
            member: "shep".into(),
            pubkey: sk.verifying_key().to_bytes(),
        },
    )
    .unwrap();
    let Some(Resp::Challenge(ch)) = read_msg::<Resp>(&mut conn).unwrap() else {
        panic!("challenge")
    };
    write_msg(
        &mut conn,
        &Req::EnrollFinish {
            proof: sk.sign(&ch.signing_bytes()),
            challenge: ch,
        },
    )
    .unwrap();
    let Some(Resp::Enrolled { cert, .. }) = read_msg::<Resp>(&mut conn).unwrap() else {
        panic!("enrolled")
    };
    let key = AgentKey::from_seed_and_cert(&sk.to_bytes(), cert).unwrap();
    // the session's event, admitted on the connection it enrolled on
    let (node, sig) = r.env.event(
        &key,
        Kind::Brief,
        None,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "l1".into(),
        },
    );
    write_msg(&mut conn, &Req::Admit { node, sig }).unwrap();
    assert!(matches!(
        read_msg::<Resp>(&mut conn).unwrap(),
        Some(Resp::Admitted { .. })
    ));
    // and it can prove a stream: a fresh challenge, signed by the session key
    let mut w = UnixStream::connect(&r.attach).unwrap();
    write_msg(&mut w, &Req::WatchBegin).unwrap();
    let Some(Resp::StreamChallenge(sc)) = read_msg::<Resp>(&mut w).unwrap() else {
        panic!("stream challenge")
    };
    let proof = Assertion::sign(&key, &StreamChallenge::id(&sc).unwrap());
    write_msg(
        &mut w,
        &Req::Watch {
            from: None,
            proof: Box::new(proof),
        },
    )
    .unwrap();
    assert!(matches!(
        read_msg::<Resp>(&mut w).unwrap(),
        Some(Resp::Frame(_))
    ));
}

#[test]
fn stopping_ends_both_sockets_and_frees_the_log() {
    let mut r = rig();
    let serving = r.serving.take().unwrap();
    // an open connection on each surface
    let _o = UnixStream::connect(&r.owner).unwrap();
    let _a = UnixStream::connect(&r.attach).unwrap();
    serving.stop();
    // the log's lock is free again
    drop(r.env.open());
}

#[test]
fn serve_without_attach_has_no_attach_socket_to_reach() {
    let env = Env::new();
    let sock = env.tmp.path().join("run").join("serve.sock");
    let s = serve(env.open(), bind_private(&sock).unwrap()).unwrap();
    assert!(!env.tmp.path().join("run").join("attach.sock").exists());
    s.stop();
}

#[test]
fn a_client_that_half_closes_sees_the_server_close_its_end() {
    // The server keeps a duplicate of each connection so `stop` can cut it, so
    // simply dropping its handle did not close the socket: a client that had
    // finished writing waited for an end that never came. (A bridge holds a
    // place for such a connection; it must be able to see it end.)
    use std::os::unix::net::UnixStream;
    let r = rig();
    for sock in [&r.owner, &r.attach] {
        let mut c = UnixStream::connect(sock).unwrap();
        write_msg(&mut c, &Req::Hello).unwrap();
        assert!(matches!(
            read_msg::<Resp>(&mut c),
            Ok(Some(Resp::Hello { .. }))
        ));
        c.shutdown(std::net::Shutdown::Write).unwrap();
        // the server's side is closed: a clean end of stream, not a hang (the
        // timeout only turns a server that never closes into a failure)
        c.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        // print what the read gave: a platform's end-of-stream differs
        let end = read_msg::<Resp>(&mut c);
        assert!(matches!(end, Ok(None)), "{sock:?}: read gave {end:?}");
    }
}

#[test]
fn a_watch_that_disconnects_ends_its_worker_with_nothing_published() {
    use agent_mesh_flock_server::wire::StreamChallenge;
    // A member session stays alive; a reader opens a watch, catches up and
    // goes away, over and over, with no new record and no server stop. Each
    // time the server must end the worker that was waiting for the next frame
    // (the count of running connection threads is the proof; a place in a
    // bridge's gate is not).
    let r = rig();
    let serving = r.serving.as_ref().unwrap();
    let Resp::Invited { token } = ask(
        &r.owner,
        &Req::Invite {
            member: "shep".into(),
        },
    ) else {
        panic!("invite")
    };
    let sk = SigningKey::generate(&mut OsRng);
    let mut conn = UnixStream::connect(&r.attach).unwrap();
    write_msg(
        &mut conn,
        &Req::EnrollBegin {
            token,
            member: "shep".into(),
            pubkey: sk.verifying_key().to_bytes(),
        },
    )
    .unwrap();
    let Some(Resp::Challenge(ch)) = read_msg::<Resp>(&mut conn).unwrap() else {
        panic!("challenge")
    };
    write_msg(
        &mut conn,
        &Req::EnrollFinish {
            proof: sk.sign(&ch.signing_bytes()),
            challenge: ch,
        },
    )
    .unwrap();
    let Some(Resp::Enrolled { cert, .. }) = read_msg::<Resp>(&mut conn).unwrap() else {
        panic!("enrolled")
    };
    let key = AgentKey::from_seed_and_cert(&sk.to_bytes(), cert).unwrap();
    // the enrolling connection is the one live worker
    let baseline = serving.live_connections();
    assert_eq!(baseline, 1);
    for _ in 0..8 {
        let mut w = UnixStream::connect(&r.attach).unwrap();
        write_msg(&mut w, &Req::WatchBegin).unwrap();
        let Some(Resp::StreamChallenge(sc)) = read_msg::<Resp>(&mut w).unwrap() else {
            panic!("stream challenge")
        };
        let proof = Assertion::sign(&key, &StreamChallenge::id(&sc).unwrap());
        write_msg(
            &mut w,
            &Req::Watch {
                from: None,
                proof: Box::new(proof),
            },
        )
        .unwrap();
        // through the replay to Caught: the worker now waits for news
        while !matches!(read_msg::<Resp>(&mut w).unwrap(), Some(Resp::Caught { .. })) {}
        assert_eq!(serving.live_connections(), baseline + 1);
        drop(w);
        serving.wait_connections_at_most(baseline);
    }
    drop(conn);
}

/// #165: on macOS this hung about a third of the time while `stop` woke an
/// accept loop by connecting and closing at once (the kernel drops a queued
/// connection whose peer has gone, so the loop slept on). `stop` now keeps the
/// wake open until the loop ends; looped 100 times on macOS, no hang.
///
/// Stopping needs no new descriptor for a connection it already holds. The
/// limit is lowered in a child process (the test re-runs itself), so the
/// rest of the suite keeps its descriptors.
#[test]
fn stop_with_no_spare_descriptors_still_ends_every_connection() {
    const CHILD: &str = "AMESH_STOP_FD_CHILD";
    const NAME: &str = "stop_with_no_spare_descriptors_still_ends_every_connection";
    if std::env::var_os(CHILD).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let mut r = rig();
    let serving = r.serving.take().unwrap();
    let mut clients = vec![];
    for i in 0..12 {
        let mut c = UnixStream::connect(if i % 2 == 0 { &r.owner } else { &r.attach }).unwrap();
        write_msg(&mut c, &Req::Hello).unwrap();
        assert!(matches!(
            read_msg::<Resp>(&mut c),
            Ok(Some(Resp::Hello { .. }))
        ));
        // Set the read guard while the socket is live: macOS refuses
        // SO_RCVTIMEO (EINVAL) on a socket the server has already shut down.
        c.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        clients.push(c);
    }
    // 12 idle workers are running (each answered, so each was accepted)
    assert_eq!(serving.live_connections(), 12);
    // Leave exactly one free descriptor number, which is what stop's wake of
    // a listener needs (a duplicate per connection would need twelve more).
    // The lowest free number is where a new descriptor lands, so a probe
    // names it; nothing below it is free, and nothing above it may be used.
    let probe = std::fs::File::open("/dev/null").unwrap();
    let limit = u64::try_from(std::os::fd::AsRawFd::as_raw_fd(&probe)).unwrap() + 1;
    drop(probe);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(limit),
            // the hard limit stays as it was
            maximum: rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum,
        },
    )
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        serving.stop();
        let _ = tx.send(());
    });
    // only a guard: a stop that cannot end a worker would wait forever
    rx.recv_timeout(std::time::Duration::from_secs(30))
        .expect("stop did not complete");
    for mut c in clients {
        let end = read_msg::<Resp>(&mut c);
        assert!(matches!(end, Ok(None) | Err(_)), "{end:?}");
    }
}

#[test]
fn registering_a_device_certificate_is_the_owners_alone() {
    let r = rig();
    let dev = support::operator(&r.env);
    let reg = |cert: CertChain| Req::RegisterDevice { cert };
    // the attach socket never offers it
    let refused = ask(&r.attach, &reg(dev.cert().clone()));
    assert!(refused_as_not_offered(&refused), "{refused:?}");
    // another user's certificate is refused even to the owner
    assert!(matches!(ask(&r.owner, &reg(a_cert())), Resp::Err(_)));
    assert!(matches!(ask(&r.owner, &reg(dev.cert().clone())), Resp::Ok));
    // and only once
    assert!(matches!(
        ask(&r.owner, &reg(dev.cert().clone())),
        Resp::Err(_)
    ));
}
