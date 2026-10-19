//! The reader side of cited files: what a member gets from a home host, and
//! that a host which lies about the bytes is caught here.
#![cfg(unix)]

use agent_mesh_flock::{Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp, StreamChallenge};
use agent_mesh_flock_server::{bind_private, init, serve, InitSpec, Server, Serving};
use agent_mesh_flock_session::{Cited, Files, ReaderError};
use agent_mesh_protocol::{AgentKey, Assertion, UserKey};
use content_addressable::{ContentId, RawContentId};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use tempfile::TempDir;

fn id_of(b: &[u8]) -> RawContentId {
    RawContentId::from_content(b)
}

fn prover(key: &AgentKey) -> impl Fn(&StreamChallenge) -> Result<Assertion, ReaderError> + '_ {
    move |ch| Ok(Assertion::sign(key, &ch.id().unwrap()))
}

struct Home {
    tmp: TempDir,
    sock: PathBuf,
    notes: PathBuf,
    key: AgentKey,
    _serving: Serving,
}

fn home() -> Home {
    let tmp = TempDir::new().unwrap();
    let user = UserKey::generate();
    init(
        tmp.path(),
        &user,
        InitSpec {
            name: "f".into(),
            roster: vec![Member {
                name: "shep".into(),
                role: Role::Shepherd,
                devices: vec![],
            }],
            salt: "00".into(),
            host: "h".into(),
            issued_at: "t".into(),
        },
    )
    .unwrap();
    let mut server = Server::open(tmp.path()).unwrap();
    let invite = server.invite("shep").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let ch = server
        .enroll_begin(&invite.token, "shep", sk.verifying_key().to_bytes())
        .unwrap();
    let done = server
        .enroll_finish(&ch, &sk.sign(&ch.signing_bytes()))
        .unwrap();
    let key = AgentKey::from_seed_and_cert(&sk.to_bytes(), done.cert).unwrap();
    let notes = tmp.path().join("notes");
    std::fs::create_dir(&notes).unwrap();
    server
        .serve_roots(BTreeMap::from([("notes".to_owned(), notes.clone())]))
        .unwrap();
    let sock = tmp.path().join("run").join("serve.sock");
    let serving = serve(server, bind_private(&sock).unwrap()).unwrap();
    Home {
        tmp,
        sock,
        notes,
        key,
        _serving: serving,
    }
}

#[test]
fn a_member_reads_stats_and_is_told_what_changed() {
    let h = home();
    std::fs::write(h.notes.join("a.md"), b"as cited").unwrap();
    let mut f = Files::open(&h.sock, &prover(&h.key)).unwrap();
    assert_eq!(f.stat("notes", "a.md").unwrap(), Ok(id_of(b"as cited")));
    assert_eq!(
        f.read("notes", "a.md", &id_of(b"as cited")).unwrap(),
        Cited::Bytes(b"as cited".to_vec())
    );
    std::fs::write(h.notes.join("a.md"), b"edited").unwrap();
    assert_eq!(
        f.read("notes", "a.md", &id_of(b"as cited")).unwrap(),
        Cited::Changed {
            current: id_of(b"edited")
        }
    );
    assert_eq!(
        f.read("notes", "../x", &id_of(b"x")).unwrap(),
        Cited::Unavailable("outside the root".into())
    );
    assert_eq!(f.stat("notes", "gone").unwrap(), Err("missing".to_owned()));
    let _ = &h.tmp;
}

#[test]
fn a_non_member_cannot_open() {
    let h = home();
    let stranger = AgentKey::issue(
        &UserKey::generate(),
        agent_mesh_protocol::AgentMetadata {
            role: "x".into(),
            host: "h".into(),
            capabilities: vec![],
            issued_at: "t".into(),
            expires_at: None,
            caveats: agent_mesh_protocol::Caveats::top(),
        },
    );
    assert!(matches!(
        Files::open(&h.sock, &prover(&stranger)),
        Err(ReaderError::Stream(_))
    ));
}

/// A server that proves membership and then answers each request with
/// `answer`, whatever was asked.
fn liar(answer: Resp) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let sock = tmp.path().join("liar.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let Ok((mut c, _)) = listener.accept() else {
            return;
        };
        let mut nonce = [0u8; 32];
        nonce[0] = 1;
        let ch = StreamChallenge {
            flock: ContentId::from_canonical_bytes(b"f"),
            nonce,
        };
        loop {
            match read_msg::<Req>(&mut c) {
                Ok(Some(Req::WatchBegin)) => {
                    let _ = write_msg(&mut c, &Resp::StreamChallenge(ch.clone()));
                }
                Ok(Some(Req::Prove { .. })) => {
                    let _ = write_msg(&mut c, &Resp::Proved);
                }
                Ok(Some(_)) => {
                    let _ = write_msg(&mut c, &answer);
                }
                _ => return,
            }
        }
    });
    (tmp, sock)
}

fn lied_to(answer: Resp) -> Result<Cited, ReaderError> {
    let (_tmp, sock) = liar(answer);
    let key = AgentKey::issue(
        &UserKey::generate(),
        agent_mesh_protocol::AgentMetadata {
            role: "x".into(),
            host: "h".into(),
            capabilities: vec![],
            issued_at: "t".into(),
            expires_at: None,
            caveats: agent_mesh_protocol::Caveats::top(),
        },
    );
    let mut f = Files::open(&sock, &prover(&key)).unwrap();
    f.read("notes", "a.md", &id_of(b"cited"))
}

#[test]
fn bytes_that_do_not_hash_to_the_cited_id_are_refused_whoever_sends_them() {
    let r = lied_to(Resp::File {
        bytes: b"something else".to_vec(),
    });
    assert!(matches!(r, Err(ReaderError::Invalid(_))), "{r:?}");
    // the right bytes are accepted: the check is on the hash, not on the lie
    let ok = lied_to(Resp::File {
        bytes: b"cited".to_vec(),
    });
    assert_eq!(ok.unwrap(), Cited::Bytes(b"cited".to_vec()));
}

#[test]
fn a_changed_report_naming_the_cited_id_is_a_lie() {
    let r = lied_to(Resp::ChangedSinceCited {
        current: id_of(b"cited"),
    });
    assert!(matches!(r, Err(ReaderError::Invalid(_))), "{r:?}");
}

#[test]
fn bytes_past_the_limit_are_refused_even_if_they_hash_right() {
    let big = vec![1u8; agent_mesh_flock_server::wire::MAX_FILE + 1];
    let (_tmp, sock) = liar(Resp::File { bytes: big.clone() });
    let key = AgentKey::issue(
        &UserKey::generate(),
        agent_mesh_protocol::AgentMetadata {
            role: "x".into(),
            host: "h".into(),
            capabilities: vec![],
            issued_at: "t".into(),
            expires_at: None,
            caveats: agent_mesh_protocol::Caveats::top(),
        },
    );
    let mut f = Files::open(&sock, &prover(&key)).unwrap();
    // the message limit itself stops the server from sending it; a reader
    // that did receive it would still refuse
    let r = f.read("notes", "a.md", &id_of(&big));
    assert!(matches!(r, Err(ReaderError::Invalid(_))), "{r:?}");
}

#[test]
fn an_answer_to_another_request_is_refused() {
    let r = lied_to(Resp::Proved);
    assert!(matches!(r, Err(ReaderError::Invalid(_))), "{r:?}");
}
