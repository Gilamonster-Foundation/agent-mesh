//! Frames that cite or carry the wrong certificate are refused by both
//! readers (`Server::open` replaying the log, and a `Follower`), exactly as an
//! honest frame is accepted. A sealed event is verified against a certificate
//! the log recorded for its author; nothing else may stand in for it.
#![cfg(all(unix, feature = "serve"))]
mod support;

use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock_server::{encode, seal, Follower, Frame, Sealed, Server};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats};
use std::io::Write;
use support::{bump_and_renew, enroll, Enrolment, Env};

struct World {
    env: Env,
    server: Server,
    shep: Enrolment,
    h1: Enrolment,
}

fn world() -> World {
    let env = Env::new();
    let mut server = env.open();
    let shep = enroll(&mut server, "shep");
    let h1 = enroll(&mut server, "h1");
    World {
        env,
        server,
        shep,
        h1,
    }
}

/// shep's `brief` to h1: the event, authored by shep, and the signature of
/// whichever key `signer` is.
fn brief(
    w: &mut World,
    signer: &AgentKey,
) -> (
    content_addressable::MerkleNode<agent_mesh_flock::Event>,
    Assertion,
) {
    let prev = w.server.board().head_of(&w.shep.key.fingerprint().hex());
    let (node, _) = w.env.event(
        &w.shep.key,
        Kind::Brief,
        prev,
        &[],
        Body::Brief {
            to: "h1".into(),
            lane: "l1".into(),
        },
    );
    let sig = Assertion::sign(
        signer,
        &content_addressable::ContentAddressable::content_id(&node).unwrap(),
    );
    (node, sig)
}

/// An assertion with `author`'s certificate and `from`'s signature bytes: a
/// certificate that does not match the signature, built without any helper
/// that would refuse to.
fn mix(author: &Assertion, from: &Assertion) -> Assertion {
    let a = serde_json::to_value(author).unwrap();
    let mut f = serde_json::to_value(from).unwrap();
    f["author"] = a["author"].clone();
    serde_json::from_value(f).unwrap()
}

fn seal_next(
    w: &World,
    node: content_addressable::MerkleNode<agent_mesh_flock::Event>,
    sig: Assertion,
) -> Sealed {
    let epoch = w.server.epoch();
    seal(
        &w.env.server_key(),
        w.server.head_record(),
        w.server.admitted() + 1,
        epoch,
        node,
        sig,
    )
    .unwrap()
}

fn prefix(w: &World) -> Vec<Vec<Sealed>> {
    let j = w.server.journal();
    let mut c = j.cursor_from(None).unwrap();
    let mut out = vec![];
    while c.delivered() < j.len() {
        out.push(c.next_frame().unwrap().0.to_vec());
    }
    out
}

/// Whether the follower takes the prefix and then `forged`.
fn follower_accepts(w: &World, forged: &Sealed) -> bool {
    let genesis = agent_mesh_flock_server::load_genesis(w.env.tmp.path())
        .unwrap()
        .node;
    let mut f = Follower::new(&genesis).unwrap();
    for fr in prefix(w) {
        f.apply(&fr).unwrap();
    }
    f.apply(std::slice::from_ref(forged)).is_ok()
}

/// Whether `Server::open` takes the log with `forged` appended.
fn open_accepts(w: World, forged: &Sealed) -> bool {
    let env = w.env;
    drop(w.server);
    let bytes = encode(&Frame {
        sealed: vec![forged.clone()],
    })
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(env.log_path())
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    Server::open(&env.dir()).is_ok()
}

fn both(w: World, forged: &Sealed) -> (bool, bool) {
    (follower_accepts(&w, forged), open_accepts(w, forged))
}

#[test]
fn control_an_honest_frame_is_accepted_by_both_readers() {
    let mut w = world();
    let key = key_of(&w.shep);
    let (n, s) = brief(&mut w, &key);
    let sealed = seal_next(&w, n, s);
    assert_eq!(both(w, &sealed), (true, true));
}

#[test]
fn a_certificate_the_log_never_recorded_is_refused() {
    let mut w = world();
    // certified by the same user, never enrolled: not a session of this flock
    let stranger = AgentKey::issue(
        &w.env.user,
        AgentMetadata {
            role: "x".into(),
            host: "x".into(),
            capabilities: vec![],
            issued_at: "2026-10-18T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    );
    let (n, s) = brief(&mut w, &stranger);
    let sealed = seal_next(&w, n, s);
    assert_eq!(both(w, &sealed), (false, false));
}

#[test]
fn another_sessions_certificate_cannot_stand_in_for_the_authors() {
    // h1's key and cert signing shep's event
    let mut w = world();
    let key = key_of(&w.h1);
    let (n, s) = brief(&mut w, &key);
    let sealed = seal_next(&w, n, s);
    assert_eq!(both(w, &sealed), (false, false));
}

#[test]
fn another_sessions_certificate_cited_over_the_authors_signature_is_refused() {
    // shep really signed it, but the frame cites h1's certificate
    let mut w = world();
    let (shep, h1) = (key_of(&w.shep), key_of(&w.h1));
    let (n, mine) = brief(&mut w, &shep);
    let (_, theirs) = brief(&mut w, &h1);
    let sealed = seal_next(&w, n, mix(&theirs, &mine));
    assert_eq!(both(w, &sealed), (false, false));
}

#[test]
fn the_right_key_with_a_certificate_from_before_the_epoch_moved_is_refused() {
    let mut w = world();
    let mut herdr = enroll(&mut w.server, "herdr");
    let mut h1 = Enrolment {
        ..clone_enrolment(&w.h1)
    };
    // the epoch moves; only h1 renews, shep keeps its epoch-0 certificate
    bump_and_renew(&mut w.server, &herdr, &mut [&mut h1]);
    herdr.pending = false;
    let key = key_of(&w.shep);
    let (n, s) = brief(&mut w, &key);
    let sealed = seal_next(&w, n, s);
    assert!(w.server.epoch() >= 1);
    assert_eq!(both(w, &sealed), (false, false));
}

/// A second handle on the enrolment's key.
fn key_of(e: &Enrolment) -> AgentKey {
    AgentKey::from_seed_and_cert(&e.sk.to_bytes(), e.key.cert().clone()).unwrap()
}

fn clone_enrolment(e: &Enrolment) -> Enrolment {
    Enrolment {
        sk: e.sk.clone(),
        key: key_of(e),
        session: e.session.clone(),
        pending: e.pending,
    }
}

#[test]
fn the_servers_certificate_on_a_session_event_is_refused() {
    // signed outright by the server key
    let mut w = world();
    let sk = w.env.server_key();
    let (n, s) = brief(&mut w, &sk);
    let sealed = seal_next(&w, n, s);
    assert_eq!(
        both(w, &sealed),
        (false, false),
        "server key on a session event"
    );

    // shep's signature under the server's certificate
    let mut w = world();
    let (shep, sk) = (key_of(&w.shep), w.env.server_key());
    let (n, mine) = brief(&mut w, &shep);
    let (_, srv) = brief(&mut w, &sk);
    let sealed = seal_next(&w, n, mix(&srv, &mine));
    assert_eq!(
        both(w, &sealed),
        (false, false),
        "server cert over a session signature"
    );
}

#[test]
fn a_record_citing_a_certificate_the_log_does_not_hold_says_so() {
    // a frame cites its certificate by id; one the log never recorded is
    // refused for that reason, not for some later failure
    let mut w = world();
    let stranger = AgentKey::issue(
        &w.env.user,
        AgentMetadata {
            role: "x".into(),
            host: "x".into(),
            capabilities: vec![],
            issued_at: "2026-10-18T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    );
    let (n, s) = brief(&mut w, &stranger);
    let sealed = seal_next(&w, n, s);
    let genesis = agent_mesh_flock_server::load_genesis(w.env.tmp.path())
        .unwrap()
        .node;
    let mut f = Follower::new(&genesis).unwrap();
    for fr in prefix(&w) {
        f.apply(&fr).unwrap();
    }
    let why = format!("{:?}", f.apply(std::slice::from_ref(&sealed)).unwrap_err());
    assert!(why.contains("does not hold"), "{why}");
}

/// The server's own key under a second, equally valid certificate: only the
/// metadata differs, and the same user signs it. Nothing in the log holds it.
fn alternate_server_cert(w: &World) -> AgentKey {
    use agent_mesh_protocol::{CertChain, SerdeSig};
    let server = w.env.server_key();
    let mut meta = server.cert().metadata.clone();
    meta.issued_at = "2026-12-31T00:00:00Z".into();
    let mut payload = server.cert().agent_pubkey.to_vec();
    payload.extend(serde_json::to_vec(&meta).unwrap());
    let cert = CertChain {
        agent_pubkey: server.cert().agent_pubkey,
        metadata: meta,
        issuer: server.cert().issuer.clone(),
        issuer_sig: SerdeSig(w.env.user.sign(&payload)),
    };
    cert.verify().expect("the alternate certificate is valid");
    AgentKey::from_seed_and_cert(&server.signing_key_bytes(), cert).unwrap()
}

#[test]
fn a_valid_alternate_server_certificate_is_refused_at_admission_and_the_log_stays_readable() {
    let mut w = world();
    let alt = alternate_server_cert(&w);
    assert_ne!(alt.cert(), w.env.server_key().cert());
    let before = w.env.log_len();
    // a server-authored event signed under it
    let (node, _) = w.env.server_event("under the alternate certificate");
    let node_id = content_addressable::ContentAddressable::content_id(&node).unwrap();
    let sig = Assertion::sign(&alt, &node_id);
    let err = w.server.admit(node, sig).unwrap_err();
    assert!(
        format!("{err:?}").contains("does not hold"),
        "refused for its citation: {err:?}"
    );
    assert_eq!(w.env.log_len(), before, "nothing was appended");

    // and the flock goes on: an honest event is admitted, and every reader
    // that replays the log agrees with the server
    let key = key_of(&w.shep);
    let (n, s) = brief(&mut w, &key);
    w.server.admit(n, s).unwrap();
    let head = w.server.head_record();
    let genesis = agent_mesh_flock_server::load_genesis(w.env.tmp.path())
        .unwrap()
        .node;
    let mut f = Follower::new(&genesis).unwrap();
    for fr in prefix(&w) {
        f.apply(&fr).unwrap();
    }
    assert_eq!(f.admitted(), w.server.admitted());
    let snap = agent_mesh_flock_server::Snapshot::read(w.env.tmp.path()).unwrap();
    assert_eq!(snap.admitted(), w.server.admitted());
    let env = w.env;
    drop(w.server);
    let reopened = Server::open(&env.dir()).unwrap();
    assert_eq!(reopened.head_record(), head);
}
