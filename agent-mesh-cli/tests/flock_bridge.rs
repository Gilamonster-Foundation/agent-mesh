//! The flock over the mesh, in one process on loopback: the home is a real
//! server with its attach socket and a bridge on a bus; the remote is a second
//! bus with the attach proxy, and real sessions and readers dial the proxy's
//! socket exactly as they dial the server's. Direct dial, no mDNS, no sleeps:
//! every wait is a blocking read or a server-side epoch wait.
#![cfg(unix)]

use agent_mesh_bus::{Bus, BusOptions, PeerEndpoint};
use agent_mesh_cli::flock_bridge::{
    fetch_genesis, pin_genesis, serve_home, serve_proxy, topic, Peer,
};
use agent_mesh_flock::{Body, Kind, Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp, StreamChallenge};
use agent_mesh_flock_server::{
    bind_private, init, load_genesis, serve_with_attach, InitSpec, Server, Serving, Snapshot,
};
use agent_mesh_flock_session::{Policy, Reader, ReaderError, RealFs, Session};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats, UserKey};
use content_addressable::{ContentAddressable as _, ContentId};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

fn agent(user: &UserKey, role: &str) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "test".into(),
            capabilities: vec![],
            issued_at: "2026-10-18T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    )
}

/// A bus on loopback, not announced, and where to dial it.
async fn node(user: &UserKey, role: &str) -> (Arc<Bus>, PeerEndpoint) {
    let key = agent(user, role);
    let pubkey = key.public_bytes();
    let bus = Bus::bind_with(user, key, 0, BusOptions { announce: false })
        .await
        .unwrap();
    let at = PeerEndpoint::new(
        pubkey,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bus.local_port()),
    );
    (Arc::new(bus), at)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

/// A served flock with an attach socket, bridged on `bus`.
struct Home {
    dir: TempDir,
    owner: PathBuf,
    id: ContentId,
    serving: Option<Serving>,
}

fn home(user: &UserKey, bus: &Bus, name: &str) -> Home {
    let dir = tempfile::tempdir().unwrap();
    let member = |n: &str, role| Member {
        name: n.into(),
        role,
        devices: vec![],
    };
    let spec = InitSpec {
        name: name.into(),
        roster: vec![
            member("shep", Role::Shepherd),
            member("h1", Role::Helper),
            member("h2", Role::Helper),
            member("rev", Role::Reviewer),
        ],
        salt: "00".into(),
        host: "h".into(),
        issued_at: "t".into(),
    };
    let id = init(dir.path(), user, spec).unwrap();
    let server = Server::open(dir.path()).unwrap();
    let owner = dir.path().join("run").join("serve.sock");
    let attach = dir.path().join("run").join("attach.sock");
    let serving = serve_with_attach(
        server,
        bind_private(&owner).unwrap(),
        bind_private(&attach).unwrap(),
    )
    .unwrap();
    serve_home(bus, topic(user.fingerprint(), &id), attach);
    Home {
        dir,
        owner,
        id,
        serving: Some(serving),
    }
}

impl Home {
    fn serving(&self) -> &Serving {
        self.serving.as_ref().unwrap()
    }

    /// The owner mints an invite, locally, as `amesh flock invite` does.
    fn invite(&self, member: &str) -> String {
        let mut c = UnixStream::connect(&self.owner).unwrap();
        write_msg(
            &mut c,
            &Req::Invite {
                member: member.into(),
            },
        )
        .unwrap();
        match read_msg::<Resp>(&mut c).unwrap() {
            Some(Resp::Invited { token }) => token,
            other => panic!("{other:?}"),
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot::read(self.dir.path()).unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        if let Some(s) = self.serving.take() {
            s.stop();
        }
    }
}

/// The remote's view of a flock: its directory, with the genesis the home
/// served and the proxy's socket.
struct Attached {
    dir: TempDir,
    sock: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

async fn attach(user: &UserKey, remote: &Arc<Bus>, at: PeerEndpoint, home: &Home) -> Attached {
    let t = topic(user.fingerprint(), &home.id);
    let peer = Peer::Direct(at);
    let signed = fetch_genesis(remote, &peer, &t).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    pin_genesis(dir.path(), &home.id, &signed).unwrap();
    let sock = dir.path().join("run").join("serve.sock");
    let listener = bind_private(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let remote = remote.clone();
    let task = tokio::spawn(async move {
        let _ = serve_proxy(remote, peer, t, listener).await;
    });
    Attached { dir, sock, task }
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn ask(sock: &Path, req: &Req) -> Resp {
    let mut c = UnixStream::connect(sock).unwrap();
    write_msg(&mut c, req).unwrap();
    read_msg::<Resp>(&mut c).unwrap().expect("an answer")
}

/// Enrol a key made here, over `sock`, keeping the connection (its life).
fn enrol_by_hand(sock: &Path, token: &str, member: &str) -> (UnixStream, AgentKey, String, bool) {
    let mut c = UnixStream::connect(sock).unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    write_msg(
        &mut c,
        &Req::EnrollBegin {
            token: token.into(),
            member: member.into(),
            pubkey: sk.verifying_key().to_bytes(),
        },
    )
    .unwrap();
    let Some(Resp::Challenge(ch)) = read_msg::<Resp>(&mut c).unwrap() else {
        panic!("no challenge")
    };
    let proof = sk.sign(&ch.signing_bytes());
    write_msg(
        &mut c,
        &Req::EnrollFinish {
            challenge: ch,
            proof,
        },
    )
    .unwrap();
    let Some(Resp::Enrolled {
        session,
        cert,
        pending,
    }) = read_msg::<Resp>(&mut c).unwrap()
    else {
        panic!("not enrolled")
    };
    (
        c,
        AgentKey::from_seed_and_cert(&sk.to_bytes(), cert).unwrap(),
        session,
        pending,
    )
}

/// Open a stream on a fresh connection and sign its challenge: the proof, and
/// the connection it belongs to.
fn stream_proof(sock: &Path, key: &AgentKey) -> (UnixStream, StreamChallenge, Assertion) {
    let mut c = UnixStream::connect(sock).unwrap();
    write_msg(&mut c, &Req::WatchBegin).unwrap();
    let Some(Resp::StreamChallenge(ch)) = read_msg::<Resp>(&mut c).unwrap() else {
        panic!("no stream challenge")
    };
    let proof = Assertion::sign(key, &ch.id().unwrap());
    (c, ch, proof)
}

/// A stream that was not opened: an error answer or no answer at all.
fn refused(c: &mut UnixStream) -> bool {
    matches!(read_msg::<Resp>(c), Ok(Some(Resp::Err(_)) | None) | Err(_))
}

fn job() -> (Kind, Body) {
    (
        Kind::Job,
        Body::Job {
            lane: "l".into(),
            label: "x".into(),
        },
    )
}

struct World {
    user: Arc<UserKey>,
    home_bus: Arc<Bus>,
    home_at: PeerEndpoint,
    remote_bus: Arc<Bus>,
}

async fn world() -> World {
    let user = Arc::new(UserKey::generate());
    let (home_bus, home_at) = node(&user, "home").await;
    let (remote_bus, _) = node(&user, "remote").await;
    World {
        user,
        home_bus,
        home_at,
        remote_bus,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_session_enrols_with_a_token_from_home_and_emits_into_the_home_log() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.home_at, &h).await;
    let token = h.invite("h1");
    let sock = a.sock.clone();
    let (admitted, _s) = blocking(move || {
        let mut s = Session::enroll(&sock, &token, "h1", Policy::AllowUnlocked).unwrap();
        let (k, b) = job();
        let r = s.emit(k, Default::default(), b).unwrap();
        (r, s)
    })
    .await;
    // the key was made on the remote; the home's log has the event, by h1
    let snap = h.snapshot();
    let e = snap
        .board()
        .entries()
        .find(|e| e.id == admitted.0)
        .expect("in the home log");
    assert_eq!(e.member.as_deref(), Some("h1"));
    assert_eq!(e.event.kind, Kind::Job);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_is_not_offered_remotely_and_still_works_at_home() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.home_at, &h).await;
    let sock = a.sock.clone();
    let answer = blocking(move || {
        ask(
            &sock,
            &Req::Invite {
                member: "h1".into(),
            },
        )
    })
    .await;
    match answer {
        Resp::Err(why) => assert!(why.contains("not offered"), "{why}"),
        other => panic!("an invite was minted remotely: {other:?}"),
    }
    assert!(!h.invite("h1").is_empty(), "the owner can");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wrong_flock_id_is_refused_before_anything_is_written() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let other = home(&w.user, &w.home_bus, "g"); // another flock, another id
    let t = topic(w.user.fingerprint(), &h.id);
    let signed = fetch_genesis(&w.remote_bus, &Peer::Direct(w.home_at), &t)
        .await
        .unwrap();
    assert_eq!(
        signed.node.content_id().unwrap(),
        h.id,
        "the home's genesis"
    );
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("flock");
    let err = pin_genesis(&target, &other.id, &signed).unwrap_err();
    assert!(err.to_string().contains("not the"), "{err}");
    assert!(!target.exists(), "nothing was written");
    // the right id is accepted and verifies as the server's own file does
    pin_genesis(&target, &h.id, &signed).unwrap();
    assert_eq!(
        load_genesis(&target).unwrap().node.content_id().unwrap(),
        h.id
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_replays_through_the_proxy_and_then_follows_live() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.home_at, &h).await;
    let (t1, t2) = (h.invite("h1"), h.invite("h2"));
    let sock = a.sock.clone();
    let rdir = a.dir.path().join("reader");
    std::fs::create_dir_all(&rdir).unwrap();
    let genesis = load_genesis(a.dir.path()).unwrap().node;
    let home_admitted = {
        let (s2, d) = (sock.clone(), rdir.clone());
        blocking(move || {
            let mut h1 = Session::enroll(&s2, &t1, "h1", Policy::AllowUnlocked).unwrap();
            let (k, b) = job();
            h1.emit(k, Default::default(), b).unwrap();
            // replay: everything so far arrives through the proxy, verified
            let mut reader = Reader::open(genesis.clone(), &d, RealFs).unwrap();
            let cell = std::cell::RefCell::new(h1);
            let prove = |ch: &StreamChallenge| {
                cell.borrow_mut()
                    .prove_stream(ch)
                    .map_err(|e| ReaderError::Stream(e.to_string()))
            };
            reader.sync(&s2, &prove).unwrap();
            let seen = reader.follower().admitted();
            (seen, genesis, cell.into_inner())
        })
        .await
    };
    let (replayed, genesis, mut h1) = home_admitted;
    assert_eq!(replayed, h.snapshot().admitted(), "replay is the whole log");

    // live: a follower thread, then another remote session emits
    let (tx, rx) = std::sync::mpsc::channel();
    let s2 = sock.clone();
    let follower = std::thread::spawn(move || {
        let mut reader = Reader::open(genesis, &rdir, RealFs).unwrap();
        let cell = std::cell::RefCell::new(&mut h1);
        let prove = |ch: &StreamChallenge| {
            cell.borrow_mut()
                .prove_stream(ch)
                .map_err(|e| ReaderError::Stream(e.to_string()))
        };
        let _ = reader.follow(&s2, &prove, false, &mut |seen| {
            let _ = tx.send(matches!(seen, agent_mesh_flock_session::Seen::Caught(..)));
            if let agent_mesh_flock_session::Seen::Frame(f, _) = seen {
                for s in f {
                    let _ = tx.send(s.event.payload.kind == Kind::Job);
                }
            }
        });
    });
    // caught up first
    loop {
        if rx.recv().unwrap() {
            break;
        }
    }
    let s3 = sock.clone();
    blocking(move || {
        let mut h2 = Session::enroll(&s3, &t2, "h2", Policy::AllowUnlocked).unwrap();
        let (k, b) = job();
        h2.emit(k, Default::default(), b).unwrap();
        h2.end().unwrap();
    })
    .await;
    // the live job arrives on the open stream
    while !rx.recv().unwrap() {}
    // stopping the home ends the stream and the follower
    drop(h);
    follower.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_offline_across_two_bumps_renews_and_emits_and_an_ended_one_cannot() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.home_at, &h).await;
    let (t1, t2, t3) = (h.invite("h1"), h.invite("shep"), h.invite("h2"));
    let sock = a.sock.clone();
    let before = h.snapshot().epoch();
    let renewed = blocking({
        let sock = sock.clone();
        move || {
            // h1 enrols and then says nothing while two others come and go
            let mut h1 = Session::enroll(&sock, &t1, "h1", Policy::AllowUnlocked).unwrap();
            for (token, member) in [(t2, "shep"), (t3, "h2")] {
                Session::enroll(&sock, &token, member, Policy::AllowUnlocked)
                    .unwrap()
                    .end()
                    .unwrap();
            }
            // two bumps behind: the certificate is stale; emit renews, over the proxy
            let (k, b) = job();
            let ok = h1.emit(k, Default::default(), b).is_ok();
            // kept open: dropping it would itself end it, and bump the epoch
            (ok, h1)
        }
    })
    .await;
    let (renewed, _h1) = renewed;
    assert!(
        renewed,
        "a stale session renews through the proxy and emits"
    );
    assert_eq!(
        h.snapshot().epoch(),
        before + 2,
        "two bumps while it was quiet"
    );

    // an ended session cannot renew, however far behind it is
    let (t_rev, t_shep) = (h.invite("rev"), h.invite("shep"));
    let answer = blocking(move || {
        let (mut conn, key, _session, _) = enrol_by_hand(&sock, &t_rev, "rev");
        write_msg(&mut conn, &Req::End).unwrap();
        assert!(matches!(read_msg::<Resp>(&mut conn), Ok(Some(Resp::Ok))));
        // another bump after it ended, so its certificate is behind the epoch
        Session::enroll(&sock, &t_shep, "shep", Policy::AllowUnlocked)
            .unwrap()
            .end()
            .unwrap();
        ask(
            &sock,
            &Req::Renew {
                last: key.cert().clone(),
            },
        )
    })
    .await;
    assert!(
        matches!(answer, Resp::Err(_)),
        "an ended session was renewed: {answer:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_flocks_at_different_epochs_share_one_connection_and_a_bump_in_one_leaves_the_other_alone(
) {
    let w = world().await;
    let (a_home, b_home) = (
        home(&w.user, &w.home_bus, "a"),
        home(&w.user, &w.home_bus, "b"),
    );
    // one bus on each side, so both flocks ride the same host-to-host connection
    let a = attach(&w.user, &w.remote_bus, w.home_at, &a_home).await;
    let b = attach(&w.user, &w.remote_bus, w.home_at, &b_home).await;
    let tokens: Vec<String> = (0..3).map(|_| a_home.invite("h2")).collect();
    let (b_token, a_sock, b_sock) = (b_home.invite("h1"), a.sock.clone(), b.sock.clone());
    let b_emitted = blocking(move || {
        let mut b1 = Session::enroll(&b_sock, &b_token, "h1", Policy::AllowUnlocked).unwrap();
        // bump A three times (a session of A ends each time)
        for t in tokens {
            Session::enroll(&a_sock, &t, "h2", Policy::AllowUnlocked)
                .unwrap()
                .end()
                .unwrap();
        }
        // B's session was never behind: its certificate is still current
        let (k, body) = job();
        let ok = b1.emit(k, Default::default(), body).is_ok();
        // keep the session open: dropping it would itself end it, and bump B
        (ok, b1)
    })
    .await;
    let (b_emitted, _b1) = b_emitted;
    assert!(b_emitted);
    assert_eq!(a_home.snapshot().epoch(), 3, "A moved");
    assert_eq!(b_home.snapshot().epoch(), 0, "B did not");
    // and B's log carries no epoch event at all
    assert!(!b_home
        .snapshot()
        .board()
        .entries()
        .any(|e| e.event.kind == Kind::Epoch));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_refusals_hold_through_the_proxy_a_copied_cert_a_replayed_proof_pending_and_ended_sessions(
) {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let other = home(&w.user, &w.home_bus, "g");
    let a = attach(&w.user, &w.remote_bus, w.home_at, &h).await;
    let b = attach(&w.user, &w.remote_bus, w.home_at, &other).await;
    let (t_victim, t_attacker, t_pending, t_ended) = (
        h.invite("h1"),
        h.invite("h2"),
        h.invite("h1"),
        h.invite("rev"),
    );
    let (sock, bsock) = (a.sock.clone(), b.sock.clone());
    blocking(move || {
        let (_vc, victim, victim_session, _) = enrol_by_hand(&sock, &t_victim, "h1");
        let (_ac, attacker, _s, _) = enrol_by_hand(&sock, &t_attacker, "h2");

        // a copied certificate: the attacker signs an event claiming the victim's
        // session with its own key (it cannot make a key for the victim's cert)
        let flock = match ask(&sock, &Req::Hello) {
            Resp::Hello { flock, .. } => flock,
            other => panic!("{other:?}"),
        };
        let node = agent_mesh_flock::Event {
            flock,
            kind: job().0,
            author: victim_session.clone(),
            prev: None,
            refs: Default::default(),
            files: vec![],
            at: 0,
            body: job().1,
        }
        .node();
        let forged = Assertion::sign(&attacker, &node.content_id().unwrap());
        assert!(
            matches!(ask(&sock, &Req::Admit { node, sig: forged }), Resp::Err(_)),
            "an event signed by another key was admitted as the victim's"
        );

        // a proof is for one stream: valid where it was made, refused replayed
        // on another stream of the same flock, and on another flock's stream
        let (mut first, _ch, proof) = stream_proof(&sock, &victim);
        write_msg(
            &mut first,
            &Req::Watch {
                from: None,
                proof: Box::new(proof.clone()),
            },
        )
        .unwrap();
        assert!(
            matches!(read_msg::<Resp>(&mut first), Ok(Some(Resp::Frame(_)))),
            "the proof works on its own stream"
        );
        let (mut replay, _, _) = stream_proof(&sock, &victim);
        write_msg(
            &mut replay,
            &Req::Watch {
                from: None,
                proof: Box::new(proof.clone()),
            },
        )
        .unwrap();
        assert!(refused(&mut replay), "a proof replayed on another stream");
        let (mut elsewhere, _, _) = stream_proof(&bsock, &victim);
        write_msg(
            &mut elsewhere,
            &Req::Watch {
                from: None,
                proof: Box::new(proof),
            },
        )
        .unwrap();
        assert!(refused(&mut elsewhere), "a proof replayed on another flock");

        // a pending replacement cannot open a stream
        let (_pc, pending_key, _ps, pending) = enrol_by_hand(&sock, &t_pending, "h1");
        assert!(pending);
        let (mut c, _, p) = stream_proof(&sock, &pending_key);
        write_msg(
            &mut c,
            &Req::Watch {
                from: None,
                proof: Box::new(p),
            },
        )
        .unwrap();
        assert!(refused(&mut c), "a pending session watched");

        // an ended session cannot either
        let (mut conn, ended, _es, _) = enrol_by_hand(&sock, &t_ended, "rev");
        write_msg(&mut conn, &Req::End).unwrap();
        assert!(matches!(read_msg::<Resp>(&mut conn), Ok(Some(Resp::Ok))));
        let (mut c, _, p) = stream_proof(&sock, &ended);
        write_msg(
            &mut c,
            &Req::Watch {
                from: None,
                proof: Box::new(p),
            },
        )
        .unwrap();
        assert!(refused(&mut c), "an ended session watched");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_drops_without_goodbye_is_recorded_lost_at_home() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.home_at, &h).await;
    let token = h.invite("h1");
    let sock = a.sock.clone();
    // enrol and vanish: no End, the stream just goes away
    blocking(move || {
        let s = Session::enroll(&sock, &token, "h1", Policy::AllowUnlocked).unwrap();
        drop(s);
    })
    .await;
    // the bridge closed the attach connection, so the server saw it drop: a
    // `lost` and the epoch bump that follows (waited for causally)
    let serving = h.serving();
    assert!(serving.wait_epoch(1));
    let ended_lost = h.snapshot().board().entries().any(|e| {
        matches!(
            &e.event.body,
            Body::SessionEnd {
                reason: agent_mesh_flock::EndReason::Lost,
                ..
            }
        )
    });
    assert!(ended_lost);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_home_that_sends_something_that_is_not_one_wire_message_is_cut_off() {
    let w = world().await;
    let t = agent_mesh_bus::Topic::new(w.user.fingerprint(), "flock/hostile");
    // a hostile "home": it accepts every stream and answers with a whole, valid
    // message and one stray byte after it. If the proxy wrote that to the
    // socket the client would read the message and then be out of step.
    w.home_bus
        .handle_sessions(t.clone(), |incoming| async move {
            let mut s = incoming.accept().await?;
            let _ = s.recv().await?;
            let mut glued = Vec::new();
            write_msg(&mut glued, &Resp::Ok).unwrap();
            glued.push(0);
            s.send(glued).await?;
            Ok(())
        });
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("run").join("serve.sock");
    let listener = bind_private(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let task = tokio::spawn(serve_proxy(
        w.remote_bus.clone(),
        Peer::Direct(w.home_at),
        t,
        listener,
    ));
    let outcome = blocking(move || {
        let mut c = UnixStream::connect(&sock).unwrap();
        write_msg(&mut c, &Req::Hello).unwrap();
        // the local end sees the connection end: it never reads the glued message
        read_msg::<Resp>(&mut c)
    })
    .await;
    assert!(
        matches!(outcome, Ok(None) | Err(_)),
        "the glued message was delivered: {outcome:?}"
    );
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_genesis_answer_that_is_not_exactly_one_message_is_refused() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let real = topic(w.user.fingerprint(), &h.id);
    let signed = fetch_genesis(&w.remote_bus, &Peer::Direct(w.home_at), &real)
        .await
        .unwrap();
    // the real genesis, with a stray byte after it, on a topic of its own
    let hostile = agent_mesh_bus::Topic::new(w.user.fingerprint(), "flock/hostile");
    w.home_bus
        .handle_sessions(hostile.clone(), move |incoming| {
            let g = signed.clone();
            async move {
                let mut s = incoming.accept().await?;
                let _ = s.recv().await?;
                let mut body = Vec::new();
                write_msg(&mut body, &Resp::Genesis(g)).unwrap();
                body.push(0);
                s.send(body).await?;
                Ok(())
            }
        });
    let err = fetch_genesis(&w.remote_bus, &Peer::Direct(w.home_at), &hostile)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("exactly one wire message"),
        "{err}"
    );
}
