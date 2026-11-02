//! Fixtures and scenarios for the flock-over-the-mesh tests, shared so the same
//! scenarios run over each carrier. A test file picks a `World`, then calls a
//! scenario with it.
#![allow(dead_code)]

use agent_mesh_bus::RevocationGuard;
use agent_mesh_bus::{Bus, BusOptions, PeerEndpoint};
use agent_mesh_cli::flock_bridge::{
    fetch_genesis, pin_genesis, serve_home, serve_proxy, topic, Attachment, Gate, Limits, Peer,
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

pub fn agent(user: &UserKey, role: &str) -> AgentKey {
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
pub async fn node(user: &UserKey, role: &str) -> (Arc<Bus>, PeerEndpoint) {
    let key = agent(user, role);
    let pubkey = key.public_bytes();
    let bus = Bus::bind_with(
        user,
        key,
        0,
        BusOptions { announce: false },
        RevocationGuard::in_memory(user),
    )
    .await
    .unwrap();
    let at = PeerEndpoint::new(
        pubkey,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bus.local_port()),
    );
    (Arc::new(bus), at)
}

pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

/// A served flock with an attach socket, bridged on `bus`.
pub struct Home {
    pub dir: TempDir,
    pub owner: PathBuf,
    pub id: ContentId,
    pub serving: Option<Serving>,
}

pub fn home(user: &UserKey, bus: &Bus, name: &str) -> Home {
    home_gated(user, bus, name, Gate::new(Limits::default()))
}

pub fn home_gated(user: &UserKey, bus: &Bus, name: &str, gate: Arc<Gate>) -> Home {
    home_with_roots(user, bus, name, gate, std::collections::BTreeMap::new())
}

pub fn home_with_roots(
    user: &UserKey,
    bus: &Bus,
    name: &str,
    gate: Arc<Gate>,
    roots: std::collections::BTreeMap<String, PathBuf>,
) -> Home {
    let dir = tempfile::tempdir().unwrap();
    let member = |n: &str, role| Member {
        name: n.into(),
        role,
        devices: vec![],
        delegate: false,
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
    let mut server = Server::open(dir.path()).unwrap();
    server.serve_roots(roots).unwrap();
    let owner = dir.path().join("run").join("serve.sock");
    let attach = dir.path().join("run").join("attach.sock");
    let serving = serve_with_attach(
        server,
        bind_private(&owner).unwrap(),
        bind_private(&attach).unwrap(),
    )
    .unwrap();
    serve_home(bus, topic(user.fingerprint(), &id), attach, gate.clone());
    Home {
        dir,
        owner,
        id,
        serving: Some(serving),
    }
}

impl Home {
    pub fn serving(&self) -> &Serving {
        self.serving.as_ref().unwrap()
    }

    /// The owner mints an invite, locally, as `amesh flock invite` does.
    pub fn invite(&self, member: &str) -> String {
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

    pub fn snapshot(&self) -> Snapshot {
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
pub struct Attached {
    pub dir: TempDir,
    pub sock: PathBuf,
    pub task: tokio::task::JoinHandle<()>,
    pub _att: Attachment,
}

pub async fn attach(user: &UserKey, remote: &Arc<Bus>, peer: Peer, home: &Home) -> Attached {
    let t = topic(user.fingerprint(), &home.id);
    let signed = fetch_genesis(remote, &peer, &t).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    // attach insists on a private directory; a temp dir is not always one
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let att = pin_genesis(dir.path(), &home.id, &signed).unwrap();
    let sock = dir.path().join("run").join("serve.sock");
    let listener = bind_private(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let remote = remote.clone();
    let task = tokio::spawn(async move {
        let _ = serve_proxy(remote, peer, t, listener, Gate::new(Limits::default())).await;
    });
    Attached {
        dir,
        sock,
        task,
        _att: att,
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn ask(sock: &Path, req: &Req) -> Resp {
    let mut c = UnixStream::connect(sock).unwrap();
    write_msg(&mut c, req).unwrap();
    read_msg::<Resp>(&mut c).unwrap().expect("an answer")
}

/// Enrol a key made here, over `sock`, keeping the connection (its life).
pub fn enrol_by_hand(
    sock: &Path,
    token: &str,
    member: &str,
) -> (UnixStream, AgentKey, String, bool) {
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
pub fn stream_proof(sock: &Path, key: &AgentKey) -> (UnixStream, StreamChallenge, Assertion) {
    let mut c = UnixStream::connect(sock).unwrap();
    write_msg(&mut c, &Req::WatchBegin).unwrap();
    let Some(Resp::StreamChallenge(ch)) = read_msg::<Resp>(&mut c).unwrap() else {
        panic!("no stream challenge")
    };
    let proof = Assertion::sign(key, &ch.id().unwrap());
    (c, ch, proof)
}

/// A stream that was not opened: an error answer or no answer at all.
pub fn refused(c: &mut UnixStream) -> bool {
    matches!(read_msg::<Resp>(c), Ok(Some(Resp::Err(_)) | None) | Err(_))
}

pub fn job() -> (Kind, Body) {
    (
        Kind::Job,
        Body::Job {
            lane: "l".into(),
            label: "x".into(),
        },
    )
}

/// Both ends of a mesh on one machine, however it is carried.
pub struct World {
    pub user: Arc<UserKey>,
    pub home_bus: Arc<Bus>,
    pub remote_bus: Arc<Bus>,
    /// How the remote finds the home.
    pub peer: Peer,
}

/// The default carrier: iroh/QUIC on loopback, dialled directly.
pub async fn world() -> World {
    let user = Arc::new(UserKey::generate());
    let (home_bus, home_at) = node(&user, "home").await;
    let (remote_bus, _) = node(&user, "remote").await;
    World {
        user,
        home_bus,
        remote_bus,
        peer: Peer::Direct(home_at),
    }
}

// ---- scenarios ----

pub async fn enrol_and_emit(w: World) {
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
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

pub async fn replay_then_live(w: World) {
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
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

pub async fn renew_after_missed_epochs(w: World) {
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
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

pub async fn refusals_hold(w: World) {
    let h = home(&w.user, &w.home_bus, "f");
    let other = home(&w.user, &w.home_bus, "g");
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
    let b = attach(&w.user, &w.remote_bus, w.peer.clone(), &other).await;
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

pub async fn cited_file(w: World) {
    use agent_mesh_flock_session::{Cited, Files};
    let files = tempfile::tempdir().unwrap();
    std::fs::write(files.path().join("brief.md"), b"as cited").unwrap();
    let h = home_with_roots(
        &w.user,
        &w.home_bus,
        "f",
        Gate::new(Limits::default()),
        [("notes".to_owned(), files.path().to_owned())].into(),
    );
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
    let token = h.invite("h1");
    let sock = a.sock.clone();
    let dir = files.path().to_owned();
    blocking(move || {
        // the key is made here; the home never sees it
        let (_conn, key, _session, _pending) = enrol_by_hand(&sock, &token, "h1");
        let prove = |ch: &StreamChallenge| {
            Ok::<_, agent_mesh_flock_session::ReaderError>(Assertion::sign(&key, &ch.id().unwrap()))
        };
        let mut f = Files::open(&sock, &prove).unwrap();
        let cited = content_addressable::RawContentId::from_content(b"as cited");
        assert_eq!(f.stat("notes", "brief.md").unwrap(), Ok(cited));
        assert_eq!(
            f.read("notes", "brief.md", &cited).unwrap(),
            Cited::Bytes(b"as cited".to_vec())
        );
        std::fs::write(dir.join("brief.md"), b"edited").unwrap();
        assert!(matches!(
            f.read("notes", "brief.md", &cited).unwrap(),
            Cited::Changed { .. }
        ));
        assert_eq!(
            f.read("notes", "../brief.md", &cited).unwrap(),
            Cited::Unavailable("outside the root".into())
        );
    })
    .await;
}
