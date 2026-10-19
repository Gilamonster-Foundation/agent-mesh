//! The flock over the mesh, in one process on loopback: the home is a real
//! server with its attach socket and a bridge on a bus; the remote is a second
//! bus with the attach proxy, and real sessions and readers dial the proxy's
//! socket exactly as they dial the server's. Direct dial, no mDNS, no sleeps:
//! every wait is a blocking read or a server-side epoch wait.
//!
//! The scenarios shared with the other carriers live in `support`.
#![cfg(unix)]

mod support;

use agent_mesh_bus::{Bus, PeerEndpoint};
use agent_mesh_cli::flock_bridge::{
    fetch_genesis, pin_genesis, serve_home, serve_proxy, topic, Attachment, Gate, Limits, Peer,
};
use agent_mesh_flock::{Body, Kind, Member, Role};
use agent_mesh_flock_server::wire::{read_msg, write_msg, Req, Resp};
use agent_mesh_flock_server::{bind_private, init, load_genesis, InitSpec, Serving};
use agent_mesh_flock_session::{Policy, Session};
use agent_mesh_protocol::{AgentKey, Assertion, UserKey};
use content_addressable::{ContentAddressable as _, ContentId};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use support::*;

fn at(w: &World) -> PeerEndpoint {
    match w.peer {
        Peer::Direct(at) => at,
        Peer::Known(_) => unreachable!("the iroh world dials directly"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_session_enrols_with_a_token_from_home_and_emits_into_the_home_log() {
    enrol_and_emit(world().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_replays_through_the_proxy_and_then_follows_live() {
    replay_then_live(world().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_offline_across_two_bumps_renews_and_emits_and_an_ended_one_cannot() {
    renew_after_missed_epochs(world().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_refusals_hold_through_the_proxy_a_copied_cert_a_replayed_proof_pending_and_ended_sessions(
) {
    refusals_hold(world().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_member_reads_a_cited_file_through_the_proxy_and_a_changed_one_is_only_reported() {
    cited_file(world().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_is_not_offered_remotely_and_still_works_at_home() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
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
    let signed = fetch_genesis(&w.remote_bus, &Peer::Direct(at(&w)), &t)
        .await
        .unwrap();
    assert_eq!(
        signed.node.content_id().unwrap(),
        h.id,
        "the home's genesis"
    );
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("flock");
    let err = pin_genesis(&target, &other.id, &signed).err().unwrap();
    assert!(err.to_string().contains("not the"), "{err}");
    assert!(!target.exists(), "nothing was written");
    // the right id is accepted and verifies as the server's own file does
    let _att = pin_genesis(&target, &h.id, &signed).unwrap();
    assert_eq!(
        load_genesis(&target).unwrap().node.content_id().unwrap(),
        h.id
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_flocks_at_different_epochs_on_one_bus_each_stay_independent_when_one_is_bumped() {
    let w = world().await;
    let (a_home, b_home) = (
        home(&w.user, &w.home_bus, "a"),
        home(&w.user, &w.home_bus, "b"),
    );
    // one bus on each side, a topic per flock. Each session stream is its own
    // QUIC connection today, so this shows the flocks are independent, not that
    // they share a carrier.
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &a_home).await;
    let b = attach(&w.user, &w.remote_bus, w.peer.clone(), &b_home).await;
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
async fn a_connection_that_drops_without_goodbye_is_recorded_lost_at_home() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
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
        Peer::Direct(at(&w)),
        t,
        listener,
        Gate::new(Limits::default()),
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
    let signed = fetch_genesis(&w.remote_bus, &Peer::Direct(at(&w)), &real)
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
    let err = fetch_genesis(&w.remote_bus, &Peer::Direct(at(&w)), &hostile)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("exactly one wire message"),
        "{err}"
    );
}

// ---- the pin: verified in memory first, installed without replacing anything ----

/// A real signed genesis (and its flock id), from a throwaway flock on disk.
fn some_genesis(user: &UserKey, name: &str) -> (ContentId, agent_mesh_flock_server::SignedGenesis) {
    let dir = tempfile::tempdir().unwrap();
    let spec = InitSpec {
        name: name.into(),
        roster: vec![Member {
            name: "shep".into(),
            role: Role::Shepherd,
            devices: vec![],
            delegate: false,
        }],
        salt: name.into(),
        host: "h".into(),
        issued_at: "t".into(),
    };
    let id = init(dir.path(), user, spec).unwrap();
    (id, load_genesis(dir.path()).unwrap())
}

/// The same node (so the same id) with a signature by some other key.
fn with_a_bad_signature(
    g: &agent_mesh_flock_server::SignedGenesis,
    user: &UserKey,
) -> agent_mesh_flock_server::SignedGenesis {
    let other = agent(user, "not-the-server");
    agent_mesh_flock_server::SignedGenesis {
        node: g.node.clone(),
        sig: Assertion::sign(&other, &g.node.content_id().unwrap()),
    }
}

#[test]
fn a_bad_signature_on_the_right_node_touches_nothing_absent_or_present() {
    let user = UserKey::generate();
    let (id, good) = some_genesis(&user, "f");
    let bad = with_a_bad_signature(&good, &user);
    assert_eq!(bad.node.content_id().unwrap(), id, "the id still matches");

    // an absent destination stays absent: not even the directory is made
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("flock");
    let err = pin_genesis(&target, &id, &bad).err().unwrap();
    assert!(err.to_string().contains("does not verify"), "{err}");
    assert!(!target.exists());

    // an existing pin survives, byte for byte
    let att = pin_genesis(&target, &id, &good).unwrap();
    drop(att);
    let before = std::fs::read(target.join("genesis")).unwrap();
    assert!(pin_genesis(&target, &id, &bad).is_err());
    assert_eq!(std::fs::read(target.join("genesis")).unwrap(), before);
}

#[test]
fn an_existing_pin_for_another_flock_a_link_or_a_directory_is_never_replaced() {
    let user = UserKey::generate();
    let (id_a, a) = some_genesis(&user, "a");
    let (id_b, b) = some_genesis(&user, "b");
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("flock");
    drop(pin_genesis(&target, &id_a, &a).unwrap());
    let pin = std::fs::read(target.join("genesis")).unwrap();

    // flock B into A's directory: refused, A's pin intact
    let err = pin_genesis(&target, &id_b, &b).err().unwrap();
    assert!(err.to_string().contains("another flock"), "{err}");
    assert_eq!(std::fs::read(target.join("genesis")).unwrap(), pin);

    // the same flock again: kept exactly as it is (same file, not rewritten)
    use std::os::unix::fs::MetadataExt as _;
    let before = std::fs::metadata(target.join("genesis")).unwrap();
    drop(pin_genesis(&target, &id_a, &a).unwrap());
    let after = std::fs::metadata(target.join("genesis")).unwrap();
    assert_eq!(
        (before.ino(), before.mtime(), before.mtime_nsec()),
        (after.ino(), after.mtime(), after.mtime_nsec())
    );
    assert_eq!(std::fs::read(target.join("genesis")).unwrap(), pin);

    // a symlink where the pin goes: refused, and its target is not touched
    let fresh = root.path().join("trap");
    std::fs::create_dir(&fresh).unwrap();
    std::fs::set_permissions(&fresh, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let victim = root.path().join("victim");
    std::fs::write(&victim, b"precious").unwrap();
    std::os::unix::fs::symlink(&victim, fresh.join("genesis")).unwrap();
    let err = pin_genesis(&fresh, &id_a, &a).err().unwrap();
    assert!(err.to_string().contains("not a regular file"), "{err}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    // even a link to nowhere is not followed into existence
    std::fs::remove_file(fresh.join("genesis")).unwrap();
    let nowhere = root.path().join("nowhere");
    std::os::unix::fs::symlink(&nowhere, fresh.join("genesis")).unwrap();
    assert!(pin_genesis(&fresh, &id_a, &a).is_err());
    assert!(!nowhere.exists());

    // a directory where the pin goes is refused too
    std::fs::remove_file(fresh.join("genesis")).unwrap();
    std::fs::create_dir(fresh.join("genesis")).unwrap();
    assert!(pin_genesis(&fresh, &id_a, &a).is_err());
}

#[test]
fn a_new_pin_is_private_complete_and_leaves_no_litter_and_the_directory_must_be_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let user = UserKey::generate();
    let (id, g) = some_genesis(&user, "f");
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("flock");
    let _att = pin_genesis(&target, &id, &g).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&target), 0o700);
    assert_eq!(mode(&target.join("genesis")), 0o600);
    let mut names: Vec<String> = std::fs::read_dir(&target)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["attach.lock", "genesis"], "no temporary files left");
    assert_eq!(
        load_genesis(&target).unwrap().node.content_id().unwrap(),
        id
    );

    // a directory others can enter is refused
    let loose = root.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(pin_genesis(&loose, &id, &g).is_err());
    assert!(!loose.join("genesis").exists());
}

#[test]
fn a_second_attach_on_one_directory_is_refused_until_the_first_is_gone() {
    let user = UserKey::generate();
    let (id, g) = some_genesis(&user, "f");
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("flock");
    let first = pin_genesis(&target, &id, &g).unwrap();
    let err = pin_genesis(&target, &id, &g).err().unwrap();
    assert!(err.to_string().contains("already holds"), "{err}");
    assert!(Attachment::open(&target).is_err());
    drop(first);
    drop(Attachment::open(&target).unwrap());
}

// ---- the caps: counted before anything is connected, released when it ends ----

fn hello() -> Vec<u8> {
    let mut v = Vec::new();
    write_msg(&mut v, &Req::Hello).unwrap();
    v
}

/// Open a session to the home and have it answer once, so it is certainly
/// admitted and holds its place.
async fn open_and_hold(
    bus: &Bus,
    at: PeerEndpoint,
    t: &agent_mesh_bus::Topic,
) -> Result<agent_mesh_bus::Session, agent_mesh_bus::BusError> {
    let mut s = bus.open_session_direct(at, t).await?;
    s.send(hello()).await?;
    let _ = s.recv().await?;
    Ok(s)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_over_its_share_is_refused_before_the_backend_is_touched_and_capacity_comes_back() {
    let w = world().await;
    let gate = Gate::new(Limits {
        total: 8,
        per_peer: 1,
    });
    let h = home_gated(&w.user, &w.home_bus, "f", gate.clone());
    let t = topic(w.user.fingerprint(), &h.id);
    let first = open_and_hold(&w.remote_bus, at(&w), &t).await.unwrap();
    assert_eq!(gate.open(), 1);
    // the same peer again: refused, with the reason
    match open_and_hold(&w.remote_bus, at(&w), &t).await {
        Err(agent_mesh_bus::BusError::SessionRefused(why)) => {
            assert!(why.contains("too many"), "{why}");
        }
        other => panic!("an excess open was admitted: {:?}", other.map(|_| ())),
    }
    assert_eq!(gate.open(), 1, "the refusal took no place");
    // another peer (same user) still has its own share
    let (other_bus, _) = node(&w.user, "other").await;
    let second = open_and_hold(&other_bus, at(&w), &t).await.unwrap();
    assert_eq!(gate.open(), 2);
    // closing frees the place, and the same peer can open again
    first.close().await.unwrap();
    gate.wait_open_at_most(1).await;
    let again = open_and_hold(&w.remote_bus, at(&w), &t).await.unwrap();
    drop((second, again));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_total_is_capped_across_peers() {
    let w = world().await;
    let gate = Gate::new(Limits {
        total: 1,
        per_peer: 4,
    });
    let h = home_gated(&w.user, &w.home_bus, "f", gate.clone());
    let t = topic(w.user.fingerprint(), &h.id);
    let (other_bus, _) = node(&w.user, "other").await;
    let held = open_and_hold(&w.remote_bus, at(&w), &t).await.unwrap();
    assert!(matches!(
        open_and_hold(&other_bus, at(&w), &t).await,
        Err(agent_mesh_bus::BusError::SessionRefused(_))
    ));
    held.close().await.unwrap();
    gate.wait_open_at_most(0).await;
    open_and_hold(&other_bus, at(&w), &t).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_proxy_caps_its_local_connections_and_takes_them_back() {
    let w = world().await;
    let h = home(&w.user, &w.home_bus, "f");
    let t = topic(w.user.fingerprint(), &h.id);
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("run").join("serve.sock");
    let listener = bind_private(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let gate = Gate::new(Limits {
        total: 1,
        per_peer: 1,
    });
    let task = tokio::spawn(serve_proxy(
        w.remote_bus.clone(),
        Peer::Direct(at(&w)),
        t,
        listener,
        gate.clone(),
    ));
    let first = blocking({
        let sock = sock.clone();
        move || {
            let mut c = UnixStream::connect(&sock).unwrap();
            write_msg(&mut c, &Req::Hello).unwrap();
            assert!(matches!(
                read_msg::<Resp>(&mut c),
                Ok(Some(Resp::Hello { .. }))
            ));
            c // held open
        }
    })
    .await;
    assert_eq!(gate.open(), 1);
    // a second connection ends at once: no dial, no reply
    let refused = blocking({
        let sock = sock.clone();
        move || {
            let mut c = UnixStream::connect(&sock).unwrap();
            let _ = write_msg(&mut c, &Req::Hello);
            read_msg::<Resp>(&mut c)
        }
    })
    .await;
    assert!(matches!(refused, Ok(None) | Err(_)), "{refused:?}");
    // the first going away gives the place back, and a new connection works
    drop(first);
    gate.wait_open_at_most(0).await;
    let served = blocking(move || {
        let mut c = UnixStream::connect(&sock).unwrap();
        write_msg(&mut c, &Req::Hello).unwrap();
        matches!(read_msg::<Resp>(&mut c), Ok(Some(Resp::Hello { .. })))
    })
    .await;
    assert!(served);
    task.abort();
}

/// Open a watch over `sock`, read through the replay to `Caught` (the server
/// worker now waits for news), and hand back its connection.
fn watch_caught_up(sock: &Path, key: &AgentKey) -> UnixStream {
    let (mut c, _, proof) = stream_proof(sock, key);
    write_msg(
        &mut c,
        &Req::Watch {
            from: None,
            proof: Box::new(proof),
        },
    )
    .unwrap();
    while !matches!(read_msg::<Resp>(&mut c).unwrap(), Some(Resp::Caught { .. })) {}
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_watch_that_goes_away_ends_the_home_worker_and_its_place_not_only_the_place() {
    // One place for the member's session and one for a watch. A reader opens
    // a watch, catches up and disconnects over and over; nothing is ever
    // published and the server never stops. The place coming back is not
    // enough: the server's worker must be gone too, or repeats accumulate
    // threads while the gate looks empty.
    let w = world().await;
    let gate = Gate::new(Limits {
        total: 2,
        per_peer: 2,
    });
    let h = home_gated(&w.user, &w.home_bus, "f", gate.clone());
    let a = attach(&w.user, &w.remote_bus, w.peer.clone(), &h).await;
    let token = h.invite("h1");
    let sock = a.sock.clone();
    let (member_conn, key, _, _) = blocking(move || enrol_by_hand(&sock, &token, "h1")).await;
    let key = Arc::new(key);
    let baseline = h.serving().live_connections();
    assert_eq!(baseline, 1);
    for _ in 0..8 {
        let (sock, key) = (a.sock.clone(), key.clone());
        let watch = blocking(move || watch_caught_up(&sock, &key)).await;
        assert_eq!(gate.open(), 2);
        drop(watch);
        gate.wait_open_at_most(1).await;
        let serving = h.serving.as_ref().unwrap();
        blocking_ref(serving, baseline).await;
    }
    // and the proxy going away (cancelled) takes a caught-up watch with it
    let (sock, k2) = (a.sock.clone(), key.clone());
    let watch = blocking(move || watch_caught_up(&sock, &k2)).await;
    a.task.abort();
    gate.wait_open_at_most(1).await;
    blocking_ref(h.serving.as_ref().unwrap(), baseline).await;
    drop((watch, member_conn));
}

/// Wait, off the async workers, until the server has at most `n` connection
/// threads.
async fn blocking_ref(serving: &Serving, n: usize) {
    tokio::task::block_in_place(|| serving.wait_connections_at_most(n));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_home_place_is_held_until_the_backend_connection_is_closed() {
    // A backend that does not close until told. The remote goes away; the
    // bridge tells the backend it is done (the backend reads the end), and
    // the place must still be held: it covers the backend's worker, so it is
    // released only when the backend has closed its end.
    let w = world().await;
    let (id, _) = some_genesis(&w.user, "f");
    let t = topic(w.user.fingerprint(), &id);
    let dir = tempfile::tempdir().unwrap();
    let attach = dir.path().join("attach.sock");
    let listener = std::os::unix::net::UnixListener::bind(&attach).unwrap();
    let gate = Gate::new(Limits {
        total: 1,
        per_peer: 1,
    });
    serve_home(&w.home_bus, t.clone(), attach, gate.clone());
    // (the ordering itself is proved deterministically by
    // `ending_a_backend_waits_for_the_backend_to_close`; this is the same
    // through the real bridge)
    const ROUNDS: usize = 1;
    let (saw_end, mut saw_end_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let backend = std::thread::spawn(move || {
        for _ in 0..ROUNDS {
            let (mut c, _) = listener.accept().unwrap();
            let mut sink = [0u8; 64];
            while std::io::Read::read(&mut c, &mut sink).is_ok_and(|n| n > 0) {}
            let _ = saw_end.send(());
            let _ = release_rx.recv();
            // dropping `c` closes the backend's end
        }
    });
    for _ in 0..ROUNDS {
        let s = w.remote_bus.open_session_direct(at(&w), &t).await.unwrap();
        assert_eq!(gate.open(), 1);
        drop(s);
        saw_end_rx.recv().await.unwrap();
        assert_eq!(gate.open(), 1, "the place went before the backend closed");
        release.send(()).unwrap();
        gate.wait_open_at_most(0).await;
    }
    backend.join().unwrap();
}

#[tokio::test]
async fn ending_a_backend_waits_for_the_backend_to_close() {
    // The step that releases a place once a pipe has ended, driven by hand: a
    // backend that has been told we are done writing but has not closed. The
    // future must be pending exactly then (an omitted wait would be ready at
    // its first poll), and complete once the backend closes.
    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};
    let (ours, mut theirs) = tokio::net::UnixStream::pair().unwrap();
    let (from, to) = ours.into_split();
    let mut done = Box::pin(agent_mesh_cli::flock_bridge::end_backend(
        from,
        to,
        Err(anyhow::anyhow!("the remote went away")),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(done.as_mut().poll(&mut cx).is_pending());
    // the backend sees our end of writing, and still has not closed
    let mut buf = [0u8; 8];
    assert_eq!(
        tokio::io::AsyncReadExt::read(&mut theirs, &mut buf)
            .await
            .unwrap(),
        0
    );
    assert!(done.as_mut().poll(&mut cx).is_pending());
    // the backend closing completes it, and the original error is kept
    drop(theirs);
    let out = done.await;
    assert_eq!(out.unwrap_err().to_string(), "the remote went away");
    let _: Poll<()> = Poll::Pending;
}
