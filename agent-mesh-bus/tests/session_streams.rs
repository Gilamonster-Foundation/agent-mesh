//! Session streams (#84) over the REAL iroh transport: loopback QUIC, direct
//! dial, no mDNS. The frame protocol, ordering and failure semantics are
//! covered deterministically over in-memory pipes in `session.rs`; these
//! ground that pipe against a QUIC bidi stream — its handover from the accept
//! loop, its flow control, and its teardown when a bus closes.

use agent_mesh_bus::{Bus, BusError, BusOptions, IncomingSession, MeshNet, PeerEndpoint, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

fn agent(user: &UserKey, role: &str, capability: &str) -> AgentKey {
    AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "test".into(),
            capabilities: vec![capability.into()],
            issued_at: "2026-09-29T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    )
}

async fn quiet(user: &UserKey, agent: AgentKey) -> Bus {
    Bus::bind_with(user, agent, 0, BusOptions { announce: false })
        .await
        .unwrap()
}

fn loopback(pubkey: [u8; 32], bus: &Bus) -> PeerEndpoint {
    PeerEndpoint::new(
        pubkey,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bus.local_port()),
    )
}

/// The responder authorizes each open from the opener's verified
/// certificate, pushes a greeting before it is asked anything, then echoes.
fn serve_chat(bus: &Bus, topic: &Topic) {
    bus.handle_sessions(topic.clone(), |incoming: IncomingSession| async move {
        let caps = &incoming.peer().cert_chain.metadata.capabilities;
        if !caps.iter().any(|c| c == "chat") {
            return incoming.refuse("not authorized for chat").await;
        }
        let mut session = incoming.accept().await?;
        let who = session.peer().cert_chain.metadata.role.clone();
        session.send(format!("welcome {who}").into_bytes()).await?;
        while let Some(msg) = session.recv().await? {
            session.send([b"echo: ".as_slice(), &msg].concat()).await?;
        }
        Ok(())
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_over_quic_is_full_duplex_and_authorized_at_open() {
    let user = UserKey::generate();
    let bob = agent(&user, "bob", "serve");
    let bob_pubkey = bob.public_bytes();
    let bob_bus = quiet(&user, bob).await;
    let topic = Topic::new(user.fingerprint(), "chat");
    serve_chat(&bob_bus, &topic);
    let bob_at = loopback(bob_pubkey, &bob_bus);

    let alice_bus = quiet(&user, agent(&user, "alice", "chat")).await;
    let mut session = alice_bus.open_session_direct(bob_at, &topic).await.unwrap();
    assert_eq!(session.peer().agent_fp, bob_bus.agent_fingerprint());
    assert_eq!(session.recv().await.unwrap().unwrap(), b"welcome alice");
    for turn in ["one", "two", "three"] {
        session.send(turn.as_bytes().to_vec()).await.unwrap();
        let echo = session.recv().await.unwrap().unwrap();
        assert_eq!(echo, format!("echo: {turn}").into_bytes());
    }
    session.close().await.unwrap();

    let mallory_bus = quiet(&user, agent(&user, "mallory", "other")).await;
    match mallory_bus.open_session_direct(bob_at, &topic).await {
        Err(BusError::SessionRefused(reason)) => assert_eq!(reason, "not authorized for chat"),
        other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
    }
    let elsewhere = Topic::new(user.fingerprint(), "elsewhere");
    assert!(matches!(
        alice_bus.open_session_direct(bob_at, &elsewhere).await,
        Err(BusError::SessionRefused(_))
    ));

    for bus in [alice_bus, mallory_bus, bob_bus] {
        bus.close().await.unwrap();
    }
}

/// Closing the responder's bus ends its accepted session at both ends: the
/// handler's `recv` returns and its task finishes, and the opener sees the
/// session fail rather than hang.
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_bus_ends_the_sessions_it_serves() {
    let user = UserKey::generate();
    let bob = agent(&user, "bob", "serve");
    let bob_pubkey = bob.public_bytes();
    let bob_bus = quiet(&user, bob).await;
    let topic = Topic::new(user.fingerprint(), "chat");
    let (ended_tx, ended) = oneshot::channel();
    let ended_tx = std::sync::Mutex::new(Some(ended_tx));
    bob_bus.handle_sessions(topic.clone(), move |incoming: IncomingSession| {
        let ended_tx = ended_tx.lock().unwrap().take();
        async move {
            let mut session = incoming.accept().await?;
            let outcome = session.recv().await;
            if let Some(tx) = ended_tx {
                let _ = tx.send(outcome.map(|_| ()));
            }
            Ok(())
        }
    });

    let alice_bus = quiet(&user, agent(&user, "alice", "chat")).await;
    let bob_at = loopback(bob_pubkey, &bob_bus);
    let mut session = alice_bus.open_session_direct(bob_at, &topic).await.unwrap();
    bob_bus.close().await.unwrap();

    let handler = tokio::time::timeout(Duration::from_secs(10), ended).await;
    assert!(
        matches!(handler, Ok(Ok(Err(_)))),
        "the handler's session ends when its bus closes"
    );
    let opener = tokio::time::timeout(Duration::from_secs(10), session.recv()).await;
    assert!(matches!(opener, Ok(Err(_))), "the opener sees it fail");
    alice_bus.close().await.unwrap();
}

/// A consumer that stops reading stalls the responder's pushes through QUIC
/// flow control; nothing in the bus buffers them.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_session_consumer_holds_its_pushing_peer_back() {
    const FRAMES: usize = 16;
    const BODY: usize = 64 * 1024;
    let user = UserKey::generate();
    let bob = agent(&user, "bob", "serve");
    let bob_pubkey = bob.public_bytes();
    let bob_bus = quiet(&user, bob).await;
    let topic = Topic::new(user.fingerprint(), "feed");
    let pushed = Arc::new(AtomicUsize::new(0));
    let counter = pushed.clone();
    bob_bus.handle_sessions(topic.clone(), move |incoming: IncomingSession| {
        let counter = counter.clone();
        async move {
            let session = incoming.accept().await?;
            for _ in 0..FRAMES {
                session.send(vec![7; BODY]).await?;
                counter.fetch_add(1, Ordering::SeqCst);
            }
            session.close().await
        }
    });

    let alice_bus = quiet(&user, agent(&user, "alice", "feed")).await;
    let bob_at = loopback(bob_pubkey, &bob_bus);
    let mut session = alice_bus.open_session_direct(bob_at, &topic).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = pushed.load(Ordering::SeqCst);
    assert!(
        before < FRAMES,
        "an unread session pushed all {before} frames"
    );

    for _ in 0..FRAMES {
        assert_eq!(session.recv().await.unwrap().unwrap().len(), BODY);
    }
    assert_eq!(session.recv().await.unwrap(), None);
    assert_eq!(pushed.load(Ordering::SeqCst), FRAMES);
    alice_bus.close().await.unwrap();
    bob_bus.close().await.unwrap();
}

#[tokio::test]
async fn a_transport_without_streams_cannot_open_a_session() {
    let user = UserKey::generate();
    let (a, b) = (agent(&user, "a", "chat"), agent(&user, "b", "chat"));
    let b_fp = b.fingerprint();
    let net = MeshNet::new();
    let a_transport = Arc::new(net.transport_for(&a));
    let _b_transport = net.transport_for(&b);
    let bus = Bus::bind_with_transport(Arc::new(a), a_transport).unwrap();
    let topic = Topic::new(user.fingerprint(), "chat");
    assert!(matches!(
        bus.open_session(b_fp, &topic).await,
        Err(BusError::TransportBackend(_))
    ));
}
