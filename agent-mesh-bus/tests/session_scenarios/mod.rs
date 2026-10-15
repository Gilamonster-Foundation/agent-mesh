//! Session-stream scenarios shared by every transport that carries streams.
//!
//! The frame protocol and failure semantics are covered over in-memory pipes
//! in `session.rs`; these ground that pipe against a real transport. Each
//! transport supplies a [`Fabric`] and wraps these in its own `#[tokio::test]`s
//! (iroh: `tests/session_streams.rs`; SSH: the transport crate's unit tests).

#![allow(dead_code)] // each transport wraps only what it needs

use agent_mesh_bus::{Bus, BusError, IncomingSession, PeerEndpoint, Topic};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// One participant: its bus, where peers dial it, and whatever the fabric
/// needs to wire it to others.
pub struct Node {
    pub bus: Bus,
    pub at: PeerEndpoint,
    pub handle: Option<Arc<dyn Any + Send + Sync>>,
}

pub type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How a transport under test builds nodes and lets one dial another.
pub trait Fabric: Sync {
    fn node<'a>(&'a self, user: &'a UserKey, agent: AgentKey) -> Boxed<'a, Node>;
    /// Make `to` reachable from `from` (a no-op where dialing is by address).
    fn link(&self, from: &Node, to: &Node);
}

pub fn agent(user: &UserKey, role: &str, capability: &str) -> AgentKey {
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

pub async fn full_duplex_and_authorized_at_open(fab: &dyn Fabric) {
    let user = UserKey::generate();
    let bob = fab.node(&user, agent(&user, "bob", "serve")).await;
    let topic = Topic::new(user.fingerprint(), "chat");
    serve_chat(&bob.bus, &topic);

    let alice = fab.node(&user, agent(&user, "alice", "chat")).await;
    fab.link(&alice, &bob);
    let mut session = alice.bus.open_session_direct(bob.at, &topic).await.unwrap();
    assert_eq!(session.peer().agent_fp, bob.bus.agent_fingerprint());
    assert_eq!(session.recv().await.unwrap().unwrap(), b"welcome alice");
    for turn in ["one", "two", "three"] {
        session.send(turn.as_bytes().to_vec()).await.unwrap();
        let echo = session.recv().await.unwrap().unwrap();
        assert_eq!(echo, format!("echo: {turn}").into_bytes());
    }
    session.close().await.unwrap();

    let mallory = fab.node(&user, agent(&user, "mallory", "other")).await;
    fab.link(&mallory, &bob);
    match mallory.bus.open_session_direct(bob.at, &topic).await {
        Err(BusError::SessionRefused(reason)) => assert_eq!(reason, "not authorized for chat"),
        other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
    }
    let elsewhere = Topic::new(user.fingerprint(), "elsewhere");
    assert!(matches!(
        alice.bus.open_session_direct(bob.at, &elsewhere).await,
        Err(BusError::SessionRefused(_))
    ));

    for node in [alice, mallory, bob] {
        node.bus.close().await.unwrap();
    }
}

/// Closing the responder's bus ends its accepted session at both ends: the
/// handler's `recv` returns and its task finishes, and the opener sees the
/// session fail rather than hang.
pub async fn closing_a_bus_ends_the_sessions_it_serves(fab: &dyn Fabric) {
    let user = UserKey::generate();
    let bob = fab.node(&user, agent(&user, "bob", "serve")).await;
    let topic = Topic::new(user.fingerprint(), "chat");
    let (ended_tx, ended) = oneshot::channel();
    let ended_tx = std::sync::Mutex::new(Some(ended_tx));
    bob.bus
        .handle_sessions(topic.clone(), move |incoming: IncomingSession| {
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

    let alice = fab.node(&user, agent(&user, "alice", "chat")).await;
    fab.link(&alice, &bob);
    let mut session = alice.bus.open_session_direct(bob.at, &topic).await.unwrap();
    bob.bus.close().await.unwrap();

    let handler = tokio::time::timeout(Duration::from_secs(10), ended).await;
    assert!(
        matches!(handler, Ok(Ok(Err(_)))),
        "the handler's session ends when its bus closes"
    );
    let opener = tokio::time::timeout(Duration::from_secs(10), session.recv()).await;
    assert!(matches!(opener, Ok(Err(_))), "the opener sees it fail");
    alice.bus.close().await.unwrap();
}

/// A consumer that stops reading stalls the responder's pushes through the
/// transport's flow control; nothing in the bus buffers them.
pub async fn a_stalled_consumer_holds_its_pushing_peer_back(fab: &dyn Fabric) {
    const FRAMES: usize = 16;
    const BODY: usize = 64 * 1024;
    let user = UserKey::generate();
    let bob = fab.node(&user, agent(&user, "bob", "serve")).await;
    let topic = Topic::new(user.fingerprint(), "feed");
    let pushed = Arc::new(AtomicUsize::new(0));
    let counter = pushed.clone();
    bob.bus
        .handle_sessions(topic.clone(), move |incoming: IncomingSession| {
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

    let alice = fab.node(&user, agent(&user, "alice", "feed")).await;
    fab.link(&alice, &bob);
    let mut session = alice.bus.open_session_direct(bob.at, &topic).await.unwrap();
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
    alice.bus.close().await.unwrap();
    bob.bus.close().await.unwrap();
}

/// The opener finishes sending (`SessionSender::close`, a send-half shutdown)
/// and must still receive the peer's later, final envelope.
pub async fn a_closed_send_half_still_receives_the_final_response(fab: &dyn Fabric) {
    let user = UserKey::generate();
    let bob = fab.node(&user, agent(&user, "bob", "serve")).await;
    let topic = Topic::new(user.fingerprint(), "batch");
    bob.bus
        .handle_sessions(topic.clone(), |incoming: IncomingSession| async move {
            let mut session = incoming.accept().await?;
            let mut seen = 0usize;
            while session.recv().await?.is_some() {
                seen += 1;
            }
            session
                .send(format!("final after {seen}").into_bytes())
                .await?;
            session.close().await
        });

    let alice = fab.node(&user, agent(&user, "alice", "batch")).await;
    fab.link(&alice, &bob);
    let session = alice.bus.open_session_direct(bob.at, &topic).await.unwrap();
    let (tx, mut rx) = session.split();
    tx.send(b"a".to_vec()).await.unwrap();
    tx.send(b"b".to_vec()).await.unwrap();
    tx.close().await.unwrap();

    let last = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await;
    assert_eq!(last.unwrap().unwrap().unwrap(), b"final after 2");
    assert_eq!(rx.recv().await.unwrap(), None);
    alice.bus.close().await.unwrap();
    bob.bus.close().await.unwrap();
}
