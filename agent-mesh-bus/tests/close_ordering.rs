//! What `Bus::close` has finished by the time it reaches the transport (#152).
//!
//! Releasing the socket is observable only after the endpoint is really closed,
//! by which point later awaits have given an un-awaited aborted task time to
//! disappear. These tests pin the ordering itself on the `Transport` seam: a
//! probe whose `close` records what had already happened. No clock, no socket.

use agent_mesh_bus::{
    AuthenticatedPeer, Bus, InMemoryTransport, Inbound, MeshNet, PeerEndpoint, ReplyRoute,
    SessionStream, Topic, Transport,
};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, Fingerprint, SignedEnvelope, UserKey};
use async_trait::async_trait;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::sync::mpsc;

fn agent(user: &UserKey, role: &str) -> Arc<AgentKey> {
    Arc::new(AgentKey::issue(
        user,
        AgentMetadata {
            role: role.into(),
            host: "test".into(),
            capabilities: vec!["test".into()],
            issued_at: "2026-10-19T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        },
    ))
}

/// The in-memory transport, except that `close` first records whether `probe`
/// held when it was reached.
struct Probe {
    inner: InMemoryTransport,
    probe: Box<dyn Fn() -> bool + Send + Sync>,
    held: Arc<AtomicBool>,
    reached: Arc<AtomicBool>,
}

#[async_trait]
impl Transport for Probe {
    async fn send_to(&self, fp: Fingerprint, env: SignedEnvelope) -> agent_mesh_bus::Result<()> {
        self.inner.send_to(fp, env).await
    }
    async fn send_to_endpoint(
        &self,
        peer: &PeerEndpoint,
        env: SignedEnvelope,
    ) -> agent_mesh_bus::Result<()> {
        self.inner.send_to_endpoint(peer, env).await
    }
    async fn reply(
        &self,
        fp: Fingerprint,
        route: &ReplyRoute,
        env: SignedEnvelope,
    ) -> agent_mesh_bus::Result<()> {
        self.inner.reply(fp, route, env).await
    }
    async fn open_stream_to(
        &self,
        fp: Fingerprint,
    ) -> agent_mesh_bus::Result<(AuthenticatedPeer, SessionStream)> {
        self.inner.open_stream_to(fp).await
    }
    async fn recv(&self) -> Option<Inbound> {
        self.inner.recv().await
    }
    fn local_port(&self) -> u16 {
        self.inner.local_port()
    }
    async fn close(&self) {
        self.held.store((self.probe)(), Ordering::SeqCst);
        self.reached.store(true, Ordering::SeqCst);
        self.inner.close().await;
    }
}

/// Sets the flag when dropped: the handler future is gone.
struct Gone(Arc<AtomicBool>);
impl Drop for Gone {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A bob bus on a probing transport with a request handler that has started and
/// never finishes, holding a `Gone` guard. Returns once the handler is running.
struct Fixture {
    bob: Bus,
    _alice: Arc<Bus>,
    handler_gone: Arc<AtomicBool>,
    close_saw_handler_gone: Arc<AtomicBool>,
    close_reached: Arc<AtomicBool>,
}

async fn fixture() -> Fixture {
    let user = UserKey::generate();
    let (alice, bob) = (agent(&user, "alice"), agent(&user, "bob"));
    let net = MeshNet::new();
    let alice_bus = Arc::new(
        Bus::bind_with_transport(alice.clone(), Arc::new(net.transport_for(&alice))).unwrap(),
    );
    let handler_gone = Arc::new(AtomicBool::new(false));
    let (held, reached) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let gone = handler_gone.clone();
    let bob_bus = Bus::bind_with_transport(
        bob.clone(),
        Arc::new(Probe {
            inner: net.transport_for(&bob),
            probe: Box::new(move || gone.load(Ordering::SeqCst)),
            held: held.clone(),
            reached: reached.clone(),
        }),
    )
    .unwrap();

    let topic = Topic::new(user.fingerprint(), "stuck");
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel::<()>();
    let flag = handler_gone.clone();
    bob_bus.handle_requests(topic.clone(), move |_| {
        let (entered, guard) = (entered_tx.clone(), Gone(flag.clone()));
        async move {
            let _guard = guard;
            let _ = entered.send(());
            std::future::pending::<()>().await;
            Ok(Vec::new())
        }
    });
    let bob_fp = bob.fingerprint();
    let alice_ask = alice_bus.clone();
    tokio::spawn(async move {
        let _ = alice_ask
            .request(bob_fp, &topic, b"x".to_vec(), Duration::from_secs(600))
            .await;
    });
    entered_rx.recv().await.expect("the handler started");
    Fixture {
        bob: bob_bus,
        _alice: alice_bus,
        handler_gone,
        close_saw_handler_gone: held,
        close_reached: reached,
    }
}

/// The handler's future is destroyed before `close` reaches the transport. The
/// current-thread runtime means nothing else runs between close's awaits, so a
/// close that stopped waiting for the aborted task would reach the transport
/// with the handler still alive.
#[tokio::test]
async fn close_destroys_the_running_handlers_before_it_closes_the_transport() {
    let f = fixture().await;
    assert!(!f.handler_gone.load(Ordering::SeqCst));
    f.bob.close().await.unwrap();
    assert!(
        f.close_reached.load(Ordering::SeqCst),
        "the transport was closed"
    );
    assert!(
        f.close_saw_handler_gone.load(Ordering::SeqCst),
        "close reached the transport while a handler was still alive"
    );
}

/// `close` is not done until the bus loop has been driven: polled by hand with
/// nothing else running, it stays pending and has not touched the transport; once
/// the loop gets to run, it finishes and the transport is closed after it.
#[tokio::test]
async fn close_stays_pending_until_the_bus_loop_has_stopped() {
    let f = fixture().await;
    let mut close = Box::pin(f.bob.close());
    let mut cx = Context::from_waker(Waker::noop());
    // one poll, no yield: no other task (the loop included) has run
    assert!(matches!(close.as_mut().poll(&mut cx), Poll::Pending));
    assert!(
        !f.close_reached.load(Ordering::SeqCst),
        "close reached the transport without waiting for the bus loop"
    );
    close.await.unwrap();
    assert!(f.close_reached.load(Ordering::SeqCst));
    assert!(f.close_saw_handler_gone.load(Ordering::SeqCst));
}
