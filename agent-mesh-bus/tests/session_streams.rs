//! Session streams (#84) over the REAL iroh transport: loopback QUIC, direct
//! dial, no mDNS. The frame protocol, ordering and failure semantics are
//! covered deterministically over in-memory pipes in `session.rs`; these
//! ground that pipe against a QUIC bidi stream — its handover from the accept
//! loop, its flow control, and its teardown when a bus closes.

use agent_mesh_bus::RevocationGuard;
use agent_mesh_bus::{Bus, BusError, BusOptions, MeshNet, PeerEndpoint, Topic};
use agent_mesh_protocol::{AgentKey, UserKey};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

mod session_scenarios;
use session_scenarios::{agent, Boxed, Fabric, Node};

struct Iroh;

impl Fabric for Iroh {
    fn node<'a>(&'a self, user: &'a UserKey, agent: AgentKey) -> Boxed<'a, Node> {
        Box::pin(async move {
            let pubkey = agent.public_bytes();
            let bus = Bus::bind_with(
                user,
                agent,
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
            Node {
                bus,
                at,
                handle: None,
            }
        })
    }

    fn link(&self, _from: &Node, _to: &Node) {}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_over_quic_is_full_duplex_and_authorized_at_open() {
    session_scenarios::full_duplex_and_authorized_at_open(&Iroh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_bus_ends_the_sessions_it_serves() {
    session_scenarios::closing_a_bus_ends_the_sessions_it_serves(&Iroh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_session_consumer_holds_its_pushing_peer_back() {
    session_scenarios::a_stalled_consumer_holds_its_pushing_peer_back(&Iroh).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_send_half_still_receives_the_final_response_over_quic() {
    session_scenarios::a_closed_send_half_still_receives_the_final_response(&Iroh).await;
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

/// A revocation the log learns mid-session ends the revoked peer's session
/// before its next envelope reaches the handler: the handler's `recv` fails
/// instead of delivering "two", and the revoked side never sees an echo of it.
/// Red before session streams re-checked the log.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_connected_peer_ends_its_session_before_its_next_envelope() {
    use agent_mesh_protocol::{RevocationEntry, RevocationLog};
    use std::time::Duration;

    let user = UserKey::generate();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revocation.json");
    let mut log = RevocationLog::genesis(&user).unwrap();
    std::fs::write(&path, serde_json::to_vec(&log).unwrap()).unwrap();

    let (bob_agent, alice_agent) = (agent(&user, "bob", "serve"), agent(&user, "alice", "chat"));
    let alice_fp = alice_agent.fingerprint();
    let bob_pubkey = bob_agent.public_bytes();
    let guard = RevocationGuard::open(&path, user.fingerprint()).unwrap();
    let opts = BusOptions { announce: false };
    let bob = Bus::bind_with(&user, bob_agent, 0, opts.clone(), guard)
        .await
        .unwrap();
    let alice = Bus::bind_with(
        &user,
        alice_agent,
        0,
        opts,
        RevocationGuard::in_memory(&user),
    )
    .await
    .unwrap();
    let at = PeerEndpoint::new(
        bob_pubkey,
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bob.local_port()),
    );

    let topic = Topic::new(user.fingerprint(), "chat");
    let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
    bob.handle_sessions(topic.clone(), move |incoming| {
        let seen_tx = seen_tx.clone();
        async move {
            let mut session = incoming.accept().await?;
            loop {
                let got = session.recv().await;
                let _ = seen_tx.send(got.as_ref().map(Clone::clone).map_err(|e| e.to_string()));
                match got {
                    Ok(Some(msg)) => session.send(msg).await?,
                    _ => return Ok(()),
                }
            }
        }
    });

    let bounded = Duration::from_secs(10);
    let mut session = alice.open_session_direct(at, &topic).await.unwrap();
    session.send(b"one".to_vec()).await.unwrap();
    let echo = tokio::time::timeout(bounded, session.recv()).await;
    assert_eq!(echo.unwrap().unwrap().unwrap(), b"one");
    assert_eq!(seen.recv().await.unwrap().unwrap().unwrap(), b"one");

    log.append(&user, RevocationEntry::Revoke { agent: alice_fp })
        .unwrap();
    std::fs::write(&path, serde_json::to_vec(&log).unwrap()).unwrap();

    let _ = session.send(b"two".to_vec()).await;
    let handler = tokio::time::timeout(bounded, seen.recv()).await.unwrap();
    assert!(
        matches!(handler, Some(Err(_))),
        "the handler must see the session fail, not the message: {handler:?}"
    );
    let echo = tokio::time::timeout(bounded, session.recv()).await.unwrap();
    assert!(
        !matches!(echo, Ok(Some(_))),
        "the revoked peer must not get an echo: {echo:?}"
    );
    alice.close().await.unwrap();
    bob.close().await.unwrap();
}
