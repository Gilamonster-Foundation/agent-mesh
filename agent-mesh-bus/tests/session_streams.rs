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
