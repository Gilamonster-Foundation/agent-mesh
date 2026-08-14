//! [`Transport`] — the seam between [`Bus`](crate::Bus) request/reply logic
//! and the wire that carries signed envelopes between peers.
//!
//! Production is iroh QUIC + mDNS ([`IrohTransport`]); tests wire two buses
//! together with an in-memory switchboard ([`InMemoryTransport`]) so the
//! request/reply/correlation/dial-back logic runs **deterministically** — no
//! sockets, no multicast discovery, no QUIC handshake timing. This is what lets
//! the bus-level round-trip be tested against implemented logic rather than the
//! whole transport stack (the flaky `request_reply_roundtrip` used real mDNS +
//! iroh and timed out on hosted CI runners).
//!
//! `Bus` owns the *policy* (sign + sequence the envelope, verify and bind the
//! inbound signer, register the reply waiter, run the inbox); the transport
//! owns delivery and must report the peer its session authenticated. The reply
//! route is an opaque [`ReplyRoute`] the transport alone interprets (iroh: the
//! dial-back key + address; in-memory: the sender's fingerprint).

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use agent_mesh_protocol::{AgentKey, Fingerprint, SignedEnvelope};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

use crate::bus::PeerEndpoint;
use crate::{BusError, Result};

/// An opaque, transport-specific handle for replying to an inbound envelope
/// over the exact route it arrived on (iroh dial-back; in-memory direct
/// channel). [`Bus`](crate::Bus) treats it as a black box and hands it back to
/// [`Transport::reply`].
pub type ReplyRoute = Arc<dyn Any + Send + Sync>;

/// The peer identity authenticated by the transport carrying an envelope.
///
/// This is the **carrier**, not necessarily the original envelope signer. A
/// direct delivery requires them to be identical; a future relay design can
/// add a separate provenance variant without silently treating a relay as the
/// signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    /// User root authenticated for the carrier session.
    pub user_fp: Fingerprint,
    /// Agent identity authenticated for the carrier session.
    pub agent_fp: Fingerprint,
}

impl AuthenticatedPeer {
    /// Record the user + agent identity a transport authenticated.
    ///
    /// Implementors of [`Transport`] must construct this only from their
    /// authenticated session state, never from an envelope's claimed signer.
    #[must_use]
    pub fn new(user_fp: Fingerprint, agent_fp: Fingerprint) -> Self {
        Self { user_fp, agent_fp }
    }

    fn for_agent(agent: &AgentKey) -> Self {
        Self::new(agent.cert().user_fingerprint(), agent.fingerprint())
    }
}

/// How a transport says an envelope reached the bus admission boundary.
///
/// Missing authentication is represented explicitly and rejected by the bus.
/// Only direct delivery exists today. A future authorized-relay variant must
/// keep its authenticated carrier separate from the envelope's original
/// signer and define its own admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryProvenance {
    /// The transport directly authenticated `carrier` for this delivery.
    Direct {
        /// Peer authenticated by the transport session.
        carrier: AuthenticatedPeer,
    },
    /// No peer identity was bound to the delivery.
    Unbound,
}

/// One inbound envelope, its authenticated delivery provenance, and the route
/// to reply to its sender.
pub struct Inbound {
    /// The signed envelope as it arrived. The common bus boundary verifies it
    /// independently of any transport-specific checks.
    pub envelope: SignedEnvelope,
    /// Typed evidence about the transport-authenticated carrier.
    pub provenance: DeliveryProvenance,
    /// Opaque route to reply back to the sender (see [`ReplyRoute`]).
    pub reply_route: ReplyRoute,
}

/// The wire a [`Bus`](crate::Bus) sends and receives signed envelopes over.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Deliver `env` to the peer named by `fp` (resolve + dial in production).
    async fn send_to(&self, fp: Fingerprint, env: SignedEnvelope) -> Result<()>;

    /// Deliver `env` to a known endpoint (no resolution / discovery).
    async fn send_to_endpoint(&self, peer: &PeerEndpoint, env: SignedEnvelope) -> Result<()>;

    /// Deliver a reply `env` to `fp`, preferring the inbound `route`
    /// (dial-back) and falling back to resolving `fp`.
    async fn reply(&self, fp: Fingerprint, route: &ReplyRoute, env: SignedEnvelope) -> Result<()>;

    /// The next inbound envelope with typed carrier provenance, or `None` when
    /// the transport is closed. A transport without a peer binding must report
    /// [`DeliveryProvenance::Unbound`], which the bus rejects by default.
    async fn recv(&self) -> Option<Inbound>;

    /// Local port peers use to reach this bus (`0` when not socket-backed).
    fn local_port(&self) -> u16;

    /// Release resources (endpoint, discovery, switchboard registration).
    async fn close(&self);
}

// ── In-memory transport (test double) ───────────────────────────────────────

/// A process-local switchboard: the fabric that connects a set of
/// [`InMemoryTransport`]s. Each transport registers under its agent
/// [`Fingerprint`]; `send_to(fp)` looks the recipient up here and pushes the
/// envelope straight into its inbound queue. Cheap, deterministic, no sockets.
#[derive(Default)]
pub struct MeshNet {
    peers: Mutex<HashMap<Fingerprint, mpsc::UnboundedSender<Inbound>>>,
}

impl MeshNet {
    /// A fresh, empty switchboard.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Create a transport for `agent`, deriving its fixed carrier identity from
    /// the agent's certified key and registering it on this switchboard.
    pub fn transport_for(self: &Arc<Self>, agent: &AgentKey) -> InMemoryTransport {
        let me = AuthenticatedPeer::for_agent(agent);
        let (tx, rx) = mpsc::unbounded_channel();
        self.peers.lock().unwrap().insert(me.agent_fp, tx);
        InMemoryTransport {
            me,
            net: Arc::clone(self),
            inbound: AsyncMutex::new(rx),
        }
    }

    fn deliver(&self, to: Fingerprint, inbound: Inbound) -> Result<()> {
        let peers = self.peers.lock().unwrap();
        match peers.get(&to) {
            Some(tx) => tx.send(inbound).map_err(|_| {
                BusError::Unreachable(format!("in-memory peer {} has closed", to.short()))
            }),
            None => Err(BusError::Unreachable(format!(
                "in-memory peer {} is not on the mesh",
                to.short()
            ))),
        }
    }

    fn remove(&self, me: &Fingerprint) {
        self.peers.lock().unwrap().remove(me);
    }
}

/// One agent's leg of a [`MeshNet`] — a fully in-memory [`Transport`].
pub struct InMemoryTransport {
    me: AuthenticatedPeer,
    net: Arc<MeshNet>,
    inbound: AsyncMutex<mpsc::UnboundedReceiver<Inbound>>,
}

impl InMemoryTransport {
    /// Deliver `env` to `to`, tagging it with THIS transport's fingerprint as
    /// the reply route (so the recipient can reply straight back to us).
    fn push(&self, to: Fingerprint, env: SignedEnvelope) -> Result<()> {
        self.net.deliver(
            to,
            Inbound {
                envelope: env,
                provenance: DeliveryProvenance::Direct { carrier: self.me },
                reply_route: Arc::new(self.me.agent_fp),
            },
        )
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    async fn send_to(&self, fp: Fingerprint, env: SignedEnvelope) -> Result<()> {
        self.push(fp, env)
    }

    async fn send_to_endpoint(&self, peer: &PeerEndpoint, env: SignedEnvelope) -> Result<()> {
        // In-memory routing is by fingerprint; a "direct endpoint" resolves to
        // the same switchboard lookup (there is no separate address plane).
        self.push(peer.fingerprint(), env)
    }

    async fn reply(&self, fp: Fingerprint, _route: &ReplyRoute, env: SignedEnvelope) -> Result<()> {
        // In-memory has no dial-back/resolve distinction — the switchboard
        // reaches every registered peer directly.
        self.push(fp, env)
    }

    async fn recv(&self) -> Option<Inbound> {
        self.inbound.lock().await.recv().await
    }

    fn local_port(&self) -> u16 {
        0
    }

    async fn close(&self) {
        self.net.remove(&self.me.agent_fp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, Recipient, UserKey};

    fn agent(user: &UserKey, role: &str) -> AgentKey {
        AgentKey::issue(
            user,
            AgentMetadata {
                role: role.into(),
                host: "test".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        )
    }

    fn envelope(from: &AgentKey, to: Fingerprint, body: &[u8]) -> SignedEnvelope {
        SignedEnvelope::new(from, Recipient::Direct { agent_fp: to }, 1, body.to_vec())
    }

    #[tokio::test]
    async fn send_delivers_and_reply_route_round_trips() {
        let user = UserKey::generate();
        let a = agent(&user, "a");
        let b = agent(&user, "b");
        let (a_fp, b_fp) = (a.fingerprint(), b.fingerprint());
        let net = MeshNet::new();
        let ta = net.transport_for(&a);
        let tb = net.transport_for(&b);

        ta.send_to(b_fp, envelope(&a, b_fp, b"hi")).await.unwrap();
        let inbound = tb.recv().await.expect("b receives");
        assert_eq!(inbound.envelope.sender_agent_fp(), a_fp);
        assert_eq!(
            inbound.provenance,
            DeliveryProvenance::Direct {
                carrier: AuthenticatedPeer::new(user.fingerprint(), a_fp),
            },
            "the in-memory carrier evidence must describe the sending leg"
        );

        // b replies over the inbound route; it reaches a.
        tb.reply(a_fp, &inbound.reply_route, envelope(&b, a_fp, b"yo"))
            .await
            .unwrap();
        let back = ta.recv().await.expect("a receives reply");
        assert_eq!(back.envelope.sender_agent_fp(), b_fp);
    }

    #[tokio::test]
    async fn send_to_endpoint_routes_by_fingerprint() {
        let user = UserKey::generate();
        let a = agent(&user, "a");
        let b = agent(&user, "b");
        let b_fp = b.fingerprint();
        let net = MeshNet::new();
        let ta = net.transport_for(&a);
        let tb = net.transport_for(&b);

        let peer = PeerEndpoint::new(b.public_bytes(), "127.0.0.1:1".parse().unwrap());
        ta.send_to_endpoint(&peer, envelope(&a, b_fp, b"hi"))
            .await
            .unwrap();
        assert!(tb.recv().await.is_some(), "endpoint send reaches b");
    }

    #[tokio::test]
    async fn send_to_unregistered_peer_is_unreachable() {
        let user = UserKey::generate();
        let a = agent(&user, "a");
        let net = MeshNet::new();
        let ta = net.transport_for(&a);
        let phantom = Fingerprint([0x11u8; 32]);
        match ta.send_to(phantom, envelope(&a, phantom, b"x")).await {
            Err(BusError::Unreachable(_)) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
        assert_eq!(ta.local_port(), 0);
    }

    #[tokio::test]
    async fn a_closed_peer_no_longer_receives() {
        let user = UserKey::generate();
        let a = agent(&user, "a");
        let b = agent(&user, "b");
        let b_fp = b.fingerprint();
        let net = MeshNet::new();
        let ta = net.transport_for(&a);
        let tb = net.transport_for(&b);
        tb.close().await;
        match ta.send_to(b_fp, envelope(&a, b_fp, b"x")).await {
            Err(BusError::Unreachable(_)) => {}
            other => panic!("expected Unreachable after close, got {other:?}"),
        }
    }
}
