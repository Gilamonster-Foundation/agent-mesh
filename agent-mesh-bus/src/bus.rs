//! [`Bus`] — the high-level message-bus type.
//!
//! Stitches together:
//!
//! * [`Endpoint`] (transport) — QUIC + ALPN + cert handshake,
//! * [`PeerResolver`] (transport) — mDNS-discovered peers, looked up
//!   by [`Fingerprint`],
//! * [`Inbox`] (this crate) — verifies + dispatches each incoming
//!   envelope into a request handler, a reply waiter, or a topic
//!   subscription.
//!
//! What the caller sees is a small surface: [`Bus::bind`], plus
//! [`Bus::request`], [`Bus::handle_requests`], [`Bus::publish_to`],
//! [`Bus::subscribe`], [`Bus::close`].
//!
//! Connection model: this version **dials per outbound message**.
//! Connection reuse is a follow-up. The cost is one QUIC handshake
//! per message; the benefit is that the bus has no per-peer state
//! to clean up when a peer disappears, and the inbox routes replies
//! by correlation id (not by connection), so a reply arriving on a
//! freshly-dialed reverse connection works exactly the same.
//!
//! Replies prefer **dial-back over mDNS**: the request connection's
//! TLS-authenticated remote key doubles as the sender's agent pubkey,
//! so the responder dials the observed source address directly and
//! only falls back to mDNS resolution if that dial fails. This keeps
//! replies working when the asker's announce hasn't propagated yet
//! (cold-start race) or when the asker never announces at all (a
//! quiet [`BusOptions`] bind).

use crate::inbox::{BusMessage, Inbox, OutgoingReply};
use crate::reply::CorrelationId;
use crate::{BusError, Result, Topic};
use agent_mesh_discovery::{AnnounceConfig, Announcer, AnnouncerHandle};
use agent_mesh_protocol::{AgentKey, CertChain, Fingerprint, Recipient, SignedEnvelope, UserKey};
use agent_mesh_transport::{
    do_handshake,
    identity::agent_pubkey_to_iroh,
    iroh_reexports::{Connection, Incoming, IncomingAddr, PublicKey},
    recv_envelope, send_envelope, Endpoint, PeerResolver, ResolverHandle, TransportError,
};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// How long we'll wait for a peer to appear on mDNS before giving up.
///
/// mDNS announcements typically arrive within a few hundred ms on a
/// quiet LAN; 5s is generous enough to absorb daemon startup jitter
/// without making a missing-peer test slow.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on the handshake half of a connection. Keeps a stalled peer
/// from pinning a stream forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Options for [`Bus::bind_with`].
#[derive(Debug, Clone)]
pub struct BusOptions {
    /// Announce this bus over mDNS so peers can resolve it by
    /// fingerprint (the default). Quiet binds (`false`) are for
    /// ephemeral clients that only dial out — peers can still reply
    /// to them via dial-back on the connection the request arrived on.
    pub announce: bool,
}

impl Default for BusOptions {
    fn default() -> Self {
        Self { announce: true }
    }
}

/// An explicit dial route to a known peer — its ed25519 agent pubkey
/// plus one socket address — used to reach a peer **without mDNS
/// discovery**.
///
/// This is the building block for the WAN / WireGuard phase of the
/// mesh: mDNS is LAN-multicast only, but over a VPN the client already
/// has L3 reachability to a known agent's `SocketAddr`, so it dials by
/// endpoint instead of resolving a fingerprint over multicast.
///
/// Note the dial route carries the **agent pubkey**, not just a
/// [`Fingerprint`]. A fingerprint is `blake3(agent_pubkey)` — a
/// one-way hash — so it cannot be turned back into the iroh node
/// identity QUIC needs to dial. The [`Fingerprint`] used for envelope
/// addressing is *derived from* the pubkey here
/// ([`Self::fingerprint`]), so a caller who knows the pubkey + address
/// has everything required. (This mirrors the reply dial-back path,
/// which likewise takes the peer's TLS-authenticated pubkey + observed
/// address from the request connection.)
#[derive(Debug, Clone, Copy)]
pub struct PeerEndpoint {
    /// The peer agent's raw 32-byte ed25519 public key.
    pub agent_pubkey: [u8; 32],
    /// A socket address the peer is reachable at (e.g. its WireGuard
    /// tunnel IP + UDP port).
    pub addr: SocketAddr,
}

impl PeerEndpoint {
    /// Build a dial route from the peer's agent pubkey and a single
    /// `SocketAddr`.
    #[must_use]
    pub fn new(agent_pubkey: [u8; 32], addr: SocketAddr) -> Self {
        Self { agent_pubkey, addr }
    }

    /// Build a dial route from the peer's agent pubkey, an IP, and a
    /// port. Convenience for callers holding the parts separately.
    #[must_use]
    pub fn from_parts(agent_pubkey: [u8; 32], ip: IpAddr, port: u16) -> Self {
        Self::new(agent_pubkey, SocketAddr::new(ip, port))
    }

    /// The peer's agent fingerprint, derived as `blake3(agent_pubkey)`
    /// — the same value the peer announces over mDNS and signs its
    /// envelopes under. Used for the envelope `Recipient` address so a
    /// directly-dialed message is indistinguishable on the wire from a
    /// resolver-dialed one.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_bytes(&self.agent_pubkey)
    }
}

/// The high-level message bus.
///
/// One `Bus` per process — owns the bound QUIC endpoint, the mDNS
/// resolver, the inbox, and the accept loop. Drop or [`Self::close`]
/// to release resources.
pub struct Bus {
    agent: Arc<AgentKey>,
    user_fp: Fingerprint,
    endpoint: Arc<Endpoint>,
    resolver: Arc<PeerResolver>,
    inbox: Arc<Inbox>,
    sequence: Arc<AtomicU64>,
    local_port: u16,
    /// Keeps the mDNS browser thread alive for the life of the bus.
    _resolver_handle: ResolverHandle,
    /// Keeps the mDNS announcer alive (so peers can discover us).
    /// `None` for a quiet bind ([`BusOptions::announce`] = false).
    _announcer: Option<AnnouncerHandle>,
    accept_task: JoinHandle<()>,
}

impl Bus {
    /// Bind a bus on `port` (use `0` for an OS-picked port). Starts
    /// the mDNS resolver and the accept loop.
    ///
    /// Returns once the endpoint is bound, the resolver is running,
    /// and the accept task is spawned — the bus is immediately ready
    /// to send and receive.
    pub async fn bind(user: &UserKey, agent: AgentKey, port: u16) -> Result<Self> {
        Self::bind_with(user, agent, port, BusOptions::default()).await
    }

    /// Bind a bus with explicit [`BusOptions`]. See [`Self::bind`].
    pub async fn bind_with(
        user: &UserKey,
        agent: AgentKey,
        port: u16,
        opts: BusOptions,
    ) -> Result<Self> {
        let user_fp = user.fingerprint();
        let endpoint = Endpoint::bind(&agent, port).await?;
        let local_port = endpoint.port();
        let endpoint = Arc::new(endpoint);
        let (resolver, resolver_handle) = PeerResolver::start()?;
        let resolver = Arc::new(resolver);
        let inbox = Arc::new(Inbox::new());
        let agent = Arc::new(agent);
        let sequence = Arc::new(AtomicU64::new(1));

        let announcer = if opts.announce {
            Some(
                Announcer::start(AnnounceConfig {
                    agent_fp: agent.fingerprint(),
                    agent_pubkey: Some(agent.public_bytes()),
                    user_fp,
                    capabilities: agent.cert().metadata.capabilities.clone(),
                    role: agent.cert().metadata.role.clone(),
                    host: agent.cert().metadata.host.clone(),
                    port: local_port,
                })
                .map_err(|e| {
                    BusError::Transport(TransportError::Iroh(format!("announce start: {e}")))
                })?,
            )
        } else {
            None
        };

        let accept_task = spawn_accept_loop(
            endpoint.clone(),
            agent.clone(),
            inbox.clone(),
            resolver.clone(),
            sequence.clone(),
        );

        Ok(Self {
            agent,
            user_fp,
            endpoint,
            resolver,
            inbox,
            sequence,
            local_port,
            _resolver_handle: resolver_handle,
            _announcer: announcer,
            accept_task,
        })
    }

    /// User fingerprint this bus belongs to.
    #[must_use]
    pub fn user_fingerprint(&self) -> Fingerprint {
        self.user_fp
    }

    /// Agent fingerprint this bus runs as.
    #[must_use]
    pub fn agent_fingerprint(&self) -> Fingerprint {
        self.agent.fingerprint()
    }

    /// Local UDP port the iroh endpoint is bound on.
    #[must_use]
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Send a `Request` to `peer_fp` on `topic` and wait up to
    /// `timeout` for the matching `Reply`.
    ///
    /// Resolves `peer_fp` over mDNS before dialing. Returns the reply
    /// body on success. On timeout returns [`BusError::Timeout`]; on
    /// peer-not-found, [`BusError::Unreachable`].
    pub async fn request(
        &self,
        peer_fp: Fingerprint,
        topic: &Topic,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.request_via(DialRoute::Resolve(peer_fp), topic, body, timeout)
            .await
    }

    /// Send a `Request` directly to a known [`PeerEndpoint`] — its
    /// agent pubkey + socket address — **without mDNS discovery** —
    /// and wait up to `timeout` for the matching `Reply`.
    ///
    /// This is the WAN / WireGuard dial path: the caller already knows
    /// where the agent lives (e.g. its VPN tunnel address), so the
    /// resolver is skipped entirely and the bus dials the endpoint
    /// straight away. The reply routes back over the freshly-dialed
    /// reverse connection by correlation id, exactly as a
    /// resolver-dialed request would.
    ///
    /// The on-wire envelope is identical to one sent via [`request`]:
    /// the recipient fingerprint is derived from
    /// [`PeerEndpoint::fingerprint`], so the responder cannot tell a
    /// direct dial from a resolver dial.
    ///
    /// [`request`]: Self::request
    pub async fn request_direct(
        &self,
        peer: PeerEndpoint,
        topic: &Topic,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.request_via(DialRoute::Direct(peer), topic, body, timeout)
            .await
    }

    /// Shared request core for both the resolver and direct-dial paths.
    async fn request_via(
        &self,
        route: DialRoute,
        topic: &Topic,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let correlation = CorrelationId::new_random();
        let waiter = self.inbox.register_reply(correlation);

        let msg = BusMessage::Request {
            topic: topic.wire(),
            correlation: correlation.0,
            body,
        };
        if let Err(e) = self.send_via(route, msg).await {
            self.inbox.cancel_reply(&correlation);
            return Err(e);
        }

        match tokio::time::timeout(timeout, waiter).await {
            Ok(Ok(payload)) => Ok(payload),
            Ok(Err(_)) => Err(BusError::LostReply),
            Err(_) => {
                self.inbox.cancel_reply(&correlation);
                Err(BusError::Timeout(timeout))
            }
        }
    }

    /// Register a handler for `topic`. The handler runs whenever an
    /// incoming `Request` names this topic. The reply it returns is
    /// shipped back to the original sender.
    pub fn handle_requests<F, Fut>(&self, topic: Topic, handler: F)
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'static,
    {
        let inbox = self.inbox.clone();
        // Inbox::register_handler is async only because it takes a
        // write lock; spawn it so the caller doesn't have to .await.
        // The handler is in place by the time the next message is
        // dispatched.
        tokio::spawn(async move {
            inbox.register_handler(topic, handler).await;
        });
    }

    /// Publish a body to `peer_fp` on `topic`. Fire-and-forget — the
    /// caller doesn't wait for a reply. The named peer's bus will
    /// fan it out to any local subscribers on that topic.
    ///
    /// v1 is **peer-explicit**: the sender names which peer to
    /// deliver to. A "publish to anyone subscribed" mode (topic
    /// routing without naming peers) is deferred to a follow-up.
    pub async fn publish_to(
        &self,
        peer_fp: Fingerprint,
        topic: &Topic,
        body: Vec<u8>,
    ) -> Result<()> {
        let msg = BusMessage::Publish {
            topic: topic.wire(),
            body,
        };
        self.send_via(DialRoute::Resolve(peer_fp), msg).await
    }

    /// Publish a body directly to a known [`PeerEndpoint`] on `topic`,
    /// **without mDNS discovery**. Fire-and-forget. The direct-dial
    /// counterpart of [`publish_to`]; see [`request_direct`] for the
    /// WAN / WireGuard rationale.
    ///
    /// [`publish_to`]: Self::publish_to
    /// [`request_direct`]: Self::request_direct
    pub async fn publish_to_direct(
        &self,
        peer: PeerEndpoint,
        topic: &Topic,
        body: Vec<u8>,
    ) -> Result<()> {
        let msg = BusMessage::Publish {
            topic: topic.wire(),
            body,
        };
        self.send_via(DialRoute::Direct(peer), msg).await
    }

    /// Subscribe to a topic. Returns a `broadcast::Receiver` that
    /// yields the body of each `Publish` for that topic that arrives
    /// on this bus.
    pub async fn subscribe(&self, topic: &Topic) -> broadcast::Receiver<Vec<u8>> {
        self.inbox.subscribe(topic).await
    }

    /// Graceful shutdown. Stops the accept loop, closes the endpoint,
    /// shuts the resolver down.
    pub async fn close(self) -> Result<()> {
        self.accept_task.abort();
        // Endpoint is owned via Arc by the (now-aborted) accept loop;
        // try to take the inner Endpoint by unwrapping the Arc. If
        // some background task still holds a clone we can't reclaim
        // the owned value — fall back to letting Drop release the
        // socket.
        match Arc::try_unwrap(self.endpoint) {
            Ok(ep) => ep.close().await,
            Err(_) => {
                tracing::debug!("bus close: endpoint still shared, leaving Drop to clean up");
            }
        }
        Ok(())
    }

    /// Dial the peer named by `route` (resolver or direct endpoint),
    /// pull the next sequence number, and ship a single envelope
    /// carrying `msg`.
    async fn send_via(&self, route: DialRoute, msg: BusMessage) -> Result<()> {
        let (conn, peer_fp) = match route {
            DialRoute::Resolve(peer_fp) => {
                let conn = dial_peer(&self.endpoint, &self.resolver, peer_fp).await?;
                (conn, peer_fp)
            }
            DialRoute::Direct(peer) => {
                let conn = dial_endpoint(&self.endpoint, peer).await?;
                (conn, peer.fingerprint())
            }
        };
        send_one(
            &conn,
            self.agent.cert(),
            self.agent.as_ref(),
            peer_fp,
            &self.sequence,
            msg,
        )
        .await
    }
}

/// How an outbound message names its destination: resolve a
/// [`Fingerprint`] over mDNS, or dial a known [`PeerEndpoint`]
/// directly.
#[derive(Debug, Clone, Copy)]
enum DialRoute {
    /// Look the peer up by fingerprint over mDNS, then dial.
    Resolve(Fingerprint),
    /// Dial a known agent pubkey + socket address, no resolver.
    Direct(PeerEndpoint),
}

/// Dial a known [`PeerEndpoint`] directly — no mDNS. Reuses the same
/// transport connect path as the resolver dial and the reply
/// dial-back: convert the agent pubkey to an iroh node id and
/// [`Endpoint::dial`] it at the supplied address.
async fn dial_endpoint(endpoint: &Endpoint, peer: PeerEndpoint) -> Result<Connection> {
    let iroh_pk = agent_pubkey_to_iroh(&peer.agent_pubkey).ok_or_else(|| {
        BusError::Unreachable(format!(
            "direct-dial endpoint {} has an invalid ed25519 pubkey",
            peer.fingerprint().short()
        ))
    })?;
    tracing::debug!(
        peer = %peer.fingerprint().short(),
        addr = %peer.addr,
        "bus: direct-dialing peer endpoint (no mDNS)"
    );
    let conn = endpoint.dial(iroh_pk, [peer.addr]).await?;
    Ok(conn)
}

/// Resolve `peer_fp` via mDNS, then dial the iroh endpoint.
async fn dial_peer(
    endpoint: &Endpoint,
    resolver: &PeerResolver,
    peer_fp: Fingerprint,
) -> Result<Connection> {
    let peer = resolver
        .resolve(&peer_fp, RESOLVE_TIMEOUT)
        .await
        .ok_or_else(|| {
            BusError::Unreachable(format!(
                "peer {} not announced within {:?}",
                peer_fp.short(),
                RESOLVE_TIMEOUT
            ))
        })?;
    let pubkey = peer.agent_pubkey.ok_or_else(|| {
        BusError::Unreachable(format!(
            "peer {} announced without ed25519 pubkey",
            peer_fp.short()
        ))
    })?;
    let iroh_pk = agent_pubkey_to_iroh(&pubkey).ok_or_else(|| {
        BusError::Unreachable(format!(
            "peer {} advertised invalid ed25519 pubkey",
            peer_fp.short()
        ))
    })?;
    // mDNS gives us the peer's real interface addresses (eth0, wlan0, etc).
    // For same-host peers those addresses route fine, but iroh's "address
    // lookup" can fail on them when the endpoint was bound without a relay
    // (the `clear_address_lookup()` path). Adding loopback explicitly makes
    // same-host dial work in tests and on developer laptops without
    // pessimizing the cross-host case — iroh races addresses and uses
    // whichever responds first.
    let mut socket_addrs: Vec<SocketAddr> = peer
        .addrs
        .iter()
        .copied()
        .map(|ip| SocketAddr::new(ip, peer.port))
        .collect();
    let lo_v4: std::net::IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
    let lo_v6: std::net::IpAddr = std::net::Ipv6Addr::LOCALHOST.into();
    let lo_addrs = [
        SocketAddr::new(lo_v4, peer.port),
        SocketAddr::new(lo_v6, peer.port),
    ];
    for addr in lo_addrs {
        if !socket_addrs.contains(&addr) {
            socket_addrs.push(addr);
        }
    }
    tracing::debug!(
        peer = %peer_fp.short(),
        addrs = ?socket_addrs,
        "bus: dialing peer"
    );
    if socket_addrs.is_empty() {
        return Err(BusError::Unreachable(format!(
            "peer {} announced without socket addresses",
            peer_fp.short()
        )));
    }
    let conn = endpoint.dial(iroh_pk, socket_addrs).await?;
    Ok(conn)
}

/// Open a fresh bidi stream on `conn`, do the cert handshake, ship one
/// envelope carrying `msg`.
async fn send_one(
    conn: &Connection,
    our_cert: &CertChain,
    sender: &AgentKey,
    peer_agent_fp: Fingerprint,
    sequence: &AtomicU64,
    msg: BusMessage,
) -> Result<()> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| BusError::Transport(TransportError::Iroh(format!("open_bi: {e}"))))?;
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        do_handshake(our_cert, &mut send, &mut recv, true),
    )
    .await
    .map_err(|_| BusError::Timeout(HANDSHAKE_TIMEOUT))??;

    let seq = sequence.fetch_add(1, Ordering::SeqCst);
    let payload = serde_json::to_vec(&msg)?;
    let env = SignedEnvelope::new(
        sender,
        Recipient::Direct {
            agent_fp: peer_agent_fp,
        },
        seq,
        payload,
    );
    send_envelope(&mut send, &env).await?;
    send.finish()
        .map_err(|e| BusError::Transport(TransportError::Iroh(format!("finish: {e}"))))?;
    // Wait for the send side to fully drain so the peer sees the
    // bytes before the stream tears down.
    let _ = send.stopped().await;
    Ok(())
}

/// Spawn the accept loop. Reads incoming connections, runs the
/// handshake on each fresh bi-stream, feeds each envelope into the
/// inbox, and ships any outgoing reply.
fn spawn_accept_loop(
    endpoint: Arc<Endpoint>,
    agent: Arc<AgentKey>,
    inbox: Arc<Inbox>,
    resolver: Arc<PeerResolver>,
    sequence: Arc<AtomicU64>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                tracing::debug!("bus accept loop: endpoint closed");
                break;
            };
            let agent = agent.clone();
            let inbox = inbox.clone();
            let endpoint = endpoint.clone();
            let resolver = resolver.clone();
            let sequence = sequence.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_incoming(incoming, agent, inbox, endpoint, resolver, sequence).await
                {
                    tracing::warn!(error = %e, "bus: incoming connection error");
                }
            });
        }
    })
}

/// Handle a single accepted connection: finish QUIC, then loop over
/// bidi streams accepting envelopes.
async fn handle_incoming(
    incoming: Incoming,
    agent: Arc<AgentKey>,
    inbox: Arc<Inbox>,
    endpoint: Arc<Endpoint>,
    resolver: Arc<PeerResolver>,
    sequence: Arc<AtomicU64>,
) -> Result<()> {
    // The UDP source the connection physically arrived from. QUIC uses
    // one socket for both directions, so this is also where the peer
    // can be dialed back.
    let reverse_addr = match incoming.remote_addr() {
        IncomingAddr::Ip(addr) => Some(addr),
        // Relay/custom transports are not used in this mesh (the
        // endpoint binds relay-free), but don't pretend otherwise.
        _ => None,
    };
    let conn = incoming
        .await
        .map_err(|e| BusError::Transport(TransportError::Iroh(format!("incoming: {e}"))))?;
    // The TLS-authenticated key of whoever dialed us — for agents this
    // IS the agent pubkey, so replies can verify it against the
    // envelope sender's fingerprint and dial straight back.
    let reverse: Option<(PublicKey, SocketAddr)> =
        reverse_addr.map(|addr| (conn.remote_id(), addr));
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                tracing::debug!(error = %e, "bus: accept_bi ended (peer closed)");
                return Ok(());
            }
        };
        let cert = agent.cert().clone();
        let handshake_res = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            do_handshake(&cert, &mut send, &mut recv, false),
        )
        .await;
        match handshake_res {
            Ok(Ok(_peer_cert)) => {}
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "bus: handshake rejected");
                continue;
            }
            Err(_) => {
                tracing::warn!("bus: handshake timed out");
                continue;
            }
        }
        let env = match recv_envelope(&mut recv).await {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(error = %e, "bus: envelope read failed");
                continue;
            }
        };
        let outgoing = match inbox.on_envelope(env).await {
            Ok(out) => out,
            Err(e) => {
                tracing::warn!(error = %e, "bus: inbox rejected envelope");
                continue;
            }
        };
        if let Some(reply) = outgoing {
            // The peer dialed us; we now dial them to ship the
            // reply. Spawn it so the accept loop can keep
            // draining envelopes off this connection.
            let endpoint = endpoint.clone();
            let resolver = resolver.clone();
            let agent = agent.clone();
            let sequence = sequence.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    ship_reply(endpoint, resolver, agent, sequence, reply, reverse).await
                {
                    tracing::warn!(error = %e, "bus: reply ship failed");
                }
            });
        }
    }
}

/// Ship an [`OutgoingReply`] back to the peer it came from.
///
/// `reverse` is the dial-back route observed on the request connection
/// (the peer's TLS-authenticated key + the UDP source address). When it
/// matches the envelope sender it is preferred over mDNS resolution —
/// the asker may not be announced yet (cold-start race) or may never
/// announce (quiet bind).
async fn ship_reply(
    endpoint: Arc<Endpoint>,
    resolver: Arc<PeerResolver>,
    agent: Arc<AgentKey>,
    sequence: Arc<AtomicU64>,
    reply: OutgoingReply,
    reverse: Option<(PublicKey, SocketAddr)>,
) -> Result<()> {
    let conn = dial_reply_peer(&endpoint, &resolver, reply.peer_fp, reverse).await?;
    let msg = BusMessage::Reply {
        correlation: reply.correlation.0,
        body: reply.body,
    };
    send_one(
        &conn,
        agent.cert(),
        agent.as_ref(),
        reply.peer_fp,
        &sequence,
        msg,
    )
    .await
}

/// Dial the peer a reply is destined for: dial-back first, mDNS second.
///
/// The dial-back route is only taken when the connection's remote key
/// hashes to the envelope sender's fingerprint (`agent_fp =
/// blake3(agent_pubkey)`), so a reply can never be redirected to a
/// connection peer that didn't sign the request. The subsequent cert
/// handshake in `send_one` re-verifies the chain to the user trust
/// root either way.
async fn dial_reply_peer(
    endpoint: &Endpoint,
    resolver: &PeerResolver,
    peer_fp: Fingerprint,
    reverse: Option<(PublicKey, SocketAddr)>,
) -> Result<Connection> {
    if let Some((pubkey, addr)) = reverse {
        if Fingerprint::of_bytes(pubkey.as_bytes()) == peer_fp {
            match endpoint.dial(pubkey, [addr]).await {
                Ok(conn) => return Ok(conn),
                Err(e) => tracing::debug!(
                    peer = %peer_fp.short(),
                    %addr,
                    error = %e,
                    "bus: reply dial-back failed, falling back to mDNS"
                ),
            }
        } else {
            tracing::warn!(
                peer = %peer_fp.short(),
                "bus: connection key does not match envelope sender; ignoring dial-back route"
            );
        }
    }
    dial_peer(endpoint, resolver, peer_fp).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentMetadata, Caveats, UserKey};

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

    #[tokio::test(flavor = "multi_thread")]
    async fn bind_exposes_local_port_and_fingerprints() {
        let user = UserKey::generate();
        let a = agent(&user, "worker");
        let a_fp = a.fingerprint();
        let bus = Bus::bind(&user, a, 0).await.expect("bind");
        assert!(bus.local_port() > 0);
        assert_eq!(bus.user_fingerprint(), user.fingerprint());
        assert_eq!(bus.agent_fingerprint(), a_fp);
        bus.close().await.expect("close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn request_to_unknown_peer_errors_unreachable() {
        let user = UserKey::generate();
        let a = agent(&user, "alice");
        let bus = Bus::bind(&user, a, 0).await.expect("bind");
        let topic = Topic::new(user.fingerprint(), "echo");
        let phantom_fp = Fingerprint([0xfeu8; 32]);
        let res = bus
            .request(
                phantom_fp,
                &topic,
                b"x".to_vec(),
                Duration::from_millis(200),
            )
            .await;
        match res {
            Err(BusError::Unreachable(_)) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
        bus.close().await.unwrap();
    }
}
