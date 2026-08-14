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
//! by correlation id plus the expected responder's authenticated fingerprint
//! (not by connection), so a reply arriving on a freshly-dialed reverse
//! connection works exactly the same without letting another peer win the
//! correlation race.
//!
//! Replies prefer **dial-back over mDNS**: the request connection's
//! TLS-authenticated remote key doubles as the sender's agent pubkey,
//! so the responder dials the observed source address directly and
//! only falls back to mDNS resolution if that dial fails. This keeps
//! replies working when the asker's announce hasn't propagated yet
//! (cold-start race) or when the asker never announces at all (a
//! quiet [`BusOptions`] bind).

use crate::inbox::{BusMessage, Inbox, RequestContext};
use crate::reply::CorrelationId;
use crate::transport::{AuthenticatedPeer, DeliveryProvenance, Inbound, ReplyRoute, Transport};
use crate::{BusError, Result, Topic};
use agent_mesh_discovery::{AnnounceConfig, Announcer, AnnouncerHandle};
use agent_mesh_protocol::{AgentKey, CertChain, Fingerprint, Recipient, SignedEnvelope, UserKey};
use agent_mesh_transport::{
    do_handshake,
    identity::agent_pubkey_to_iroh,
    iroh_reexports::{Connection, Incoming, IncomingAddr, PublicKey},
    recv_envelope, send_envelope, Endpoint, PeerResolver, ResolverHandle, TransportError,
};
use async_trait::async_trait;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

/// The dial-back route observed on an inbound iroh connection — the peer's
/// TLS-authenticated key and the UDP source address. Carried as the opaque
/// [`ReplyRoute`] for [`IrohTransport`]; `None` when no source address was
/// observed (relay/custom transports, which this mesh does not use).
type IrohReverse = Option<(PublicKey, SocketAddr)>;

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
    /// The wire this bus sends/receives envelopes over — iroh QUIC + mDNS in
    /// production ([`IrohTransport`]), an in-memory switchboard in tests.
    transport: Arc<dyn Transport>,
    inbox: Arc<Inbox>,
    sequence: Arc<AtomicU64>,
    /// The bus-level receive loop: pulls each inbound envelope off the
    /// transport, runs it through the inbox, and ships any reply back.
    accept_task: JoinHandle<()>,
}

fn verified_local_user(agent: &AgentKey) -> Result<Fingerprint> {
    agent.cert().verify()?;
    Ok(agent.cert().user_fingerprint())
}

fn ensure_local_user(supplied_user_fp: Fingerprint, certified_user_fp: Fingerprint) -> Result<()> {
    if supplied_user_fp != certified_user_fp {
        return Err(BusError::LocalIdentityMismatch {
            supplied_user_fp: supplied_user_fp.hex(),
            certified_user_fp: certified_user_fp.hex(),
        });
    }
    Ok(())
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
        // The verified certified root is the local admission policy. Reject a
        // mismatched explicit UserKey consistently in debug and release builds.
        let user_fp = verified_local_user(&agent)?;
        ensure_local_user(user.fingerprint(), user_fp)?;
        let agent = Arc::new(agent);
        let transport = IrohTransport::bind(user_fp, agent.clone(), port, opts).await?;
        Self::bind_with_transport(agent, Arc::new(transport))
    }

    /// Bind a bus over an explicit [`Transport`], skipping iroh entirely.
    ///
    /// This is the seam that lets the bus's request/reply/correlation/dial-back
    /// logic be exercised over an in-memory switchboard in tests — the same
    /// `Bus` code path, but with no sockets, no mDNS, and no QUIC handshake
    /// timing (the flaky `request_reply_roundtrip` used the real stack and
    /// timed out on hosted CI runners). Production always goes through
    /// [`Self::bind_with`] → [`IrohTransport`].
    ///
    /// Returns an error if the local agent certificate does not verify; an
    /// unverified certificate must never define the bus's trusted user root.
    pub fn bind_with_transport(
        agent: Arc<AgentKey>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        let user_fp = verified_local_user(&agent)?;
        let inbox = Arc::new(Inbox::new());
        let sequence = Arc::new(AtomicU64::new(1));
        let accept_task = spawn_accept_loop(
            transport.clone(),
            agent.clone(),
            inbox.clone(),
            sequence.clone(),
        );
        Ok(Self {
            agent,
            user_fp,
            transport,
            inbox,
            sequence,
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

    /// Local UDP port the transport is bound on (`0` for a non-socket transport).
    #[must_use]
    pub fn local_port(&self) -> u16 {
        self.transport.local_port()
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
        let expected_peer_fp = route.peer_fingerprint();
        let waiter = self.inbox.register_reply(correlation, expected_peer_fp);

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
        // Register synchronously so the handler is live the instant this
        // returns. Previously this spawned the registration onto the
        // runtime, which left a window — before the spawned task was
        // polled — where a request dispatched to this topic found no
        // handler and was silently dropped (`Inbox::dispatch_request`
        // returns `Ok(None)`), timing out the asker. Direct-dial
        // round-trip tests papered over that window with a fixed
        // `sleep`; synchronous registration removes the race outright.
        self.inbox.register_handler(topic, handler);
    }

    /// Register a request handler that also receives the verified caller
    /// [`RequestContext`] (the authenticated user + agent fingerprints of
    /// whoever signed the request). Use this when the handler must authorize
    /// *who* is calling — e.g. a capability-gated responder — rather than serve
    /// any same-mesh peer. Same synchronous-registration guarantee as
    /// [`Self::handle_requests`].
    pub fn handle_requests_with_context<F, Fut>(&self, topic: Topic, handler: F)
    where
        F: Fn(RequestContext, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'static,
    {
        self.inbox.register_handler_with_context(topic, handler);
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

    /// Graceful shutdown. Stops the bus receive loop and releases the
    /// transport (which closes the endpoint / leaves the switchboard).
    pub async fn close(self) -> Result<()> {
        self.accept_task.abort();
        self.transport.close().await;
        Ok(())
    }

    /// Sign + sequence `msg` into an envelope for `peer_fp` and hand it to the
    /// transport for the named route.
    async fn send_via(&self, route: DialRoute, msg: BusMessage) -> Result<()> {
        match route {
            DialRoute::Resolve(peer_fp) => {
                let env = make_envelope(&self.agent, &self.sequence, peer_fp, msg)?;
                self.transport.send_to(peer_fp, env).await
            }
            DialRoute::Direct(peer) => {
                let env = make_envelope(&self.agent, &self.sequence, peer.fingerprint(), msg)?;
                self.transport.send_to_endpoint(&peer, env).await
            }
        }
    }
}

/// Sign + sequence a [`BusMessage`] into a [`SignedEnvelope`] addressed to
/// `peer_fp`. The bus owns this (the envelope is bus policy); the transport
/// only carries the finished envelope.
fn make_envelope(
    agent: &AgentKey,
    sequence: &AtomicU64,
    peer_fp: Fingerprint,
    msg: BusMessage,
) -> Result<SignedEnvelope> {
    let seq = sequence.fetch_add(1, Ordering::SeqCst);
    let payload = serde_json::to_vec(&msg)?;
    Ok(SignedEnvelope::new(
        agent,
        Recipient::Direct { agent_fp: peer_fp },
        seq,
        payload,
    ))
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

impl DialRoute {
    /// The authenticated agent identity an eventual reply must be signed by.
    fn peer_fingerprint(self) -> Fingerprint {
        match self {
            Self::Resolve(peer_fp) => peer_fp,
            Self::Direct(peer) => peer.fingerprint(),
        }
    }
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

/// `fe80::/10` link-local IPv6 with **no scope id**. Such an address is
/// undialable, and left in an iroh dial set it fails `sendmsg` with
/// `InvalidInput`, aborting the whole race (the #61 root cause). We hand-roll
/// the `fe80::/10` test because `Ipv6Addr::is_unicast_link_local` is still
/// unstable on our MSRV (1.75).
fn is_scopeless_link_local(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V6(v6) => (v6.ip().segments()[0] & 0xffc0) == 0xfe80 && v6.scope_id() == 0,
        SocketAddr::V4(_) => false,
    }
}

/// Ordered dial candidates for a peer's **reply** route, keyed by identity:
/// locations are candidates, never load-bearing (see
/// `docs/decisions/floating_identity.md`). The set is the recv source path
/// (its `recvmsg` scope id already intact) plus same-host loopback at that
/// port; scopeless link-local is filtered so it can never poison the dial
/// race. Never a single load-bearing address; never empty for a same-host
/// peer.
fn reply_dial_candidates(source: SocketAddr) -> Vec<SocketAddr> {
    // QUIC uses one socket both directions, so the source port is also the
    // dial-back port for same-host loopback (mirrors `dial_peer`).
    let port = source.port();
    let mut candidates: Vec<SocketAddr> = Vec::with_capacity(3);
    for addr in [
        source,
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port),
        SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port),
    ] {
        if is_scopeless_link_local(&addr) {
            continue;
        }
        if !candidates.contains(&addr) {
            candidates.push(addr);
        }
    }
    candidates
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
    let advertised_fp = Fingerprint::of_bytes(&pubkey);
    if advertised_fp != peer_fp {
        return Err(BusError::Unreachable(format!(
            "peer {} advertised pubkey for different agent {}",
            peer_fp.short(),
            advertised_fp.short()
        )));
    }
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
    // A scopeless link-local mDNS address (`fe80::` with no scope id) is
    // undialable and, left in the set, fails `sendmsg` with `InvalidInput`,
    // aborting the whole iroh race (#61). Drop it — loopback keeps the set
    // non-empty for same-host peers.
    socket_addrs.retain(|addr| !is_scopeless_link_local(addr));
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

/// Turn a verified Hello cert into carrier evidence only when its leaf key is
/// the QUIC/TLS-authenticated session identity.
fn authenticated_iroh_peer(
    session_id: &PublicKey,
    peer_cert: &CertChain,
) -> Result<AuthenticatedPeer> {
    // `do_handshake` verifies this too, but keep the constructor honest when
    // used on either side of a connection: the evidence is derived only from a
    // valid cert whose leaf key is byte-for-byte the QUIC/TLS session identity.
    peer_cert.verify()?;
    if &peer_cert.agent_pubkey != session_id.as_bytes() {
        return Err(BusError::Transport(TransportError::Handshake(format!(
            "peer Hello certificate agent {} is not bound to QUIC session {}",
            peer_cert.agent_fingerprint().short(),
            Fingerprint::of_bytes(session_id.as_bytes()).short(),
        ))));
    }
    Ok(AuthenticatedPeer::new(
        peer_cert.user_fingerprint(),
        peer_cert.agent_fingerprint(),
    ))
}

fn ensure_intended_iroh_peer(peer: AuthenticatedPeer, expected_peer_fp: Fingerprint) -> Result<()> {
    if peer.agent_fp != expected_peer_fp {
        return Err(BusError::Transport(TransportError::Handshake(format!(
            "authenticated peer {} does not match intended target {}",
            peer.agent_fp.short(),
            expected_peer_fp.short(),
        ))));
    }
    Ok(())
}

/// Open a fresh bidi stream on `conn`, do the cert handshake, bind its verified
/// peer to both the QUIC session and `expected_peer_fp`, then ship one
/// already-signed envelope. (The bus signs + sequences the envelope; the
/// transport only carries it — see [`make_envelope`].)
async fn send_env_on_conn(
    conn: &Connection,
    our_cert: &CertChain,
    expected_peer_fp: Fingerprint,
    env: &SignedEnvelope,
) -> Result<()> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| BusError::Transport(TransportError::Iroh(format!("open_bi: {e}"))))?;
    let peer_cert = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        do_handshake(our_cert, &mut send, &mut recv, true),
    )
    .await
    .map_err(|_| BusError::Timeout(HANDSHAKE_TIMEOUT))??;
    // Bind the Hello identity on the dialer side too. Otherwise a QUIC endpoint
    // authenticated as B could present a copied, valid same-user cert for A and
    // receive traffic intended for A.
    let peer = authenticated_iroh_peer(&conn.remote_id(), &peer_cert)?;
    ensure_intended_iroh_peer(peer, expected_peer_fp)?;
    send_envelope(&mut send, env).await?;
    send.finish()
        .map_err(|e| BusError::Transport(TransportError::Iroh(format!("finish: {e}"))))?;
    // Wait for the send side to fully drain so the peer sees the
    // bytes before the stream tears down.
    let _ = send.stopped().await;
    Ok(())
}

/// The bus-level receive loop, transport-agnostic: pull each inbound envelope
/// off the [`Transport`], run it through the [`Inbox`] (verify + dispatch), and
/// ship any resulting reply back over the transport on the envelope's inbound
/// route. This is the wiring the round-trip test exercises — identical whether
/// the transport is iroh or the in-memory switchboard.
fn spawn_accept_loop(
    transport: Arc<dyn Transport>,
    agent: Arc<AgentKey>,
    inbox: Arc<Inbox>,
    sequence: Arc<AtomicU64>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(inbound) = transport.recv().await {
            let transport = transport.clone();
            let agent = agent.clone();
            let inbox = inbox.clone();
            let sequence = sequence.clone();
            // One task per inbound so a slow handler/reply can't stall the loop.
            tokio::spawn(async move {
                let Inbound {
                    envelope,
                    provenance,
                    reply_route,
                } = inbound;
                let local_user_fp = agent.cert().user_fingerprint();
                let local_agent_fp = agent.fingerprint();
                match inbox
                    .on_envelope(envelope, provenance, local_user_fp, local_agent_fp)
                    .await
                {
                    Ok(Some(reply)) => {
                        let msg = BusMessage::Reply {
                            correlation: reply.correlation.0,
                            body: reply.body,
                        };
                        match make_envelope(&agent, &sequence, reply.peer_fp, msg) {
                            Ok(env) => {
                                if let Err(e) =
                                    transport.reply(reply.peer_fp, &reply_route, env).await
                                {
                                    tracing::warn!(error = %e, "bus: reply ship failed");
                                }
                            }
                            Err(e) => tracing::warn!(error = %e, "bus: reply encode failed"),
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error = %e, "bus: inbox rejected envelope"),
                }
            });
        }
        tracing::debug!("bus accept loop: transport closed");
    })
}

/// Dial the peer a reply is destined for: dial-back first, mDNS second.
///
/// The dial-back route is only taken when the connection's remote key
/// hashes to the envelope sender's fingerprint (`agent_fp =
/// blake3(agent_pubkey)`), so a reply can never be redirected to a
/// connection peer that didn't sign the request. The subsequent cert
/// handshake in `send_env_on_conn` re-verifies the chain to the user trust
/// root either way.
async fn dial_reply_peer(
    endpoint: &Endpoint,
    resolver: &PeerResolver,
    peer_fp: Fingerprint,
    reverse: IrohReverse,
) -> Result<Connection> {
    if let Some((pubkey, addr)) = reverse {
        if Fingerprint::of_bytes(pubkey.as_bytes()) == peer_fp {
            // Dial the peer's *identity* over a candidate set (source path +
            // same-host loopback), never a single load-bearing address — see
            // `docs/decisions/floating_identity.md` and #61.
            let candidates = reply_dial_candidates(addr);
            if !candidates.is_empty() {
                match endpoint.dial(pubkey, candidates.iter().copied()).await {
                    Ok(conn) => return Ok(conn),
                    Err(e) => tracing::debug!(
                        peer = %peer_fp.short(),
                        ?candidates,
                        error = %e,
                        "bus: reply dial-back failed, falling back to mDNS"
                    ),
                }
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

// ── IrohTransport: the production QUIC + mDNS transport ──────────────────────

/// The production [`Transport`]: iroh QUIC for delivery, mDNS for discovery.
/// Owns the bound endpoint, the resolver, the announcer, and an internal
/// accept loop that decodes each inbound envelope and feeds it (with its
/// dial-back route) into a channel the bus drains via [`Transport::recv`].
pub struct IrohTransport {
    endpoint: Arc<Endpoint>,
    resolver: Arc<PeerResolver>,
    /// Our own key — its cert is presented in every handshake.
    agent: Arc<AgentKey>,
    /// Keeps the mDNS browser thread alive for the life of the transport.
    _resolver_handle: ResolverHandle,
    /// Keeps the mDNS announcer alive; `None` for a quiet ([`BusOptions`]
    /// `announce = false`) bind.
    _announcer: Option<AnnouncerHandle>,
    inbound: AsyncMutex<mpsc::UnboundedReceiver<Inbound>>,
    accept_task: JoinHandle<()>,
}

impl IrohTransport {
    /// Bind the iroh endpoint on `port` (`0` = OS-picked), start the mDNS
    /// resolver + (optional) announcer, and spawn the internal accept loop.
    pub async fn bind(
        user_fp: Fingerprint,
        agent: Arc<AgentKey>,
        port: u16,
        opts: BusOptions,
    ) -> Result<Self> {
        let certified_user_fp = verified_local_user(&agent)?;
        ensure_local_user(user_fp, certified_user_fp)?;
        let endpoint = Endpoint::bind(&agent, port).await?;
        let local_port = endpoint.port();
        let endpoint = Arc::new(endpoint);
        let (resolver, resolver_handle) = PeerResolver::start()?;
        let resolver = Arc::new(resolver);

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

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let accept_task = spawn_iroh_accept_loop(endpoint.clone(), agent.clone(), inbound_tx);

        Ok(Self {
            endpoint,
            resolver,
            agent,
            _resolver_handle: resolver_handle,
            _announcer: announcer,
            inbound: AsyncMutex::new(inbound_rx),
            accept_task,
        })
    }
}

#[async_trait]
impl Transport for IrohTransport {
    async fn send_to(&self, fp: Fingerprint, env: SignedEnvelope) -> Result<()> {
        let conn = dial_peer(&self.endpoint, &self.resolver, fp).await?;
        send_env_on_conn(&conn, self.agent.cert(), fp, &env).await
    }

    async fn send_to_endpoint(&self, peer: &PeerEndpoint, env: SignedEnvelope) -> Result<()> {
        let conn = dial_endpoint(&self.endpoint, *peer).await?;
        send_env_on_conn(&conn, self.agent.cert(), peer.fingerprint(), &env).await
    }

    async fn reply(&self, fp: Fingerprint, route: &ReplyRoute, env: SignedEnvelope) -> Result<()> {
        // The opaque route is the dial-back (pubkey, addr) observed on the
        // inbound connection; `None` (or a foreign route) falls back to mDNS.
        let reverse: IrohReverse = route.downcast_ref::<IrohReverse>().cloned().flatten();
        let conn = dial_reply_peer(&self.endpoint, &self.resolver, fp, reverse).await?;
        send_env_on_conn(&conn, self.agent.cert(), fp, &env).await
    }

    async fn recv(&self) -> Option<Inbound> {
        self.inbound.lock().await.recv().await
    }

    fn local_port(&self) -> u16 {
        self.endpoint.port()
    }

    async fn close(&self) {
        self.accept_task.abort();
        // The iroh endpoint releases its socket on Drop; it is held via `Arc`
        // (shared with in-flight dial tasks) so we cannot consume it here.
    }
}

/// The iroh-internal accept loop: accept connections and, per bidi stream,
/// handshake + decode the envelope, then push it (with its dial-back route)
/// into `inbound_tx` for the bus to drain.
fn spawn_iroh_accept_loop(
    endpoint: Arc<Endpoint>,
    agent: Arc<AgentKey>,
    inbound_tx: mpsc::UnboundedSender<Inbound>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                tracing::debug!("iroh transport accept loop: endpoint closed");
                break;
            };
            let agent = agent.clone();
            let inbound_tx = inbound_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = accept_conn(incoming, agent, inbound_tx).await {
                    tracing::warn!(error = %e, "iroh transport: incoming connection error");
                }
            });
        }
    })
}

/// Handle one accepted connection: finish QUIC, then per bidi stream do the
/// handshake, decode the envelope, and forward it into `inbound_tx`.
async fn accept_conn(
    incoming: Incoming,
    agent: Arc<AgentKey>,
    inbound_tx: mpsc::UnboundedSender<Inbound>,
) -> Result<()> {
    // The UDP source the connection physically arrived from. QUIC uses one
    // socket for both directions, so this is also where the peer can be
    // dialed back.
    let reverse_addr = match incoming.remote_addr() {
        IncomingAddr::Ip(addr) => Some(addr),
        // Relay/custom transports are not used in this mesh (the endpoint
        // binds relay-free), but don't pretend otherwise.
        _ => None,
    };
    let conn = incoming
        .await
        .map_err(|e| BusError::Transport(TransportError::Iroh(format!("incoming: {e}"))))?;
    // The TLS-authenticated key of whoever dialed us — for agents this IS the
    // agent pubkey, so replies can verify it against the envelope sender's
    // fingerprint and dial straight back. Shared by every envelope on this
    // connection as the opaque reply route.
    let reverse: IrohReverse = reverse_addr.map(|addr| (conn.remote_id(), addr));
    let reply_route: ReplyRoute = Arc::new(reverse);
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                tracing::debug!(error = %e, "iroh transport: accept_bi ended (peer closed)");
                return Ok(());
            }
        };
        let cert = agent.cert().clone();
        let peer_cert = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            do_handshake(&cert, &mut send, &mut recv, false),
        )
        .await
        {
            Ok(Ok(peer_cert)) => peer_cert,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "iroh transport: handshake rejected");
                continue;
            }
            Err(_) => {
                tracing::warn!("iroh transport: handshake timed out");
                continue;
            }
        };
        // A valid Hello cert is not proof that the QUIC peer owns its leaf key:
        // bind it explicitly to the TLS-authenticated endpoint identity before
        // turning it into carrier evidence.
        let carrier = match authenticated_iroh_peer(&conn.remote_id(), &peer_cert) {
            Ok(peer) => peer,
            Err(e) => {
                tracing::warn!(error = %e, "iroh transport: Hello/session identity mismatch");
                continue;
            }
        };
        let env = match recv_envelope(&mut recv).await {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(error = %e, "iroh transport: envelope read failed");
                continue;
            }
        };
        if inbound_tx
            .send(Inbound {
                envelope: env,
                provenance: DeliveryProvenance::Direct { carrier },
                reply_route: reply_route.clone(),
            })
            .is_err()
        {
            tracing::debug!("iroh transport: bus receiver dropped; stopping");
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MeshNet;
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

    fn direct_provenance(agent: &AgentKey) -> DeliveryProvenance {
        DeliveryProvenance::Direct {
            carrier: AuthenticatedPeer::new(agent.cert().user_fingerprint(), agent.fingerprint()),
        }
    }

    enum CapturedSend {
        Resolve(Fingerprint, SignedEnvelope),
        Direct(PeerEndpoint, SignedEnvelope),
    }

    /// Transport test double that captures outbound envelopes and never
    /// produces inbound traffic on its own. Tests can feed the captured
    /// correlation back through the real inbox deterministically.
    struct CaptureTransport {
        sent_tx: mpsc::UnboundedSender<CapturedSend>,
        sent_rx: AsyncMutex<mpsc::UnboundedReceiver<CapturedSend>>,
    }

    impl CaptureTransport {
        fn new() -> Arc<Self> {
            let (sent_tx, sent_rx) = mpsc::unbounded_channel();
            Arc::new(Self {
                sent_tx,
                sent_rx: AsyncMutex::new(sent_rx),
            })
        }

        async fn next_sent(&self) -> CapturedSend {
            self.sent_rx
                .lock()
                .await
                .recv()
                .await
                .expect("bus keeps capture transport alive")
        }
    }

    #[async_trait]
    impl Transport for CaptureTransport {
        async fn send_to(&self, fp: Fingerprint, env: SignedEnvelope) -> Result<()> {
            self.sent_tx
                .send(CapturedSend::Resolve(fp, env))
                .expect("capture receiver is alive");
            Ok(())
        }

        async fn send_to_endpoint(&self, peer: &PeerEndpoint, env: SignedEnvelope) -> Result<()> {
            self.sent_tx
                .send(CapturedSend::Direct(*peer, env))
                .expect("capture receiver is alive");
            Ok(())
        }

        async fn reply(
            &self,
            _fp: Fingerprint,
            _route: &ReplyRoute,
            _env: SignedEnvelope,
        ) -> Result<()> {
            unreachable!("capture transport does not receive requests")
        }

        async fn recv(&self) -> Option<Inbound> {
            std::future::pending().await
        }

        fn local_port(&self) -> u16 {
            0
        }

        async fn close(&self) {}
    }

    fn reply_envelope(
        sender: &AgentKey,
        recipient_fp: Fingerprint,
        correlation: CorrelationId,
        body: &[u8],
    ) -> SignedEnvelope {
        let payload = serde_json::to_vec(&BusMessage::Reply {
            correlation: correlation.0,
            body: body.to_vec(),
        })
        .expect("encode reply");
        let env = SignedEnvelope::new(
            sender,
            Recipient::Direct {
                agent_fp: recipient_fp,
            },
            1,
            payload,
        );
        env.verify().expect("test reply envelope verifies");
        env
    }

    async fn wrong_signer_cannot_win_for_request_route(direct: bool) {
        let user = UserKey::generate();
        let asker = Arc::new(agent(&user, "asker"));
        let expected = agent(&user, "expected");
        let attacker = agent(&user, "attacker");
        let asker_fp = asker.fingerprint();
        let expected_fp = expected.fingerprint();
        let transport = CaptureTransport::new();
        let bus = Bus::bind_with_transport(asker, Arc::clone(&transport) as Arc<dyn Transport>)
            .expect("bind asker to capture transport");
        let route = if direct {
            DialRoute::Direct(PeerEndpoint::new(
                expected.public_bytes(),
                "127.0.0.1:7".parse().unwrap(),
            ))
        } else {
            DialRoute::Resolve(expected_fp)
        };
        let topic = Topic::new(user.fingerprint(), "bound-reply");

        {
            let request =
                bus.request_via(route, &topic, b"request".to_vec(), Duration::from_secs(1));
            tokio::pin!(request);
            let captured = tokio::select! {
                biased;
                sent = transport.next_sent() => sent,
                result = &mut request => panic!("request completed before a reply: {result:?}"),
            };
            let (was_direct, target_fp, outbound) = match captured {
                CapturedSend::Resolve(fp, env) => (false, fp, env),
                CapturedSend::Direct(peer, env) => (true, peer.fingerprint(), env),
            };
            assert_eq!(was_direct, direct, "request must use the selected route");
            assert_eq!(target_fp, expected_fp);
            outbound.verify().expect("outbound request verifies");
            let correlation = match serde_json::from_slice::<BusMessage>(outbound.payload.as_ref())
                .expect("decode captured request")
            {
                BusMessage::Request { correlation, .. } => CorrelationId(correlation),
                other => panic!("expected Request, got {other:?}"),
            };
            assert_eq!(
                bus.inbox.pending_replies(),
                1,
                "request route must register its waiter before sending"
            );

            bus.inbox
                .on_envelope(
                    reply_envelope(&attacker, asker_fp, correlation, b"forged"),
                    direct_provenance(&attacker),
                    user.fingerprint(),
                    asker_fp,
                )
                .await
                .unwrap();
            assert_eq!(
                bus.inbox.pending_replies(),
                1,
                "wrong signer must not consume the route-bound waiter"
            );

            bus.inbox
                .on_envelope(
                    reply_envelope(&expected, asker_fp, correlation, b"legitimate"),
                    direct_provenance(&expected),
                    user.fingerprint(),
                    asker_fp,
                )
                .await
                .unwrap();
            assert_eq!(request.await.unwrap(), b"legitimate");
            assert_eq!(bus.inbox.pending_replies(), 0);
        }
        bus.close().await.unwrap();
    }

    #[test]
    fn local_identity_requires_a_valid_cert_and_matching_user() {
        let certified_user = UserKey::generate();
        let different_user = UserKey::generate();
        let local_agent = agent(&certified_user, "local");
        let certified_fp = verified_local_user(&local_agent).expect("valid local certificate");

        let mismatch = ensure_local_user(different_user.fingerprint(), certified_fp).unwrap_err();
        assert!(matches!(mismatch, BusError::LocalIdentityMismatch { .. }));

        let mut tampered_cert = local_agent.cert().clone();
        tampered_cert.metadata.role = "tampered".into();
        let invalid_agent =
            AgentKey::from_seed_and_cert(&local_agent.signing_key_bytes(), tampered_cert)
                .expect("seed still matches the unchanged leaf key");
        assert!(
            verified_local_user(&invalid_agent).is_err(),
            "a matching private key must not make an invalid certificate trusted"
        );
    }

    /// Carrier evidence can be minted only when the verified Hello cert's leaf
    /// key is the QUIC/TLS session identity. This helper gates both dialer and
    /// acceptor paths.
    #[test]
    fn hello_certificate_is_bound_to_its_quic_session() {
        let user = UserKey::generate();
        let a = agent(&user, "a");
        let b = agent(&user, "b");
        let a_session = agent_pubkey_to_iroh(&a.public_bytes()).expect("valid ed25519 key");
        let b_session = agent_pubkey_to_iroh(&b.public_bytes()).expect("valid ed25519 key");
        let peer = authenticated_iroh_peer(&a_session, a.cert()).expect("A owns A's session");
        assert_eq!(peer.agent_fp, a.fingerprint());
        assert_eq!(peer.user_fp, user.fingerprint());
        ensure_intended_iroh_peer(peer, a.fingerprint()).expect("A is the intended target");
        let err = ensure_intended_iroh_peer(peer, b.fingerprint()).unwrap_err();
        assert!(
            matches!(err, BusError::Transport(TransportError::Handshake(_))),
            "an authenticated A session must not satisfy an intended B target, got {err:?}"
        );

        let err = authenticated_iroh_peer(&b_session, a.cert()).unwrap_err();
        assert!(
            matches!(err, BusError::Transport(TransportError::Handshake(_))),
            "a copied A Hello cert on B's TLS session must be rejected, got {err:?}"
        );
    }

    /// Real-boundary regression: a valid envelope signed by A but carried over
    /// sibling B's authenticated QUIC session must not pass common admission or
    /// consume its nonce/sequence. The test receives each transport delivery
    /// explicitly, so the exact same envelope can be admitted over A's own
    /// session without a timing-based absence assertion.
    #[tokio::test(flavor = "multi_thread")]
    async fn relayed_envelope_on_sibling_quic_session_is_rejected_before_replay() {
        let user = UserKey::generate();
        let original_signer = agent(&user, "original-signer");
        let sibling_carrier = agent(&user, "sibling-carrier");
        let recipient = Arc::new(agent(&user, "recipient"));
        let recipient_pubkey = recipient.public_bytes();
        let recipient_fp = recipient.fingerprint();

        let recipient_transport = IrohTransport::bind(
            user.fingerprint(),
            recipient.clone(),
            0,
            BusOptions { announce: false },
        )
        .await
        .expect("bind recipient transport");
        let inbox = Inbox::new();
        let topic = Topic::new(user.fingerprint(), "carrier-binding");

        let msg = BusMessage::Publish {
            topic: topic.wire(),
            body: b"authentic payload".to_vec(),
        };
        let env = SignedEnvelope::new(
            &original_signer,
            Recipient::Direct {
                agent_fp: recipient_fp,
            },
            1,
            serde_json::to_vec(&msg).expect("encode bus message"),
        );
        let recipient_id =
            agent_pubkey_to_iroh(&recipient_pubkey).expect("recipient has a valid iroh key");
        let recipient_addr = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            recipient_transport.local_port(),
        );

        // B authenticates the QUIC session and its own Hello honestly, but
        // carries A's valid envelope. The transport reports B as carrier; the
        // common boundary must reject carrier != original signer.
        let sibling_endpoint = Endpoint::bind(&sibling_carrier, 0)
            .await
            .expect("bind sibling endpoint");
        let sibling_conn = sibling_endpoint
            .dial(recipient_id, [recipient_addr])
            .await
            .expect("sibling dials recipient");
        send_env_on_conn(&sibling_conn, sibling_carrier.cert(), recipient_fp, &env)
            .await
            .expect("relay bytes reach the recipient boundary");
        drop(sibling_conn);
        let relayed = tokio::time::timeout(Duration::from_secs(3), recipient_transport.recv())
            .await
            .expect("relay reaches transport boundary before timeout")
            .expect("recipient transport remains open");
        assert_eq!(
            relayed.provenance,
            DeliveryProvenance::Direct {
                carrier: AuthenticatedPeer::new(user.fingerprint(), sibling_carrier.fingerprint(),),
            }
        );
        let error = inbox
            .on_envelope(
                relayed.envelope,
                relayed.provenance,
                user.fingerprint(),
                recipient_fp,
            )
            .await
            .expect_err("a sibling carrier must not speak as the original signer");
        assert!(matches!(error, BusError::CarrierAgentMismatch { .. }));
        assert!(inbox.nonce_cache().is_empty());
        assert_eq!(
            inbox
                .sequence_tracker()
                .last_seen(&original_signer.fingerprint()),
            None
        );

        // Exact same signed bytes, nonce, and sequence over A's session. This
        // succeeds only if the rejected relay did not poison replay state.
        let signer_endpoint = Endpoint::bind(&original_signer, 0)
            .await
            .expect("bind signer endpoint");
        let signer_conn = signer_endpoint
            .dial(recipient_id, [recipient_addr])
            .await
            .expect("signer dials recipient");
        send_env_on_conn(&signer_conn, original_signer.cert(), recipient_fp, &env)
            .await
            .expect("honest envelope reaches recipient");
        let honest = tokio::time::timeout(Duration::from_secs(3), recipient_transport.recv())
            .await
            .expect("honest delivery reaches transport boundary before timeout")
            .expect("recipient transport remains open");
        inbox
            .on_envelope(
                honest.envelope,
                honest.provenance,
                user.fingerprint(),
                recipient_fp,
            )
            .await
            .expect("the signer's own carrier session is admitted");
        assert_eq!(inbox.nonce_cache().len(), 1);
        assert_eq!(
            inbox
                .sequence_tracker()
                .last_seen(&original_signer.fingerprint()),
            Some(1)
        );

        recipient_transport.close().await;
    }

    /// The request/reply round-trip driven over the **in-memory
    /// transport** — the exact same `Bus` send / receive / inbox / reply
    /// wiring the iroh path uses, but with no sockets, no mDNS, and no QUIC
    /// handshake timing. Deterministic and portable, replacing the real-mDNS
    /// `request_reply_roundtrip` in `tests/bus_roundtrip.rs` that timed out on
    /// hosted CI runners. Single-threaded runtime so task ordering (and thus
    /// the handler-registration flush below) is deterministic.
    #[tokio::test]
    async fn request_reply_roundtrip_over_in_memory_transport() {
        let user = UserKey::generate();
        let alice = Arc::new(agent(&user, "alice"));
        let bob = Arc::new(agent(&user, "bob"));
        let bob_fp = bob.fingerprint();

        // One switchboard; each bus gets an in-memory leg registered under its
        // agent fingerprint (that's what `send_to`/`reply` route by).
        let net = MeshNet::new();
        let alice_bus =
            Bus::bind_with_transport(alice.clone(), Arc::new(net.transport_for(&alice)))
                .expect("bind Alice to in-memory transport");
        let bob_bus = Bus::bind_with_transport(bob.clone(), Arc::new(net.transport_for(&bob)))
            .expect("bind Bob to in-memory transport");

        let topic = Topic::new(user.fingerprint(), "echo");
        bob_bus.handle_requests(topic.clone(), |body| async move {
            Ok(format!("echo: {}", String::from_utf8_lossy(&body)).into_bytes())
        });
        // No yield/sleep needed: `handle_requests` registers the handler
        // synchronously before it returns (see
        // `handle_requests_registers_synchronously_no_spawn_race`).

        let reply = alice_bus
            .request(bob_fp, &topic, b"hi".to_vec(), Duration::from_secs(5))
            .await
            .expect("round-trip reply");
        assert_eq!(reply, b"echo: hi");

        alice_bus.close().await.unwrap();
        bob_bus.close().await.unwrap();
    }

    #[tokio::test]
    async fn resolver_request_binds_reply_to_resolved_peer() {
        wrong_signer_cannot_win_for_request_route(false).await;
    }

    #[tokio::test]
    async fn direct_request_binds_reply_to_endpoint_peer() {
        wrong_signer_cannot_win_for_request_route(true).await;
    }

    #[tokio::test]
    async fn timed_out_request_removes_waiter_and_drops_late_reply() {
        let user = UserKey::generate();
        let asker = Arc::new(agent(&user, "asker"));
        let expected = agent(&user, "expected");
        let asker_fp = asker.fingerprint();
        let expected_fp = expected.fingerprint();
        let transport = CaptureTransport::new();
        let bus = Bus::bind_with_transport(asker, Arc::clone(&transport) as Arc<dyn Transport>)
            .expect("bind asker to capture transport");
        let topic = Topic::new(user.fingerprint(), "timeout");

        let result = bus
            .request(
                expected_fp,
                &topic,
                b"request".to_vec(),
                Duration::from_millis(1),
            )
            .await;
        assert!(matches!(result, Err(BusError::Timeout(_))));
        assert_eq!(bus.inbox.pending_replies(), 0);

        let outbound = match transport.next_sent().await {
            CapturedSend::Resolve(fp, env) => {
                assert_eq!(fp, expected_fp);
                env
            }
            CapturedSend::Direct(_, _) => panic!("request used the wrong route"),
        };
        let correlation = match serde_json::from_slice::<BusMessage>(outbound.payload.as_ref())
            .expect("decode captured request")
        {
            BusMessage::Request { correlation, .. } => CorrelationId(correlation),
            other => panic!("expected Request, got {other:?}"),
        };
        bus.inbox
            .on_envelope(
                reply_envelope(&expected, asker_fp, correlation, b"late"),
                direct_provenance(&expected),
                user.fingerprint(),
                asker_fp,
            )
            .await
            .unwrap();
        assert_eq!(
            bus.inbox.pending_replies(),
            0,
            "late reply must not recreate a timed-out waiter"
        );
        bus.close().await.unwrap();
    }

    #[tokio::test]
    async fn context_handler_sees_the_calling_agent_over_the_transport() {
        let user = UserKey::generate();
        let alice = Arc::new(agent(&user, "alice"));
        let bob = Arc::new(agent(&user, "bob"));
        let alice_fp = alice.fingerprint();
        let bob_fp = bob.fingerprint();

        let net = MeshNet::new();
        let alice_bus =
            Bus::bind_with_transport(alice.clone(), Arc::new(net.transport_for(&alice)))
                .expect("bind Alice to in-memory transport");
        let bob_bus = Bus::bind_with_transport(bob.clone(), Arc::new(net.transport_for(&bob)))
            .expect("bind Bob to in-memory transport");

        let topic = Topic::new(user.fingerprint(), "whoami");
        bob_bus.handle_requests_with_context(
            topic.clone(),
            |ctx: RequestContext, _body| async move {
                // The responder learns WHO called from the verified envelope, not
                // from anything the caller put in the body.
                Ok(ctx.caller_agent_fp.hex().into_bytes())
            },
        );

        let reply = alice_bus
            .request(bob_fp, &topic, b"".to_vec(), Duration::from_secs(5))
            .await
            .expect("round-trip reply");
        assert_eq!(
            String::from_utf8(reply).unwrap(),
            alice_fp.hex(),
            "the responder must see ALICE as the caller"
        );

        alice_bus.close().await.unwrap();
        bob_bus.close().await.unwrap();
    }

    /// Regression (#52 de-flake): `handle_requests` must register the
    /// handler *before it returns*, with no spawn and no intervening
    /// yield. It used to spawn the registration onto the runtime, so on a
    /// `current_thread` runtime — where a spawned task is not polled until
    /// the current task next yields — the handler was still absent the
    /// instant `handle_requests` returned. A request dispatched into that
    /// window found no handler and was silently dropped
    /// (`Inbox::dispatch_request` -> `Ok(None)`), timing out the asker.
    /// That is the exact flake the direct-dial round-trip tests used to
    /// mask with a fixed `sleep(200ms)`.
    ///
    /// This test asserts the count with no yield between registration and
    /// the check: it deterministically FAILS on the old spawn-based
    /// implementation (count still 0) and PASSES on synchronous
    /// registration (count 1). Run on the default single-threaded test
    /// runtime so the "spawned task hasn't been polled yet" invariant
    /// holds.
    #[tokio::test]
    async fn handle_requests_registers_synchronously_no_spawn_race() {
        let user = UserKey::generate();
        let bob = Arc::new(agent(&user, "bob"));
        let net = MeshNet::new();
        let bob_bus = Bus::bind_with_transport(bob.clone(), Arc::new(net.transport_for(&bob)))
            .expect("bind Bob to in-memory transport");

        let topic = Topic::new(user.fingerprint(), "echo");
        assert_eq!(
            bob_bus.inbox.handler_count(),
            0,
            "no handler registered before handle_requests"
        );

        bob_bus.handle_requests(topic, |body| async move { Ok(body) });

        // No sleep, no yield: on the old spawn-based code the spawned
        // registration task has not run yet, so this would still read 0.
        assert_eq!(
            bob_bus.inbox.handler_count(),
            1,
            "handle_requests must register the handler before returning"
        );

        bob_bus.close().await.unwrap();
    }

    /// A send to a fingerprint that isn't on the switchboard is `Unreachable`
    /// (mirrors the real transport's "peer not announced").
    #[tokio::test]
    async fn in_memory_send_to_unknown_peer_is_unreachable() {
        let user = UserKey::generate();
        let alice = Arc::new(agent(&user, "alice"));
        let net = MeshNet::new();
        let alice_bus =
            Bus::bind_with_transport(alice.clone(), Arc::new(net.transport_for(&alice)))
                .expect("bind Alice to in-memory transport");

        let topic = Topic::new(user.fingerprint(), "echo");
        let phantom = Fingerprint([0xfeu8; 32]);
        match alice_bus
            .request(phantom, &topic, b"x".to_vec(), Duration::from_millis(200))
            .await
        {
            Err(BusError::Unreachable(_)) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
        alice_bus.close().await.unwrap();
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

    // ── reply dial-candidate resolution ──────────────────────────────────
    // Locations are candidates, never load-bearing
    // (docs/decisions/floating_identity.md). These are pure and deterministic,
    // so they gate every PR; the real dial-back-over-iroh proof stays
    // `#[ignore]`d on the real-LAN tier (see tests/bus_roundtrip.rs).
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    fn lo_v4(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }
    fn lo_v6(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)
    }

    /// Regression for #61: a reply whose observed source is a **scopeless**
    /// link-local IPv6 (`fe80::` with `scope_id == 0` — what mDNS surfaces on
    /// CI / most Linux hosts) must not collapse to one undialable candidate.
    /// Before the fix `dial_reply_peer` dialed `[that one addr]` →
    /// `sendmsg InvalidInput` → a quiet-bind peer's reply was lost. The set
    /// now drops the scopeless addr yet stays reachable via same-host loopback.
    #[test]
    fn scopeless_link_local_source_dropped_loopback_survives() {
        let src: SocketAddr = "[fe80::1]:9000".parse().unwrap(); // scope_id = 0
        let cands = reply_dial_candidates(src);
        assert!(!cands.is_empty(), "identity must retain a usable path");
        assert!(
            !cands.contains(&src),
            "scopeless link-local is undialable; must be filtered out"
        );
        assert!(
            cands.contains(&lo_v4(9000)),
            "same-host v4 loopback must be a candidate"
        );
        assert!(
            cands.contains(&lo_v6(9000)),
            "same-host v6 loopback must be a candidate"
        );
    }

    /// A link-local source WITH a real scope id (`recvmsg` preserved it —
    /// verified present through iroh's noq-udp fork) is dialable, so keep it.
    #[test]
    fn scoped_link_local_source_is_kept() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let src = SocketAddr::V6(SocketAddrV6::new(ip, 9000, 0, 3)); // scope_id = 3
        let cands = reply_dial_candidates(src);
        assert!(
            cands.contains(&src),
            "a scoped link-local is dialable; keep it"
        );
    }

    /// A routable source yields itself plus both loopbacks — never a single
    /// load-bearing address (floating-identity laws #1/#2).
    #[test]
    fn routable_source_yields_source_plus_loopback() {
        let src: SocketAddr = "192.0.2.50:9000".parse().unwrap(); // RFC 5737 TEST-NET-1
        let cands = reply_dial_candidates(src);
        assert!(cands.contains(&src));
        assert!(cands.contains(&lo_v4(9000)));
        assert!(cands.contains(&lo_v6(9000)));
        assert!(cands.len() >= 2, "never a single load-bearing address");
    }

    /// QUIC uses one socket both directions, so the source port is also the
    /// dial-back port for loopback. A loopback source must not be duplicated.
    #[test]
    fn loopback_source_not_duplicated() {
        let src = lo_v4(9000);
        let cands = reply_dial_candidates(src);
        assert_eq!(
            cands.iter().filter(|a| **a == src).count(),
            1,
            "no duplicate loopback candidate"
        );
    }

    /// `fe80::/10` with no scope is poison; scoped link-local, loopback,
    /// global, IPv4, and `fec0::` (outside the /10) are all fine.
    #[test]
    fn scopeless_link_local_predicate_boundaries() {
        assert!(is_scopeless_link_local(&"[fe80::abcd]:1".parse().unwrap()));
        assert!(is_scopeless_link_local(&"[febf::1]:1".parse().unwrap())); // top of /10
        let scoped = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 1, 0, 2));
        assert!(!is_scopeless_link_local(&scoped));
        assert!(!is_scopeless_link_local(&"[::1]:1".parse().unwrap()));
        assert!(!is_scopeless_link_local(
            &"[2001:db8::1]:1".parse().unwrap()
        ));
        assert!(!is_scopeless_link_local(&"127.0.0.1:1".parse().unwrap()));
        assert!(!is_scopeless_link_local(&"[fec0::1]:1".parse().unwrap())); // outside /10
    }

    // ── Decision probe (#61 / floating-identity) ────────────────────────────
    //
    // The `#[ignore]`d mDNS integration tests can't answer the sufficiency
    // question deterministically: *what does iroh's `incoming.remote_addr()`
    // actually report for a same-host dial, and does the `reply_dial_candidates`
    // set actually reconnect to it?* These do. Each binds two REAL transport
    // endpoints, dials asker→responder over a chosen local path, has the
    // responder observe the source exactly as `accept_conn` does, and then dials
    // the asker BACK over the candidate set — proving the reply route is
    // reachable end to end. The observed source is logged as the empirical
    // record for deciding whether the candidate-set fix (`#63`) suffices or the
    // upstream scope-id-preserving work is still owed.

    /// Bind two real endpoints, dial the responder at `target_ip:<responder
    /// port>`, and return `(source the responder observed, did the dial-back
    /// over `reply_dial_candidates` reconnect)`.
    async fn observe_and_dial_back(target_ip: IpAddr) -> (SocketAddr, bool) {
        let user = UserKey::generate();
        let asker = agent(&user, "probe-asker");
        let responder = agent(&user, "probe-responder");
        let a_ep = Arc::new(Endpoint::bind(&asker, 0).await.expect("bind asker"));
        let b_ep = Arc::new(Endpoint::bind(&responder, 0).await.expect("bind responder"));
        let a_pubkey = a_ep.public_key();
        let b_pubkey = b_ep.public_key();
        let target = SocketAddr::new(target_ip, b_ep.port());

        // Asker keeps accepting so the dial-back can finish its handshake.
        let a_accept = a_ep.clone();
        let a_task = tokio::spawn(async move {
            while let Some(incoming) = a_accept.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });

        // Responder accepts once, records the observed source EXACTLY as
        // `accept_conn` does, then finishes the handshake.
        let (tx, rx) = tokio::sync::oneshot::channel::<Option<SocketAddr>>();
        let b_accept = b_ep.clone();
        let b_task = tokio::spawn(async move {
            if let Some(incoming) = b_accept.accept().await {
                let src = match incoming.remote_addr() {
                    IncomingAddr::Ip(addr) => Some(addr),
                    _ => None,
                };
                let _ = tx.send(src);
                let _ = incoming.await;
            }
        });

        a_ep.dial(b_pubkey, [target])
            .await
            .expect("asker dials responder over the chosen local path");

        let observed = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("responder observed a source within 5s")
            .expect("observation channel not dropped")
            .expect("iroh reported an IP source (not a relay path)");

        // Doctrine invariant: the reply route is a non-empty candidate set that
        // reconnects to the *identity*, never a single load-bearing address.
        let candidates = reply_dial_candidates(observed);
        assert!(
            !candidates.is_empty(),
            "candidate set must never be empty for a same-host peer"
        );
        let dial_back_ok = b_ep
            .dial(a_pubkey, candidates.iter().copied())
            .await
            .is_ok();

        b_task.abort();
        a_task.abort();
        (observed, dial_back_ok)
    }

    /// Dialing the responder over IPv4 loopback: the observed source must be a
    /// dialable (non-scopeless-link-local) address, and the candidate-set
    /// dial-back must reconnect. Evidence for the common same-host case.
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_loopback_v4_source_is_dialable_and_reconnects() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let (observed, dial_back_ok) = observe_and_dial_back(Ipv4Addr::LOCALHOST.into()).await;
        eprintln!("[#61 probe] loopback-v4 dial → iroh observed source = {observed}");
        assert!(
            !is_scopeless_link_local(&observed),
            "a same-host loopback source must not be an undialable scopeless link-local"
        );
        assert!(
            dial_back_ok,
            "responder must reconnect to the asker over reply_dial_candidates({observed})"
        );
    }

    /// Same probe over IPv6 loopback. Records what iroh reports for a v6 path.
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_loopback_v6_source_is_dialable_and_reconnects() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let (observed, dial_back_ok) = observe_and_dial_back(Ipv6Addr::LOCALHOST.into()).await;
        eprintln!("[#61 probe] loopback-v6 dial → iroh observed source = {observed}");
        assert!(
            !is_scopeless_link_local(&observed),
            "a same-host loopback source must not be an undialable scopeless link-local"
        );
        assert!(
            dial_back_ok,
            "responder must reconnect to the asker over reply_dial_candidates({observed})"
        );
    }

    /// **The decisive #61 case.** When iroh surfaces a *scopeless* link-local
    /// source (`fe80::`, `scope_id == 0` — undialable; what mDNS surfaces on CI
    /// and most Linux hosts), the candidate set must drop it yet still reach the
    /// same-host peer. Proven end to end over REAL iroh: build the candidate set
    /// from the exact #61-shaped source at the asker's real port, then dial the
    /// asker back over it — the surviving loopback candidate must reconnect. This
    /// is the deterministic answer the `#[ignore]`d mDNS test can't give: for a
    /// same-host peer, `#63`'s fix delivers even in the worst-case source shape.
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_scopeless_link_local_source_reconnects_via_loopback_fallback() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let user = UserKey::generate();
        let asker = agent(&user, "probe-asker");
        let responder = agent(&user, "probe-responder");
        let a_ep = Arc::new(Endpoint::bind(&asker, 0).await.expect("bind asker"));
        let b_ep = Arc::new(Endpoint::bind(&responder, 0).await.expect("bind responder"));

        // Asker keeps accepting so the dial-back can complete.
        let a_accept = a_ep.clone();
        let a_task = tokio::spawn(async move {
            while let Some(incoming) = a_accept.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });

        // The exact #61 shape: a scopeless link-local at the asker's *real* port.
        let scopeless_source = SocketAddr::V6(SocketAddrV6::new(
            "fe80::dead:beef".parse().unwrap(),
            a_ep.port(),
            0,
            0, // scope_id 0 → undialable
        ));
        assert!(
            is_scopeless_link_local(&scopeless_source),
            "precondition: the source is the undialable #61 shape"
        );

        let candidates = reply_dial_candidates(scopeless_source);
        assert!(
            !candidates.contains(&scopeless_source),
            "the undialable scopeless link-local must be filtered out of the set"
        );
        assert!(
            !candidates.is_empty(),
            "the identity must retain a reachable candidate (loopback)"
        );

        let dial_back_ok = b_ep
            .dial(a_ep.public_key(), candidates.iter().copied())
            .await
            .is_ok();
        a_task.abort();
        assert!(
            dial_back_ok,
            "responder must reach the same-host asker via loopback despite an \
             undialable scopeless link-local source ({scopeless_source})"
        );
    }
}
