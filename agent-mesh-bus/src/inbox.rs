//! [`Inbox`] — application-level message dispatch on top of
//! [`SignedEnvelope`] framing.
//!
//! The inbox is the common admission boundary: it verifies each envelope and
//! binds its signer to transport-authenticated provenance before deciding what
//! the message *means*. A [`BusMessage::Request`] runs a registered handler, a
//! [`BusMessage::Reply`] resolves an in-flight oneshot, and a
//! [`BusMessage::Publish`] fans out to topic subscribers.
//!
//! The inbox is the single place where replay + sequence checks
//! happen. Calling code (the [`crate::bus::Bus`]) doesn't have to
//! remember to invoke them.

use crate::replay::{NonceCache, SequenceTracker};
use crate::reply::{CorrelationId, ReplyDelivery, ReplyPeerCheck, ReplyWaiter};
use crate::topic::Topic;
use crate::transport::DeliveryProvenance;
use crate::{BusError, Result};
use agent_mesh_protocol::{Fingerprint, Recipient, SignedEnvelope};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{broadcast, oneshot, RwLock};

/// Default capacity of broadcast channels backing per-topic
/// subscriptions. Subscribers that lag behind by more than this many
/// messages get `RecvError::Lagged` and have to resubscribe; this is
/// the right behavior for our load-shedding use case.
const SUBSCRIPTION_CHANNEL_CAPACITY: usize = 64;

/// Wire form of an application-level bus message. Carried as the
/// `payload` of a [`SignedEnvelope`] in JSON.
///
/// Three kinds in v1:
///
/// * [`Request`](Self::Request) — caller expects a matching
///   [`Reply`](Self::Reply) keyed by `correlation`.
/// * [`Reply`](Self::Reply) — the response.
/// * [`Publish`](Self::Publish) — fire-and-forget broadcast to anyone
///   subscribed to `topic`. v1 is peer-explicit: the sender names the
///   peer, the receiver's inbox fans out to subscribers locally. A
///   topic-routing registry is deferred to a follow-up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BusMessage {
    /// Request a reply on `topic`. The `correlation` identifies which
    /// `Reply` belongs to which `Request`.
    Request {
        /// Wire-form topic (see [`Topic::wire`]).
        topic: String,
        /// 16-byte correlation id, echoed back in the matching reply.
        correlation: [u8; 16],
        /// Application payload.
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    /// Reply to a previous `Request`. The `correlation` matches the
    /// originating request's id.
    Reply {
        /// 16-byte correlation id from the originating request.
        correlation: [u8; 16],
        /// Application payload.
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    /// Fire-and-forget publish to `topic`. Subscribers on the receiving
    /// side get the body via their `broadcast::Receiver`.
    Publish {
        /// Wire-form topic (see [`Topic::wire`]).
        topic: String,
        /// Application payload.
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
}

/// The verified principal behind an inbound request: who signed the envelope.
///
/// Both fingerprints are authenticated, not claimed. Every inbound envelope is
/// `verify()`-ed at this common admission boundary before replay state changes:
/// the agent signature is checked against the envelope's cert chain, the chain
/// proves the user→agent delegation, and direct-delivery provenance binds that
/// original signer to the transport-authenticated carrier. So
/// `caller_agent_fp` is `BLAKE3(cert_chain.agent_pubkey)` of whoever actually
/// signed this request, and `caller_user_fp` is their operator root. A handler
/// may authorize on these without re-verifying anything.
///
/// This is the *signer* of the request, which is the correct principal for
/// authorization: a relay can only deliver a request its signer already
/// authorized, never mint one under another agent's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// The caller's operator root fingerprint (`env.sender_user_fp()`).
    pub caller_user_fp: Fingerprint,
    /// The caller's agent fingerprint (`env.sender_agent_fp()` =
    /// `BLAKE3(agent_pubkey)`), the handle a capability registry keys on.
    pub caller_agent_fp: Fingerprint,
}

/// Type of a registered request handler. Takes the verified caller
/// [`RequestContext`] and the request body, returns the reply body
/// asynchronously.
pub type RequestHandler = Arc<
    dyn Fn(RequestContext, Vec<u8>) -> BoxFuture<'static, Result<Vec<u8>>> + Send + Sync + 'static,
>;

/// What the bus should send out in response to an incoming envelope.
///
/// `on_envelope` returns `Some(OutgoingReply)` when the inbox handled
/// a [`BusMessage::Request`] and produced a reply body — the caller
/// (the bus) is responsible for actually getting those bytes back to
/// the peer.
#[derive(Debug, Clone)]
pub struct OutgoingReply {
    /// Peer agent fingerprint to send to.
    pub peer_fp: Fingerprint,
    /// Correlation id to echo in the [`BusMessage::Reply`].
    pub correlation: CorrelationId,
    /// Reply payload.
    pub body: Vec<u8>,
}

/// In-process routing table + replay defense. One per bus.
pub struct Inbox {
    nonce_cache: NonceCache,
    sequence: SequenceTracker,
    waiters: ReplyWaiter,
    subscriptions: RwLock<HashMap<String, broadcast::Sender<Vec<u8>>>>,
    // Request handlers are guarded by a *synchronous* lock, not a
    // `tokio::sync::RwLock`, so a handler can be registered without an
    // `.await`. That lets `Bus::handle_requests` install the handler
    // before it returns instead of on a spawned task — closing the
    // registration race a directly-dialed request could otherwise lose
    // (see `register_handler`). The guard is only ever held for a
    // `get().cloned()` / `insert()` and never across an `.await`, so it
    // cannot block the async runtime.
    handlers: std::sync::RwLock<HashMap<String, RequestHandler>>,
}

impl Inbox {
    /// Build a fresh, empty inbox.
    ///
    /// Nonce cache defaults to 4096 entries — large enough to span any
    /// realistic burst, small enough that memory cost is trivial.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nonce_cache: NonceCache::new(4096),
            sequence: SequenceTracker::new(),
            waiters: ReplyWaiter::new(),
            subscriptions: RwLock::new(HashMap::new()),
            handlers: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Subscribe to a topic; returns a `broadcast::Receiver` that
    /// will receive every body published to this topic (locally — by
    /// the inbox, on receipt of a [`BusMessage::Publish`]).
    ///
    /// Repeated subscribes to the same topic share one underlying
    /// `broadcast::Sender`.
    pub async fn subscribe(&self, topic: &Topic) -> broadcast::Receiver<Vec<u8>> {
        let key = topic.wire();
        let mut map = self.subscriptions.write().await;
        let tx = map
            .entry(key)
            .or_insert_with(|| broadcast::channel(SUBSCRIPTION_CHANNEL_CAPACITY).0);
        tx.subscribe()
    }

    /// Register a request handler for the given topic.
    ///
    /// Synchronous by design: registration takes only the in-memory
    /// `handlers` lock (never held across an `.await`), so the handler
    /// is live the instant this returns. `Bus::handle_requests` relies
    /// on that to avoid a spawn-and-race window where a freshly-dialed
    /// request could arrive before the handler existed and be silently
    /// dropped.
    ///
    /// Re-registering replaces the previous handler for that topic.
    pub fn register_handler<F, Fut>(&self, topic: Topic, handler: F)
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'static,
    {
        // The context-free convenience: discard the caller principal. Kept so
        // existing body-only handlers need no change.
        let key = topic.wire();
        let boxed: RequestHandler = Arc::new(move |_ctx, body| Box::pin(handler(body)));
        self.handlers
            .write()
            .expect("handlers lock poisoned")
            .insert(key, boxed);
    }

    /// Register a request handler that receives the verified [`RequestContext`]
    /// (the caller's authenticated user + agent fingerprints) alongside the
    /// body — for handlers that must authorize *who* is calling, not just serve
    /// the request. Same synchronous-registration guarantee as
    /// [`Self::register_handler`].
    pub fn register_handler_with_context<F, Fut>(&self, topic: Topic, handler: F)
    where
        F: Fn(RequestContext, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>>> + Send + 'static,
    {
        let key = topic.wire();
        let boxed: RequestHandler = Arc::new(move |ctx, body| Box::pin(handler(ctx, body)));
        self.handlers
            .write()
            .expect("handlers lock poisoned")
            .insert(key, boxed);
    }

    /// Number of registered request handlers (tests + diagnostics).
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.read().expect("handlers lock poisoned").len()
    }

    /// Register an in-flight request waiter, atomically bound to the expected
    /// responder; returns the receiver half of the oneshot that will resolve
    /// when that peer's matching [`BusMessage::Reply`] arrives.
    pub fn register_reply(
        &self,
        id: CorrelationId,
        expected_peer_fp: Fingerprint,
    ) -> oneshot::Receiver<Vec<u8>> {
        self.waiters.register(id, expected_peer_fp)
    }

    /// Drop a waiter for `id` without delivering anything.
    pub fn cancel_reply(&self, id: &CorrelationId) {
        self.waiters.cancel(id);
    }

    /// Number of currently in-flight reply waiters.
    #[must_use]
    pub fn pending_replies(&self) -> usize {
        self.waiters.pending()
    }

    /// Borrow the underlying nonce cache (tests + diagnostics).
    #[must_use]
    pub fn nonce_cache(&self) -> &NonceCache {
        &self.nonce_cache
    }

    /// Borrow the underlying sequence tracker (tests + diagnostics).
    #[must_use]
    pub fn sequence_tracker(&self) -> &SequenceTracker {
        &self.sequence
    }

    /// Admit an inbound envelope into the inbox. Returns
    /// `Ok(Some(reply))` if the envelope carried a `Request` we have
    /// a handler for; the caller (the bus) ships that reply back.
    ///
    /// Admission is deliberately transport-neutral and fail-closed. It first
    /// verifies the envelope, then binds its original signer to the
    /// transport-authenticated direct carrier and the local same-user policy,
    /// then checks a direct recipient. Only after all of those immutable checks
    /// pass may nonce or sequence state be mutated.
    ///
    /// A reply for a known waiter then gets a non-consuming expected-peer check
    /// so a mismatched signer cannot poison replay state with a copied nonce.
    /// Unknown replies retain the normal nonce-first path. After admission and
    /// that targeted precheck, replay defense checks the nonce and then the
    /// per-peer sequence before any dispatch happens.
    pub async fn on_envelope(
        &self,
        env: SignedEnvelope,
        provenance: DeliveryProvenance,
        local_user_fp: Fingerprint,
        local_agent_fp: Fingerprint,
    ) -> Result<Option<OutgoingReply>> {
        // Verification belongs here even when a framing implementation already
        // did it. A Transport implementation must never be able to bypass the
        // cert-chain, CID, and signature checks before replay state changes.
        env.verify()?;

        // Keep these names distinct: `carrier` is authenticated by the
        // transport session; `signer_*` comes from the verified envelope. They
        // are equal only because today's sole delivery mode is direct. A future
        // authorized relay must get a separate provenance variant + policy.
        let carrier = match provenance {
            DeliveryProvenance::Direct { carrier } => carrier,
            DeliveryProvenance::Unbound => return Err(BusError::UnboundDelivery),
        };
        let signer_agent_fp = env.sender_agent_fp();
        let signer_user_fp = env.sender_user_fp();

        if carrier.agent_fp != signer_agent_fp {
            return Err(BusError::CarrierAgentMismatch {
                carrier_agent_fp: carrier.agent_fp.hex(),
                signer_agent_fp: signer_agent_fp.hex(),
            });
        }
        if carrier.user_fp != signer_user_fp {
            return Err(BusError::CarrierUserMismatch {
                carrier_user_fp: carrier.user_fp.hex(),
                signer_user_fp: signer_user_fp.hex(),
            });
        }
        if signer_user_fp != local_user_fp {
            return Err(BusError::ForeignPeer {
                peer_user_fp: signer_user_fp.hex(),
                local_user_fp: local_user_fp.hex(),
            });
        }
        if let Recipient::Direct { agent_fp } = &env.recipient {
            if *agent_fp != local_agent_fp {
                return Err(BusError::WrongRecipient {
                    recipient_agent_fp: agent_fp.hex(),
                    local_agent_fp: local_agent_fp.hex(),
                });
            }
        }

        let peer_fp = signer_agent_fp;
        let parsed_msg = serde_json::from_slice::<BusMessage>(env.payload.as_ref());

        // Correlations are bound to the request target, not merely unguessable.
        // Reject a known mismatch before touching the sender-agnostic nonce
        // cache: an observer may know both the correlation and the honest
        // reply's nonce, but must not be able to poison replay state by signing
        // those values as a different agent. `deliver` repeats the comparison
        // under its remove lock after replay checks to close local races.
        // Keep a parse failure pending until after replay state is updated, so
        // malformed signed envelopes retain the existing nonce-first behavior.
        if let Ok(BusMessage::Reply { correlation, .. }) = &parsed_msg {
            let cid = CorrelationId(*correlation);
            if let ReplyPeerCheck::PeerMismatch {
                expected_peer_fp,
                actual_peer_fp,
            } = self.waiters.check_peer(cid, peer_fp)
            {
                tracing::warn!(
                    correlation = %cid.hex(),
                    expected_peer = %expected_peer_fp.short(),
                    actual_peer = %actual_peer_fp.short(),
                    "inbox: rejecting reply from unexpected peer"
                );
                return Ok(None);
            }
        }

        if !self.nonce_cache.check_and_insert(env.nonce) {
            tracing::warn!(
                sender = %env.sender_agent_fp().short(),
                "inbox: rejecting envelope (duplicate nonce)"
            );
            return Err(BusError::Replay);
        }
        if let Err((expected, actual)) = self.sequence.check_and_advance(peer_fp, env.sequence) {
            tracing::warn!(
                sender = %peer_fp.short(),
                expected,
                actual,
                "inbox: rejecting envelope (bad sequence)"
            );
            return Err(BusError::BadSequence {
                peer_fp: peer_fp.hex(),
                expected,
                actual,
            });
        }

        let msg = parsed_msg?;

        // Build the verified original-signer principal. The carrier was checked
        // separately above and is not silently substituted for this identity.
        let ctx = RequestContext {
            caller_user_fp: signer_user_fp,
            caller_agent_fp: peer_fp,
        };

        match msg {
            BusMessage::Request {
                topic,
                correlation,
                body,
            } => self.dispatch_request(ctx, topic, correlation, body).await,
            BusMessage::Reply { correlation, body } => {
                let cid = CorrelationId(correlation);
                match self.waiters.deliver(cid, peer_fp, body) {
                    ReplyDelivery::Delivered => {}
                    ReplyDelivery::Unknown => tracing::debug!(
                        correlation = %cid.hex(),
                        "inbox: reply for unknown correlation (timed out or never registered)"
                    ),
                    ReplyDelivery::PeerMismatch {
                        expected_peer_fp,
                        actual_peer_fp,
                    } => tracing::warn!(
                        correlation = %cid.hex(),
                        expected_peer = %expected_peer_fp.short(),
                        actual_peer = %actual_peer_fp.short(),
                        "inbox: rejecting reply from unexpected peer"
                    ),
                    ReplyDelivery::ReceiverDropped => tracing::debug!(
                        correlation = %cid.hex(),
                        "inbox: reply receiver was dropped"
                    ),
                }
                Ok(None)
            }
            BusMessage::Publish { topic, body } => {
                self.dispatch_publish(topic, body).await;
                Ok(None)
            }
        }
    }

    async fn dispatch_request(
        &self,
        ctx: RequestContext,
        topic: String,
        correlation: [u8; 16],
        body: Vec<u8>,
    ) -> Result<Option<OutgoingReply>> {
        let handler = {
            let map = self.handlers.read().expect("handlers lock poisoned");
            map.get(&topic).cloned()
        };
        let Some(handler) = handler else {
            tracing::debug!(topic = %topic, "inbox: no handler for request topic");
            return Ok(None);
        };
        let peer_fp = ctx.caller_agent_fp;
        let reply_body = handler(ctx, body).await?;
        Ok(Some(OutgoingReply {
            peer_fp,
            correlation: CorrelationId(correlation),
            body: reply_body,
        }))
    }

    async fn dispatch_publish(&self, topic: String, body: Vec<u8>) {
        let tx = {
            let map = self.subscriptions.read().await;
            map.get(&topic).cloned()
        };
        if let Some(tx) = tx {
            // `send` only errs if there are zero receivers; that's
            // legitimate (subscribers unsubscribed mid-flight) and
            // not worth logging at warn.
            let _ = tx.send(body);
        } else {
            tracing::debug!(topic = %topic, "inbox: publish to topic with no subscribers");
        }
    }
}

impl Default for Inbox {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::AuthenticatedPeer;
    use agent_mesh_protocol::{
        AgentKey, AgentMetadata, Caveats, MeshError, Recipient, SerdeSig, SignedEnvelope, UserKey,
    };

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

    fn envelope(
        sender: &AgentKey,
        recipient_fp: Fingerprint,
        seq: u64,
        body: &BusMessage,
    ) -> SignedEnvelope {
        let payload = serde_json::to_vec(body).expect("encode bus msg");
        SignedEnvelope::new(
            sender,
            Recipient::Direct {
                agent_fp: recipient_fp,
            },
            seq,
            payload,
        )
    }

    fn direct(agent: &AgentKey) -> DeliveryProvenance {
        DeliveryProvenance::Direct {
            carrier: AuthenticatedPeer::new(agent.cert().user_fingerprint(), agent.fingerprint()),
        }
    }

    async fn rejection_does_not_poison_replay_state<F>(
        rejected_env: SignedEnvelope,
        accepted_env: SignedEnvelope,
        rejected_admission: (DeliveryProvenance, Fingerprint, Fingerprint),
        accepted_admission: (DeliveryProvenance, Fingerprint, Fingerprint),
        assert_error: F,
    ) where
        F: FnOnce(BusError),
    {
        assert_eq!(
            rejected_env.nonce, accepted_env.nonce,
            "negative and positive controls must exercise the same nonce"
        );
        assert_eq!(
            rejected_env.sequence, accepted_env.sequence,
            "negative and positive controls must exercise the same sequence"
        );
        let signer_fp = accepted_env.sender_agent_fp();
        let inbox = Inbox::new();

        let err = inbox
            .on_envelope(
                rejected_env,
                rejected_admission.0,
                rejected_admission.1,
                rejected_admission.2,
            )
            .await
            .expect_err("admission must reject the negative control");
        assert_error(err);
        assert!(
            inbox.nonce_cache().is_empty(),
            "failed admission must not insert the nonce"
        );
        assert_eq!(
            inbox.sequence_tracker().last_seen(&signer_fp),
            None,
            "failed admission must not advance sender sequence"
        );

        inbox
            .on_envelope(
                accepted_env,
                accepted_admission.0,
                accepted_admission.1,
                accepted_admission.2,
            )
            .await
            .expect("the same nonce + sequence must remain admissible");
        assert_eq!(inbox.nonce_cache().len(), 1);
        assert_eq!(inbox.sequence_tracker().last_seen(&signer_fp), Some(1));
    }

    fn publish_envelope(sender: &AgentKey, recipient_fp: Fingerprint) -> SignedEnvelope {
        envelope(
            sender,
            recipient_fp,
            1,
            &BusMessage::Publish {
                topic: "admission:test".into(),
                body: b"payload".to_vec(),
            },
        )
    }

    /// Replace an envelope nonce and re-sign it so tests can construct two
    /// independently valid envelopes with the same nonce. This mirrors the
    /// v1 signing transcript in `agent_mesh_protocol::SignedEnvelope`.
    fn set_nonce_and_resign(env: &mut SignedEnvelope, sender: &AgentKey, nonce: [u8; 24]) {
        env.nonce = nonce;
        let recipient_bytes = serde_json::to_vec(&env.recipient).expect("encode recipient");
        let mut message = Vec::with_capacity(
            b"agent-mesh-envelope-v1".len() + recipient_bytes.len() + 24 + 8 + 32,
        );
        message.extend_from_slice(b"agent-mesh-envelope-v1");
        message.extend_from_slice(&recipient_bytes);
        message.extend_from_slice(&env.nonce);
        message.extend_from_slice(&env.sequence.to_be_bytes());
        message.extend_from_slice(&env.payload_cid);
        env.agent_sig = SerdeSig(sender.sign(&message));
        env.verify().expect("re-signed test envelope must verify");
    }

    #[test]
    fn bus_message_serde_roundtrip_all_variants() {
        for msg in [
            BusMessage::Request {
                topic: "u:t".into(),
                correlation: [0x11; 16],
                body: b"req".to_vec(),
            },
            BusMessage::Reply {
                correlation: [0x22; 16],
                body: b"rep".to_vec(),
            },
            BusMessage::Publish {
                topic: "u:t".into(),
                body: b"pub".to_vec(),
            },
        ] {
            let j = serde_json::to_vec(&msg).unwrap();
            let back: BusMessage = serde_json::from_slice(&j).unwrap();
            assert_eq!(back, msg);
        }
    }

    #[tokio::test]
    async fn unbound_delivery_is_rejected_before_replay_state() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let env = publish_envelope(&alice, bob.fingerprint());

        rejection_does_not_poison_replay_state(
            env.clone(),
            env,
            (
                DeliveryProvenance::Unbound,
                user.fingerprint(),
                bob.fingerprint(),
            ),
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            |err| assert!(matches!(err, BusError::UnboundDelivery)),
        )
        .await;
    }

    #[tokio::test]
    async fn direct_carrier_must_be_the_original_signer() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let sibling = agent(&user, "sibling-carrier");
        let bob = agent(&user, "bob");
        let env = publish_envelope(&alice, bob.fingerprint());

        rejection_does_not_poison_replay_state(
            env.clone(),
            env,
            (direct(&sibling), user.fingerprint(), bob.fingerprint()),
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            |err| assert!(matches!(err, BusError::CarrierAgentMismatch { .. })),
        )
        .await;
    }

    #[tokio::test]
    async fn carrier_user_root_must_match_original_signer_root() {
        let user = UserKey::generate();
        let stranger = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let env = publish_envelope(&alice, bob.fingerprint());
        let false_carrier_root = DeliveryProvenance::Direct {
            carrier: AuthenticatedPeer::new(stranger.fingerprint(), alice.fingerprint()),
        };

        rejection_does_not_poison_replay_state(
            env.clone(),
            env,
            (false_carrier_root, user.fingerprint(), bob.fingerprint()),
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            |err| assert!(matches!(err, BusError::CarrierUserMismatch { .. })),
        )
        .await;
    }

    #[tokio::test]
    async fn stranger_root_is_rejected_by_local_same_user_policy() {
        let local_user = UserKey::generate();
        let stranger_user = UserKey::generate();
        let stranger = agent(&stranger_user, "stranger");
        let recipient = agent(&stranger_user, "recipient");
        let env = publish_envelope(&stranger, recipient.fingerprint());

        rejection_does_not_poison_replay_state(
            env.clone(),
            env,
            (
                direct(&stranger),
                local_user.fingerprint(),
                recipient.fingerprint(),
            ),
            (
                direct(&stranger),
                stranger_user.fingerprint(),
                recipient.fingerprint(),
            ),
            |err| assert!(matches!(err, BusError::ForeignPeer { .. })),
        )
        .await;
    }

    #[tokio::test]
    async fn bad_signature_is_rejected_before_replay_state() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let env = publish_envelope(&alice, bob.fingerprint());
        let mut bad = env.clone();
        bad.recipient = Recipient::Direct {
            agent_fp: Fingerprint([0x5a; 32]),
        };

        rejection_does_not_poison_replay_state(
            bad,
            env,
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            |err| assert!(matches!(err, BusError::Core(MeshError::BadSignature))),
        )
        .await;
    }

    #[tokio::test]
    async fn cid_mismatch_is_rejected_before_replay_state() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let env = publish_envelope(&alice, bob.fingerprint());
        let mut bad = env.clone();
        bad.payload[0] ^= 0xff;

        rejection_does_not_poison_replay_state(
            bad,
            env,
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            |err| {
                assert!(matches!(
                    err,
                    BusError::Core(MeshError::MalformedEnvelope(_))
                ));
            },
        )
        .await;
    }

    #[tokio::test]
    async fn direct_recipient_must_name_the_local_agent() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let charlie = agent(&user, "charlie");
        let env = publish_envelope(&alice, charlie.fingerprint());

        rejection_does_not_poison_replay_state(
            env.clone(),
            env,
            (direct(&alice), user.fingerprint(), bob.fingerprint()),
            (direct(&alice), user.fingerprint(), charlie.fingerprint()),
            |err| assert!(matches!(err, BusError::WrongRecipient { .. })),
        )
        .await;
    }

    #[tokio::test]
    async fn replay_nonce_is_rejected() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let msg = BusMessage::Publish {
            topic: "x".into(),
            body: b"y".to_vec(),
        };
        let env = envelope(&alice, bob_fp, 1, &msg);

        let inbox = Inbox::new();
        inbox
            .on_envelope(env.clone(), direct(&alice), user.fingerprint(), bob_fp)
            .await
            .expect("first");
        let err = inbox
            .on_envelope(env, direct(&alice), user.fingerprint(), bob_fp)
            .await
            .unwrap_err();
        assert!(matches!(err, BusError::Replay));
    }

    #[tokio::test]
    async fn malformed_signed_payload_still_consumes_replay_state() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let env = SignedEnvelope::new(
            &alice,
            Recipient::Direct { agent_fp: bob_fp },
            1,
            b"not a bus message".to_vec(),
        );
        let inbox = Inbox::new();

        let first = inbox
            .on_envelope(env.clone(), direct(&alice), user.fingerprint(), bob_fp)
            .await
            .expect_err("malformed payload must fail decoding");
        assert!(matches!(first, BusError::Json(_)));
        assert_eq!(inbox.nonce_cache().len(), 1);
        assert_eq!(
            inbox.sequence_tracker().last_seen(&alice.fingerprint()),
            Some(1)
        );

        let replay = inbox
            .on_envelope(env, direct(&alice), user.fingerprint(), bob_fp)
            .await
            .expect_err("the same malformed signed envelope is still a replay");
        assert!(matches!(replay, BusError::Replay));
    }

    #[tokio::test]
    async fn out_of_order_sequence_is_rejected() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let msg = BusMessage::Publish {
            topic: "x".into(),
            body: b"y".to_vec(),
        };
        let inbox = Inbox::new();
        inbox
            .on_envelope(
                envelope(&alice, bob_fp, 5, &msg),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap();
        let err = inbox
            .on_envelope(
                envelope(&alice, bob_fp, 4, &msg),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap_err();
        match err {
            BusError::BadSequence {
                expected, actual, ..
            } => {
                assert_eq!((expected, actual), (6, 4));
            }
            other => panic!("expected BadSequence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_with_registered_handler_produces_outgoing_reply() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let alice_fp = alice.fingerprint();
        let bob_fp = agent(&user, "bob").fingerprint();
        let topic = Topic::new(user.fingerprint(), "echo");

        let inbox = Inbox::new();
        inbox.register_handler(topic.clone(), |body| async move {
            Ok([b"echo:".to_vec(), body].concat())
        });

        let req = BusMessage::Request {
            topic: topic.wire(),
            correlation: [0x42; 16],
            body: b"hi".to_vec(),
        };
        let env = envelope(&alice, bob_fp, 1, &req);
        let out = inbox
            .on_envelope(env, direct(&alice), user.fingerprint(), bob_fp)
            .await
            .unwrap()
            .expect("reply produced");
        assert_eq!(out.peer_fp, alice_fp);
        assert_eq!(out.correlation.0, [0x42; 16]);
        assert_eq!(out.body, b"echo:hi");
    }

    #[tokio::test]
    async fn a_context_handler_receives_the_verified_caller_fingerprints() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let topic = Topic::new(user.fingerprint(), "whoami");

        let inbox = Inbox::new();
        // The handler echoes back the caller principal it was handed, so the
        // test can prove it is the ACTUAL signer of the envelope (alice), not a
        // value copied from the request body.
        inbox.register_handler_with_context(
            topic.clone(),
            |ctx: RequestContext, _body| async move {
                Ok(
                    format!("{}|{}", ctx.caller_user_fp.hex(), ctx.caller_agent_fp.hex())
                        .into_bytes(),
                )
            },
        );

        let req = BusMessage::Request {
            topic: topic.wire(),
            correlation: [0x7; 16],
            body: b"ignored".to_vec(),
        };
        let out = inbox
            .on_envelope(
                envelope(&alice, bob_fp, 1, &req),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap()
            .expect("reply produced");
        let got = String::from_utf8(out.body).unwrap();
        assert_eq!(
            got,
            format!("{}|{}", user.fingerprint().hex(), alice.fingerprint().hex()),
            "the handler must see alice's authenticated user+agent fingerprints"
        );
    }

    #[tokio::test]
    async fn request_with_no_handler_returns_none() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let topic = Topic::new(user.fingerprint(), "missing");
        let req = BusMessage::Request {
            topic: topic.wire(),
            correlation: [0x77; 16],
            body: b"".to_vec(),
        };
        let inbox = Inbox::new();
        let out = inbox
            .on_envelope(
                envelope(&alice, bob_fp, 1, &req),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn reply_delivers_to_waiter() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();

        let inbox = Inbox::new();
        let cid = CorrelationId([0x55; 16]);
        let rx = inbox.register_reply(cid, alice.fingerprint());
        assert_eq!(inbox.pending_replies(), 1);

        let rep = BusMessage::Reply {
            correlation: cid.0,
            body: b"ok".to_vec(),
        };
        let out = inbox
            .on_envelope(
                envelope(&alice, bob_fp, 1, &rep),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap();
        assert!(out.is_none());
        assert_eq!(rx.await.unwrap(), b"ok");
        assert_eq!(inbox.pending_replies(), 0);
    }

    #[tokio::test]
    async fn reply_from_unexpected_signer_leaves_waiter_for_expected_peer() {
        let user = UserKey::generate();
        let expected = agent(&user, "expected");
        let attacker = agent(&user, "attacker");
        let recipient_fp = agent(&user, "recipient").fingerprint();

        let inbox = Inbox::new();
        let cid = CorrelationId([0x56; 16]);
        let rx = inbox.register_reply(cid, expected.fingerprint());
        let forged = BusMessage::Reply {
            correlation: cid.0,
            body: b"forged".to_vec(),
        };
        inbox
            .on_envelope(
                envelope(&attacker, recipient_fp, 1, &forged),
                direct(&attacker),
                user.fingerprint(),
                recipient_fp,
            )
            .await
            .unwrap();
        assert_eq!(
            inbox.pending_replies(),
            1,
            "unexpected signer must not consume the waiter"
        );

        let legitimate = BusMessage::Reply {
            correlation: cid.0,
            body: b"legitimate".to_vec(),
        };
        inbox
            .on_envelope(
                envelope(&expected, recipient_fp, 1, &legitimate),
                direct(&expected),
                user.fingerprint(),
                recipient_fp,
            )
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap(), b"legitimate");
        assert_eq!(inbox.pending_replies(), 0);
    }

    #[tokio::test]
    async fn mismatched_reply_cannot_poison_honest_reply_nonce() {
        let user = UserKey::generate();
        let expected = agent(&user, "expected");
        let attacker = agent(&user, "attacker");
        let recipient_fp = agent(&user, "recipient").fingerprint();

        let inbox = Inbox::new();
        let cid = CorrelationId([0x57; 16]);
        let rx = inbox.register_reply(cid, expected.fingerprint());
        let reply = BusMessage::Reply {
            correlation: cid.0,
            body: b"legitimate".to_vec(),
        };
        let legitimate = envelope(&expected, recipient_fp, 1, &reply);
        legitimate.verify().expect("honest reply verifies");

        let mut forged = envelope(&attacker, recipient_fp, 1, &reply);
        set_nonce_and_resign(&mut forged, &attacker, legitimate.nonce);
        assert_eq!(forged.nonce, legitimate.nonce, "test precondition");
        assert_ne!(
            forged.sender_agent_fp(),
            legitimate.sender_agent_fp(),
            "test precondition"
        );

        inbox
            .on_envelope(forged, direct(&attacker), user.fingerprint(), recipient_fp)
            .await
            .unwrap();
        assert_eq!(
            inbox.nonce_cache().len(),
            0,
            "known signer mismatch must not mutate replay state"
        );
        assert_eq!(
            inbox.sequence_tracker().last_seen(&attacker.fingerprint()),
            None,
            "known signer mismatch must not advance its sequence"
        );
        assert_eq!(inbox.pending_replies(), 1);

        inbox
            .on_envelope(
                legitimate,
                direct(&expected),
                user.fingerprint(),
                recipient_fp,
            )
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap(), b"legitimate");
        assert_eq!(inbox.pending_replies(), 0);
    }

    #[tokio::test]
    async fn reply_for_unknown_correlation_is_silently_dropped() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let inbox = Inbox::new();
        let rep = BusMessage::Reply {
            correlation: [0x99; 16],
            body: b"orphan".to_vec(),
        };
        // No waiter → still Ok(None); no error.
        let out = inbox
            .on_envelope(
                envelope(&alice, bob_fp, 1, &rep),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn publish_broadcasts_to_subscribers() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let topic = Topic::new(user.fingerprint(), "pub");

        let inbox = Inbox::new();
        let mut rx1 = inbox.subscribe(&topic).await;
        let mut rx2 = inbox.subscribe(&topic).await;

        let pub_msg = BusMessage::Publish {
            topic: topic.wire(),
            body: b"hello".to_vec(),
        };
        inbox
            .on_envelope(
                envelope(&alice, bob_fp, 1, &pub_msg),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap();
        assert_eq!(rx1.recv().await.unwrap(), b"hello");
        assert_eq!(rx2.recv().await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_noop() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob_fp = agent(&user, "bob").fingerprint();
        let topic = Topic::new(user.fingerprint(), "nobody-home");
        let pub_msg = BusMessage::Publish {
            topic: topic.wire(),
            body: b"x".to_vec(),
        };
        let inbox = Inbox::new();
        // Doesn't error or panic — just silently dropped.
        inbox
            .on_envelope(
                envelope(&alice, bob_fp, 1, &pub_msg),
                direct(&alice),
                user.fingerprint(),
                bob_fp,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancel_reply_drops_waiter() {
        let inbox = Inbox::new();
        let cid = CorrelationId([0xaa; 16]);
        let _rx = inbox.register_reply(cid, Fingerprint([0x01; 32]));
        assert_eq!(inbox.pending_replies(), 1);
        inbox.cancel_reply(&cid);
        assert_eq!(inbox.pending_replies(), 0);
    }

    #[tokio::test]
    async fn default_inbox_is_empty() {
        let inbox = Inbox::default();
        assert_eq!(inbox.pending_replies(), 0);
        assert!(inbox.nonce_cache().is_empty());
    }
}
