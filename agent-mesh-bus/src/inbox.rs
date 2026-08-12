//! [`Inbox`] — application-level message dispatch on top of
//! [`SignedEnvelope`] framing.
//!
//! Where the transport delivers verified envelopes, the inbox decides
//! what they *mean* — a [`BusMessage::Request`] runs a registered
//! handler, a [`BusMessage::Reply`] resolves an in-flight oneshot,
//! a [`BusMessage::Publish`] fans out to topic subscribers.
//!
//! The inbox is the single place where replay + sequence checks
//! happen. Calling code (the [`crate::bus::Bus`]) doesn't have to
//! remember to invoke them.

use crate::replay::{NonceCache, SequenceTracker};
use crate::reply::{CorrelationId, ReplyWaiter};
use crate::topic::Topic;
use crate::{BusError, Result};
use agent_mesh_protocol::{Fingerprint, SignedEnvelope};
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
/// `verify()`-ed at the transport boundary (`recv_envelope`) before it reaches
/// the inbox — the agent signature is checked against the envelope's cert chain,
/// and the chain proves the user→agent delegation. So `caller_agent_fp` is
/// `BLAKE3(cert_chain.agent_pubkey)` of whoever actually signed this request,
/// and `caller_user_fp` is their operator root. A handler may authorize on these
/// without re-verifying anything.
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

    /// Register an in-flight request waiter; returns the receiver
    /// half of the oneshot that will resolve when the matching
    /// [`BusMessage::Reply`] arrives.
    pub fn register_reply(&self, id: CorrelationId) -> oneshot::Receiver<Vec<u8>> {
        self.waiters.register(id)
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

    /// Feed a verified envelope into the inbox. Returns
    /// `Ok(Some(reply))` if the envelope carried a `Request` we have
    /// a handler for; the caller (the bus) ships that reply back.
    ///
    /// Replay-defense order: nonce check first (cheap, in-memory
    /// hash set), then sequence check (per-peer monotonic). Both
    /// must pass before any dispatch happens.
    pub async fn on_envelope(&self, env: SignedEnvelope) -> Result<Option<OutgoingReply>> {
        if !self.nonce_cache.check_and_insert(env.nonce) {
            tracing::warn!(
                sender = %env.sender_agent_fp().short(),
                "inbox: rejecting envelope (duplicate nonce)"
            );
            return Err(BusError::Replay);
        }
        let peer_fp = env.sender_agent_fp();
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

        // Build the verified caller principal from the (already-verified)
        // envelope. Both fingerprints are authenticated by env.verify() at the
        // transport boundary — see RequestContext.
        let ctx = RequestContext {
            caller_user_fp: env.sender_user_fp(),
            caller_agent_fp: peer_fp,
        };

        let msg: BusMessage = serde_json::from_slice(env.payload.as_ref())?;
        match msg {
            BusMessage::Request {
                topic,
                correlation,
                body,
            } => self.dispatch_request(ctx, topic, correlation, body).await,
            BusMessage::Reply { correlation, body } => {
                let cid = CorrelationId(correlation);
                let delivered = self.waiters.deliver(cid, body);
                if !delivered {
                    tracing::debug!(
                        correlation = %cid.hex(),
                        "inbox: reply for unknown correlation (timed out or never registered)"
                    );
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
    use agent_mesh_protocol::{
        AgentKey, AgentMetadata, Caveats, Recipient, SignedEnvelope, UserKey,
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
        inbox.on_envelope(env.clone()).await.expect("first");
        let err = inbox.on_envelope(env).await.unwrap_err();
        assert!(matches!(err, BusError::Replay));
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
            .on_envelope(envelope(&alice, bob_fp, 5, &msg))
            .await
            .unwrap();
        let err = inbox
            .on_envelope(envelope(&alice, bob_fp, 4, &msg))
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
            .on_envelope(env)
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
            .on_envelope(envelope(&alice, bob_fp, 1, &req))
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
            .on_envelope(envelope(&alice, bob_fp, 1, &req))
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
        let rx = inbox.register_reply(cid);
        assert_eq!(inbox.pending_replies(), 1);

        let rep = BusMessage::Reply {
            correlation: cid.0,
            body: b"ok".to_vec(),
        };
        let out = inbox
            .on_envelope(envelope(&alice, bob_fp, 1, &rep))
            .await
            .unwrap();
        assert!(out.is_none());
        assert_eq!(rx.await.unwrap(), b"ok");
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
            .on_envelope(envelope(&alice, bob_fp, 1, &rep))
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
            .on_envelope(envelope(&alice, bob_fp, 1, &pub_msg))
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
            .on_envelope(envelope(&alice, bob_fp, 1, &pub_msg))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancel_reply_drops_waiter() {
        let inbox = Inbox::new();
        let cid = CorrelationId([0xaa; 16]);
        let _rx = inbox.register_reply(cid);
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
