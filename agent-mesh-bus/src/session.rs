//! Session streams — long-lived, full-duplex conversations between two agents
//! (`docs/decisions/session_streams.md`, agent-mesh#84).
//!
//! A session is one bidi stream carrying signed envelopes both ways. Each
//! envelope's payload is a [`Frame`]; its `sequence` is the frame's position
//! in its own direction, counted from the opening frame at `0`, and must
//! arrive exactly next — a duplicate, a regression or a gap ends the session.
//! Every frame passes the same immutable admission as any other envelope
//! ([`crate::inbox::admit`]: verify, carrier is signer, same user, addressed
//! here) against the peer the stream authenticated at open. Frames skip the
//! bus-wide nonce cache and sequence tracker: that stream binding, the session
//! id and the exact-next sequence are the replay defense, and a session never
//! consumes its sender's one-shot sequence space.
//!
//! Nothing is buffered past the frame being read, so a consumer that stops
//! calling [`SessionReceiver::recv`] stalls its peer's
//! [`SessionSender::send`] through the stream's own flow control.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use agent_mesh_protocol::{AgentKey, CertChain, Fingerprint, Recipient, SignedEnvelope};
use agent_mesh_transport::{send_envelope, EnvelopeReader, TransportError};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::task::AbortHandle;

use crate::inbox::admit;
use crate::transport::{AuthenticatedPeer, DeliveryProvenance, SessionStream};
use crate::{BusError, Result, Topic};

/// Wire form of one session frame, carried as the payload of a
/// [`SignedEnvelope`]. Its `kind` values never collide with a
/// [`crate::BusMessage`], and it requires a `session` id, so neither parses
/// as the other.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Frame {
    /// Random per-session id, fixed by the opener.
    session: [u8; 16],
    #[serde(flatten)]
    body: Body,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Body {
    /// First frame of the opener: which topic's handler to reach.
    Open { topic: String },
    /// First frame of the responder when its handler accepts.
    Accept,
    /// First frame of the responder when the open is refused.
    Refuse { reason: String },
    /// One application message.
    Data {
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    /// Liveness only; never surfaced.
    Keepalive,
    /// Clean goodbye: the sender has nothing more to say.
    Close,
}

/// How long a session waits for any frame, and how often it proves its own
/// liveness. Conservative, because the founding peer is a phone that roams
/// and sleeps.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timing {
    idle: Duration,
    keepalive: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(60),
            keepalive: Duration::from_secs(15),
        }
    }
}

/// The verified identity at the other end of a session, from the certificate
/// that signed its first frame. A responder authorizes an open against this,
/// e.g. by checking `cert_chain.metadata.caveats` for the topic's capability.
#[derive(Debug, Clone)]
pub struct SessionPeer {
    /// The peer's user root.
    pub user_fp: Fingerprint,
    /// The peer's agent identity.
    pub agent_fp: Fingerprint,
    /// The verified certificate chain the peer signed with.
    pub cert_chain: CertChain,
}

impl SessionPeer {
    fn of(env: &SignedEnvelope) -> Self {
        Self {
            user_fp: env.sender_user_fp(),
            agent_fp: env.sender_agent_fp(),
            cert_chain: env.cert_chain.clone(),
        }
    }
}

/// Who a session's frames are between; shared by both halves.
struct Link {
    id: [u8; 16],
    agent: Arc<AgentKey>,
    peer: AuthenticatedPeer,
}

struct Writer {
    io: Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    link: Arc<Link>,
    next_seq: u64,
    /// False once the session is closed, or while (and after) a frame write
    /// was abandoned partway: a torn frame can never be followed by another.
    intact: bool,
}

impl Writer {
    async fn write(&mut self, body: Body) -> Result<()> {
        if !self.intact {
            return Err(BusError::SessionProtocol(
                "the session is closed, or a send was cancelled mid-frame".into(),
            ));
        }
        let frame = Frame {
            session: self.link.id,
            body,
        };
        let env = SignedEnvelope::new(
            &self.link.agent,
            Recipient::Direct {
                agent_fp: self.link.peer.agent_fp,
            },
            self.next_seq,
            serde_json::to_vec(&frame)?,
        );
        self.intact = false;
        send_envelope(&mut self.io, &env).await?;
        self.io.flush().await.map_err(TransportError::from)?;
        self.intact = true;
        self.next_seq += 1;
        Ok(())
    }
}

/// Aborts the keepalive task when the last half of its session is dropped.
struct Keepalive(AbortHandle);

impl Drop for Keepalive {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The sending half of a [`Session`].
pub struct SessionSender {
    writer: Arc<AsyncMutex<Writer>>,
    shutdown: watch::Receiver<()>,
    _keepalive: Arc<Keepalive>,
}

impl SessionSender {
    /// Send one message. Waits while the peer is not reading (flow control).
    ///
    /// Cancelling this mid-frame ends the session for sending: every later
    /// send fails rather than follow a torn frame.
    ///
    /// # Errors
    /// [`BusError::NotRunning`] once the bus is gone, a transport error, or
    /// [`BusError::SessionProtocol`] after a close or a cancelled send.
    pub async fn send(&self, body: Vec<u8>) -> Result<()> {
        self.write(Body::Data { body }).await
    }

    /// Say goodbye: the peer's `recv` returns `Ok(None)`.
    ///
    /// # Errors
    /// As [`Self::send`].
    pub async fn close(self) -> Result<()> {
        self.write(Body::Close).await?;
        self.close_stream().await
    }

    /// Finish the stream; nothing may be written after.
    async fn close_stream(self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.intact = false;
        writer.io.shutdown().await.map_err(TransportError::from)?;
        Ok(())
    }

    async fn write(&self, body: Body) -> Result<()> {
        let mut shutdown = self.shutdown.clone();
        tokio::select! {
            biased;
            _ = shutdown.changed() => Err(BusError::NotRunning),
            written = async { self.writer.lock().await.write(body).await } => written,
        }
    }
}

/// The receiving half of a [`Session`].
pub struct SessionReceiver {
    reader: EnvelopeReader<Box<dyn AsyncRead + Send + Sync + Unpin>>,
    link: Arc<Link>,
    next_seq: u64,
    idle: Duration,
    shutdown: watch::Receiver<()>,
    closed: bool,
    failed: bool,
    _keepalive: Arc<Keepalive>,
}

impl SessionReceiver {
    /// The next message, or `None` once the peer closed cleanly.
    ///
    /// Cancel-safe: it may sit in a `select!` beside other work.
    ///
    /// # Errors
    /// Any failure ends the session, and every later call fails too:
    /// [`BusError::PeerDisconnected`] when the peer went away without closing,
    /// [`BusError::Timeout`] when no frame arrived within the idle window,
    /// [`BusError::NotRunning`] once the bus is gone, [`BusError::BadSequence`]
    /// for a duplicate, regressed or skipped frame, an admission error for one
    /// that does not verify or is not the authenticated peer's, and
    /// [`BusError::SessionProtocol`] for a malformed or out-of-place frame.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        if self.closed {
            return Ok(None);
        }
        loop {
            match self.next_frame().await?.1 {
                Body::Data { body } => return Ok(Some(body)),
                Body::Keepalive => {}
                Body::Close => {
                    self.closed = true;
                    return Ok(None);
                }
                other => return Err(self.fail(unexpected(&other))),
            }
        }
    }

    fn fail(&mut self, e: BusError) -> BusError {
        self.failed = true;
        e
    }

    async fn next_frame(&mut self) -> Result<(SignedEnvelope, Body)> {
        if self.failed {
            return Err(BusError::SessionProtocol(
                "the session already failed".into(),
            ));
        }
        let frame = self.read_frame().await;
        self.failed = frame.is_err();
        frame
    }

    async fn read_frame(&mut self) -> Result<(SignedEnvelope, Body)> {
        let mut shutdown = self.shutdown.clone();
        let env = tokio::select! {
            biased;
            _ = shutdown.changed() => return Err(BusError::NotRunning),
            read = tokio::time::timeout(self.idle, self.reader.next()) => match read {
                Err(_) => return Err(BusError::Timeout(self.idle)),
                Ok(env) => env?.ok_or(BusError::PeerDisconnected)?,
            },
        };
        let link = &self.link;
        let carrier = DeliveryProvenance::Direct { carrier: link.peer };
        let local_user = link.agent.cert().user_fingerprint();
        admit(&env, carrier, local_user, link.agent.fingerprint())?;
        if env.sequence != self.next_seq {
            return Err(BusError::BadSequence {
                peer_fp: link.peer.agent_fp.hex(),
                expected: self.next_seq,
                actual: env.sequence,
            });
        }
        self.next_seq += 1;
        let frame: Frame = serde_json::from_slice(env.payload.as_ref())?;
        if frame.session != link.id {
            return Err(BusError::SessionProtocol(
                "a frame of another session".into(),
            ));
        }
        Ok((env, frame.body))
    }
}

fn unexpected(body: &Body) -> BusError {
    let kind = match body {
        Body::Open { .. } => "open",
        Body::Accept => "accept",
        Body::Refuse { .. } => "refuse",
        Body::Data { .. } => "data",
        Body::Keepalive => "keepalive",
        Body::Close => "close",
    };
    BusError::SessionProtocol(format!("unexpected {kind} frame"))
}

/// Both halves of a session, opened by [`crate::Bus::open_session`] or
/// accepted from an [`IncomingSession`]. [`Self::split`] it to send and
/// receive from different tasks.
pub struct Session {
    tx: SessionSender,
    rx: SessionReceiver,
    peer: SessionPeer,
}

impl Session {
    /// The verified peer at the other end.
    #[must_use]
    pub fn peer(&self) -> &SessionPeer {
        &self.peer
    }

    /// See [`SessionSender::send`].
    ///
    /// # Errors
    /// As [`SessionSender::send`].
    pub async fn send(&self, body: Vec<u8>) -> Result<()> {
        self.tx.send(body).await
    }

    /// See [`SessionReceiver::recv`].
    ///
    /// # Errors
    /// As [`SessionReceiver::recv`].
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        self.rx.recv().await
    }

    /// See [`SessionSender::close`].
    ///
    /// # Errors
    /// As [`SessionSender::send`].
    pub async fn close(self) -> Result<()> {
        self.tx.close().await
    }

    /// Separate the halves, e.g. to push events from one task while another
    /// reads. The session's keepalive runs until both are dropped.
    #[must_use]
    pub fn split(self) -> (SessionSender, SessionReceiver) {
        (self.tx, self.rx)
    }

    /// Open a session on an authenticated `stream` to `peer`: send the open
    /// frame, then wait for the responder's verdict.
    pub(crate) async fn initiate(
        agent: Arc<AgentKey>,
        peer: AuthenticatedPeer,
        stream: SessionStream,
        topic: &Topic,
        timing: Timing,
        shutdown: watch::Receiver<()>,
    ) -> Result<Self> {
        let link = Link {
            id: rand::random(),
            agent,
            peer,
        };
        let (tx, mut rx) = halves(link, stream, 0, timing, shutdown);
        tx.write(Body::Open {
            topic: topic.wire(),
        })
        .await?;
        let (env, body) = rx.next_frame().await?;
        match body {
            Body::Accept => Ok(Self {
                tx,
                rx,
                peer: SessionPeer::of(&env),
            }),
            Body::Refuse { reason } => Err(BusError::SessionRefused(reason)),
            other => Err(unexpected(&other)),
        }
    }
}

fn halves(
    link: Link,
    stream: SessionStream,
    rx_seq: u64,
    timing: Timing,
    shutdown: watch::Receiver<()>,
) -> (SessionSender, SessionReceiver) {
    let link = Arc::new(link);
    let writer = Arc::new(AsyncMutex::new(Writer {
        io: stream.send,
        link: link.clone(),
        next_seq: 0,
        intact: true,
    }));
    let keepalive = Arc::new(Keepalive(spawn_keepalive(writer.clone(), timing.keepalive)));
    let tx = SessionSender {
        writer,
        shutdown: shutdown.clone(),
        _keepalive: keepalive.clone(),
    };
    let rx = SessionReceiver {
        reader: EnvelopeReader::new(stream.recv),
        link,
        next_seq: rx_seq,
        idle: timing.idle,
        shutdown,
        closed: false,
        failed: false,
        _keepalive: keepalive,
    };
    (tx, rx)
}

/// Prove liveness every `every` while the session is otherwise quiet. A send
/// already holding the writer proves it too, so a busy writer is skipped
/// rather than waited on. Ends on the first failed write; aborted when the
/// session's last half is dropped.
fn spawn_keepalive(writer: Arc<AsyncMutex<Writer>>, every: Duration) -> AbortHandle {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let Ok(mut writer) = writer.try_lock() else {
                continue;
            };
            if writer.write(Body::Keepalive).await.is_err() {
                return;
            }
        }
    })
    .abort_handle()
}

/// A session a peer asked to open, handed to the topic's
/// [`crate::Bus::handle_sessions`] handler before any data flows. The handler
/// decides with [`Self::accept`] or [`Self::refuse`]; dropping it undecided
/// drops the stream, which the opener sees as a failed open.
pub struct IncomingSession {
    tx: SessionSender,
    rx: SessionReceiver,
    peer: SessionPeer,
    topic: String,
}

impl IncomingSession {
    /// Admit the open frame `env` that arrived first on `stream`, carried by
    /// `provenance`. It must pass admission and be its sender's frame `0`.
    pub(crate) fn admit(
        agent: Arc<AgentKey>,
        env: &SignedEnvelope,
        provenance: DeliveryProvenance,
        stream: SessionStream,
        timing: Timing,
        shutdown: watch::Receiver<()>,
    ) -> Result<Self> {
        let (id, topic) = open_request(env)
            .ok_or_else(|| BusError::SessionProtocol("not a session open frame".into()))?;
        let caller = admit(
            env,
            provenance,
            agent.cert().user_fingerprint(),
            agent.fingerprint(),
        )?;
        if env.sequence != 0 {
            return Err(BusError::BadSequence {
                peer_fp: caller.caller_agent_fp.hex(),
                expected: 0,
                actual: env.sequence,
            });
        }
        let peer = AuthenticatedPeer::new(caller.caller_user_fp, caller.caller_agent_fp);
        let link = Link { id, agent, peer };
        let (tx, rx) = halves(link, stream, 1, timing, shutdown);
        Ok(Self {
            tx,
            rx,
            peer: SessionPeer::of(env),
            topic,
        })
    }

    /// The verified peer asking to open this session.
    #[must_use]
    pub fn peer(&self) -> &SessionPeer {
        &self.peer
    }

    /// The wire-form topic the peer asked for (see [`Topic::wire`]).
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Accept: the opener's `open_session` returns, and data may flow.
    ///
    /// # Errors
    /// As [`SessionSender::send`].
    pub async fn accept(self) -> Result<Session> {
        self.tx.write(Body::Accept).await?;
        Ok(Session {
            tx: self.tx,
            rx: self.rx,
            peer: self.peer,
        })
    }

    /// Refuse: the opener's `open_session` fails with
    /// [`BusError::SessionRefused`] carrying `reason`.
    ///
    /// # Errors
    /// As [`SessionSender::send`].
    pub async fn refuse(self, reason: &str) -> Result<()> {
        let reason = reason.to_owned();
        self.tx.write(Body::Refuse { reason }).await?;
        self.tx.close_stream().await
    }
}

/// The session id and topic of `env` when it is a session open frame.
pub(crate) fn open_request(env: &SignedEnvelope) -> Option<([u8; 16], String)> {
    match serde_json::from_slice(env.payload.as_ref()) {
        Ok(Frame {
            session,
            body: Body::Open { topic },
        }) => Some((session, topic)),
        _ => None,
    }
}

type Handler = Arc<dyn Fn(IncomingSession) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Session handlers by wire-form topic.
#[derive(Default)]
pub(crate) struct SessionHandlers(RwLock<HashMap<String, Handler>>);

impl SessionHandlers {
    pub(crate) fn register<F, Fut>(&self, topic: &Topic, handler: F)
    where
        F: Fn(IncomingSession) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handler: Handler = Arc::new(move |incoming| Box::pin(handler(incoming)));
        self.0
            .write()
            .expect("session handlers lock poisoned")
            .insert(topic.wire(), handler);
    }

    /// Run the topic's handler on `incoming`, or refuse it when there is none.
    pub(crate) async fn dispatch(&self, incoming: IncomingSession) {
        let handler = self
            .0
            .read()
            .expect("session handlers lock poisoned")
            .get(incoming.topic())
            .cloned();
        let outcome = match handler {
            Some(handler) => handler(incoming).await,
            None => incoming.refuse("no session handler for this topic").await,
        };
        if let Err(e) = outcome {
            tracing::debug!(error = %e, "bus: session ended with an error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BusMessage;
    use agent_mesh_protocol::{AgentMetadata, Caveats, UserKey};
    use agent_mesh_transport::recv_envelope;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::DuplexStream;
    use tokio::task::JoinHandle;

    fn agent(user: &UserKey, role: &str) -> Arc<AgentKey> {
        Arc::new(AgentKey::issue(
            user,
            AgentMetadata {
                role: role.into(),
                host: "test".into(),
                capabilities: vec![format!("{role}-cap")],
                issued_at: "2026-09-29T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        ))
    }

    fn carrier(agent: &AgentKey) -> AuthenticatedPeer {
        AuthenticatedPeer::new(agent.cert().user_fingerprint(), agent.fingerprint())
    }

    fn stream(io: DuplexStream) -> SessionStream {
        let (recv, send) = tokio::io::split(io);
        SessionStream {
            send: Box::new(send),
            recv: Box::new(recv),
        }
    }

    fn pipe(capacity: usize) -> (SessionStream, SessionStream) {
        let (a, b) = tokio::io::duplex(capacity);
        (stream(a), stream(b))
    }

    /// A session frame `from` signs for `to`, at `seq`.
    fn frame(from: &AgentKey, to: &AgentKey, id: [u8; 16], seq: u64, body: Body) -> SignedEnvelope {
        let payload = serde_json::to_vec(&Frame { session: id, body }).unwrap();
        let recipient = Recipient::Direct {
            agent_fp: to.fingerprint(),
        };
        SignedEnvelope::new(from, recipient, seq, payload)
    }

    fn data(body: &[u8]) -> Body {
        Body::Data {
            body: body.to_vec(),
        }
    }

    /// Alice (opener) and Bob (responder) under one user, and the bus
    /// lifetime their sessions watch.
    struct Mesh {
        user: UserKey,
        alice: Arc<AgentKey>,
        bob: Arc<AgentKey>,
        bus: Option<watch::Sender<()>>,
    }

    impl Mesh {
        fn new() -> Self {
            let user = UserKey::generate();
            let (alice, bob) = (agent(&user, "alice"), agent(&user, "bob"));
            let (bus, _) = watch::channel(());
            Self {
                user,
                alice,
                bob,
                bus: Some(bus),
            }
        }

        fn shutdown(&self) -> watch::Receiver<()> {
            self.bus.as_ref().expect("bus still running").subscribe()
        }

        fn topic(&self) -> Topic {
            Topic::new(self.user.fingerprint(), "chat")
        }

        /// Alice opens toward Bob over a pipe: her pending open, and Bob's view
        /// of it once the open frame arrived.
        async fn open(
            &self,
            capacity: usize,
            timing: Timing,
        ) -> (JoinHandle<Result<Session>>, IncomingSession) {
            let (a, mut b) = pipe(capacity);
            let (alice, bob_peer, topic) = (self.alice.clone(), carrier(&self.bob), self.topic());
            let shutdown = self.shutdown();
            let opening = tokio::spawn(async move {
                Session::initiate(alice, bob_peer, a, &topic, timing, shutdown).await
            });
            let open = recv_envelope(&mut b.recv).await.unwrap();
            let provenance = DeliveryProvenance::Direct {
                carrier: carrier(&self.alice),
            };
            let incoming = IncomingSession::admit(
                self.bob.clone(),
                &open,
                provenance,
                b,
                timing,
                self.shutdown(),
            )
            .unwrap();
            (opening, incoming)
        }

        /// Bob's receiving half, fed raw bytes by the returned stream end.
        fn bob_receiving(&self, id: [u8; 16], timing: Timing) -> (SessionReceiver, SessionStream) {
            let (a, b) = pipe(1 << 16);
            let link = Link {
                id,
                agent: self.bob.clone(),
                peer: carrier(&self.alice),
            };
            (halves(link, b, 0, timing, self.shutdown()).1, a)
        }
    }

    const PATIENT: Timing = Timing {
        idle: Duration::from_secs(3600),
        keepalive: Duration::from_secs(3600),
    };

    #[tokio::test]
    async fn an_accepted_session_is_full_duplex_and_the_responder_may_speak_first() {
        let mesh = Mesh::new();
        let (opening, incoming) = mesh.open(1 << 16, Timing::default()).await;
        assert_eq!(incoming.topic(), mesh.topic().wire());
        assert_eq!(incoming.peer().agent_fp, mesh.alice.fingerprint());
        assert_eq!(incoming.peer().user_fp, mesh.user.fingerprint());
        assert_eq!(
            &incoming.peer().cert_chain,
            mesh.alice.cert(),
            "cert evidence"
        );

        let mut bob = incoming.accept().await.unwrap();
        bob.send(b"pushed before any request".to_vec())
            .await
            .unwrap();
        let mut alice = opening.await.unwrap().unwrap();
        assert_eq!(alice.peer().agent_fp, mesh.bob.fingerprint());
        assert_eq!(&alice.peer().cert_chain, mesh.bob.cert());
        assert_eq!(
            alice.recv().await.unwrap().unwrap(),
            b"pushed before any request"
        );

        for turn in 0u8..3 {
            alice.send(vec![turn]).await.unwrap();
            assert_eq!(bob.recv().await.unwrap(), Some(vec![turn]));
            bob.send(vec![turn, turn]).await.unwrap();
            bob.send(vec![turn, turn, turn]).await.unwrap();
            assert_eq!(alice.recv().await.unwrap(), Some(vec![turn, turn]));
            assert_eq!(alice.recv().await.unwrap(), Some(vec![turn, turn, turn]));
        }

        alice.close().await.unwrap();
        assert_eq!(bob.recv().await.unwrap(), None, "a clean close");
        assert_eq!(bob.recv().await.unwrap(), None, "and it stays closed");
    }

    #[tokio::test]
    async fn a_refused_open_fails_with_the_reason_and_carries_no_data() {
        let mesh = Mesh::new();
        let (opening, incoming) = mesh.open(1 << 16, Timing::default()).await;
        incoming.refuse("not caveated for chat").await.unwrap();
        match opening.await.unwrap() {
            Err(BusError::SessionRefused(reason)) => assert_eq!(reason, "not caveated for chat"),
            other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn an_open_dropped_undecided_fails_closed() {
        let mesh = Mesh::new();
        let (opening, incoming) = mesh.open(1 << 16, Timing::default()).await;
        drop(incoming);
        assert!(matches!(
            opening.await.unwrap(),
            Err(BusError::PeerDisconnected)
        ));
    }

    #[tokio::test]
    async fn an_open_reaches_its_topics_handler_and_an_unknown_topic_is_refused() {
        let mesh = Mesh::new();
        let handlers = SessionHandlers::default();
        let (opening, incoming) = mesh.open(1 << 16, Timing::default()).await;
        handlers.dispatch(incoming).await;
        match opening.await.unwrap() {
            Err(BusError::SessionRefused(reason)) => assert!(reason.contains("no session handler")),
            other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
        }

        handlers.register(&mesh.topic(), |incoming: IncomingSession| async move {
            let session = incoming.accept().await?;
            session.send(b"hello".to_vec()).await
        });
        let (opening, incoming) = mesh.open(1 << 16, Timing::default()).await;
        handlers.dispatch(incoming).await;
        let mut alice = opening.await.unwrap().unwrap();
        assert_eq!(alice.recv().await.unwrap().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn an_open_must_be_frame_zero_signed_by_its_carrier() {
        let mesh = Mesh::new();
        let carol = agent(&mesh.user, "carol");
        let open = Body::Open {
            topic: mesh.topic().wire(),
        };
        let by_alice = DeliveryProvenance::Direct {
            carrier: carrier(&mesh.alice),
        };
        let admit_open = |env: &SignedEnvelope| {
            IncomingSession::admit(
                mesh.bob.clone(),
                env,
                by_alice,
                pipe(64).0,
                PATIENT,
                mesh.shutdown(),
            )
            .map(|_| ())
        };
        let late = frame(&mesh.alice, &mesh.bob, [1; 16], 1, open);
        assert!(matches!(
            admit_open(&late),
            Err(BusError::BadSequence { .. })
        ));
        let open = Body::Open {
            topic: mesh.topic().wire(),
        };
        let relayed = frame(&carol, &mesh.bob, [1; 16], 0, open);
        assert!(matches!(
            admit_open(&relayed),
            Err(BusError::CarrierAgentMismatch { .. })
        ));
        let not_open = frame(&mesh.alice, &mesh.bob, [1; 16], 0, data(b"x"));
        assert!(matches!(
            admit_open(&not_open),
            Err(BusError::SessionProtocol(_))
        ));
    }

    /// Exact-next ordering per direction: a duplicate, a regression, or a gap
    /// each end the session, and it stays ended.
    #[tokio::test]
    async fn a_duplicate_regressed_or_skipped_frame_ends_the_session() {
        for (case, seqs) in [
            ("duplicate", vec![0, 1, 1]),
            ("regressed", vec![0, 1, 2, 1]),
            ("skipped", vec![0, 2]),
        ] {
            let mesh = Mesh::new();
            let (mut bob, mut raw) = mesh.bob_receiving([7; 16], PATIENT);
            let (last, good) = seqs.split_last().unwrap();
            for &seq in good {
                let env = frame(&mesh.alice, &mesh.bob, [7; 16], seq, data(b"ok"));
                send_envelope(&mut raw.send, &env).await.unwrap();
                assert_eq!(bob.recv().await.unwrap(), Some(b"ok".to_vec()), "{case}");
            }
            let env = frame(&mesh.alice, &mesh.bob, [7; 16], *last, data(b"bad"));
            send_envelope(&mut raw.send, &env).await.unwrap();
            match bob.recv().await {
                Err(BusError::BadSequence {
                    expected, actual, ..
                }) => {
                    assert_eq!((expected, actual), (good.len() as u64, *last), "{case}");
                }
                other => panic!("{case}: expected BadSequence, got {other:?}"),
            }
            let next = frame(
                &mesh.alice,
                &mesh.bob,
                [7; 16],
                good.len() as u64,
                data(b"x"),
            );
            send_envelope(&mut raw.send, &next).await.unwrap();
            assert!(
                matches!(bob.recv().await, Err(BusError::SessionProtocol(_))),
                "{case}: a failed session stays failed"
            );
        }
    }

    #[tokio::test]
    async fn a_frame_not_from_the_authenticated_peer_or_not_verifying_ends_the_session() {
        let mesh = Mesh::new();
        let carol = agent(&mesh.user, "carol");
        let (mut bob, mut raw) = mesh.bob_receiving([7; 16], PATIENT);
        let env = frame(&carol, &mesh.bob, [7; 16], 0, data(b"x"));
        send_envelope(&mut raw.send, &env).await.unwrap();
        assert!(matches!(
            bob.recv().await,
            Err(BusError::CarrierAgentMismatch { .. })
        ));

        let (mut bob, mut raw) = mesh.bob_receiving([7; 16], PATIENT);
        let mut env = frame(&mesh.alice, &mesh.bob, [7; 16], 0, data(b"x"));
        env.payload = serde_bytes::ByteBuf::from(
            serde_json::to_vec(&Frame {
                session: [7; 16],
                body: data(b"forged"),
            })
            .unwrap(),
        );
        send_envelope(&mut raw.send, &env).await.unwrap();
        assert!(matches!(bob.recv().await, Err(BusError::Transport(_))));
    }

    #[tokio::test]
    async fn a_frame_of_another_session_or_out_of_place_ends_the_session() {
        let mesh = Mesh::new();
        let (mut bob, mut raw) = mesh.bob_receiving([7; 16], PATIENT);
        let env = frame(&mesh.alice, &mesh.bob, [8; 16], 0, data(b"x"));
        send_envelope(&mut raw.send, &env).await.unwrap();
        assert!(matches!(
            bob.recv().await,
            Err(BusError::SessionProtocol(_))
        ));

        for body in [
            Body::Open { topic: "t".into() },
            Body::Accept,
            Body::Refuse { reason: "r".into() },
        ] {
            let (mut bob, mut raw) = mesh.bob_receiving([7; 16], PATIENT);
            let env = frame(&mesh.alice, &mesh.bob, [7; 16], 0, body);
            send_envelope(&mut raw.send, &env).await.unwrap();
            assert!(matches!(
                bob.recv().await,
                Err(BusError::SessionProtocol(_))
            ));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_times_out_but_keepalives_hold_a_quiet_session_open() {
        let mesh = Mesh::new();
        let deaf = Timing {
            idle: Duration::from_secs(5),
            keepalive: Duration::from_secs(3600),
        };
        let (opening, incoming) = mesh.open(1 << 16, deaf).await;
        let mut bob = incoming.accept().await.unwrap();
        let _alice = opening.await.unwrap().unwrap();
        assert!(matches!(bob.recv().await, Err(BusError::Timeout(_))));

        let chatty = Timing {
            idle: Duration::from_secs(5),
            keepalive: Duration::from_secs(1),
        };
        let (opening, incoming) = mesh.open(1 << 16, chatty).await;
        let mut bob = incoming.accept().await.unwrap();
        let _alice = opening.await.unwrap().unwrap();
        let quiet = tokio::time::timeout(Duration::from_secs(60), bob.recv()).await;
        assert!(
            quiet.is_err(),
            "keepalives are not data and do not time out"
        );
    }

    /// Dropping a session releases its stream at once — its keepalive task
    /// holds no reference past the drop — so the peer sees a disconnect, not
    /// an idle timeout.
    #[tokio::test(start_paused = true)]
    async fn a_dropped_session_disconnects_its_peer_without_lingering() {
        let mesh = Mesh::new();
        let timing = Timing {
            idle: Duration::from_secs(5),
            keepalive: Duration::from_secs(1),
        };
        let (opening, incoming) = mesh.open(1 << 16, timing).await;
        let mut bob = incoming.accept().await.unwrap();
        let (tx, rx) = opening.await.unwrap().unwrap().split();
        drop(tx);
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(rx);
        let seen = tokio::time::timeout(Duration::from_secs(60), bob.recv()).await;
        assert!(matches!(seen, Ok(Err(BusError::PeerDisconnected))));
    }

    #[tokio::test]
    async fn a_shut_down_bus_ends_its_sessions() {
        let mut mesh = Mesh::new();
        let (opening, incoming) = mesh.open(1 << 16, PATIENT).await;
        let mut bob = incoming.accept().await.unwrap();
        let alice = opening.await.unwrap().unwrap();
        mesh.bus = None;
        let seen = tokio::time::timeout(Duration::from_secs(5), bob.recv()).await;
        assert!(matches!(seen, Ok(Err(BusError::NotRunning))));
        assert!(matches!(
            alice.send(b"x".to_vec()).await,
            Err(BusError::NotRunning)
        ));
    }

    #[tokio::test]
    async fn a_send_cancelled_mid_frame_ends_sending() {
        let mesh = Mesh::new();
        let (opening, incoming) = mesh.open(4096, PATIENT).await;
        let _bob = incoming.accept().await.unwrap();
        let alice = opening.await.unwrap().unwrap();
        let stuck = tokio::time::timeout(Duration::from_millis(50), alice.send(vec![0; 1 << 16]));
        assert!(stuck.await.is_err(), "the unread pipe holds the send");
        let after = tokio::time::timeout(Duration::from_secs(1), alice.send(b"x".to_vec()));
        assert!(
            matches!(after.await, Ok(Err(BusError::SessionProtocol(_)))),
            "a send after a torn frame fails at once instead of writing"
        );
    }

    /// A consumer that stops reading stalls its sender: nothing buffers the
    /// frames it has not asked for.
    #[tokio::test]
    async fn a_stalled_consumer_holds_its_sender_back() {
        let mesh = Mesh::new();
        let (opening, incoming) = mesh.open(4096, PATIENT).await;
        let mut bob = incoming.accept().await.unwrap();
        let alice = opening.await.unwrap().unwrap();
        let sent = Arc::new(AtomicUsize::new(0));
        let counter = sent.clone();
        let sender = tokio::spawn(async move {
            for _ in 0..50 {
                alice.send(vec![1; 1024]).await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = sent.load(Ordering::SeqCst);
        assert!(before < 5, "only what fits the pipe went out, not {before}");
        for _ in 0..50 {
            assert_eq!(bob.recv().await.unwrap().unwrap().len(), 1024);
        }
        sender.await.unwrap();
    }

    #[test]
    fn session_frames_and_bus_messages_never_parse_as_each_other() {
        let publish = serde_json::to_vec(&BusMessage::Publish {
            topic: "t".into(),
            body: vec![1],
        })
        .unwrap();
        assert!(serde_json::from_slice::<Frame>(&publish).is_err());
        let open = serde_json::to_vec(&Frame {
            session: [3; 16],
            body: Body::Open { topic: "t".into() },
        })
        .unwrap();
        assert!(serde_json::from_slice::<BusMessage>(&open).is_err());
        let user = UserKey::generate();
        let (a, b) = (agent(&user, "a"), agent(&user, "b"));
        let env = |body| frame(&a, &b, [3; 16], 0, body);
        let topic = "t".to_string();
        assert_eq!(
            open_request(&env(Body::Open {
                topic: topic.clone()
            })),
            Some(([3; 16], topic))
        );
        assert_eq!(open_request(&env(Body::Accept)), None);
    }
}
