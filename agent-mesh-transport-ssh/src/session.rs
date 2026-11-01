//! Mutually authenticated AgentKey sessions over an arbitrary byte stream.
//!
//! The SSH subprocess authenticates an SSH account, but that identity is not
//! the AgentKey which signs mesh envelopes.  This module supplies the missing
//! end-to-end binding.  A raw stream starts as [`UnauthenticatedMeshSession`]
//! and can carry envelopes only after both sides prove possession of the leaf
//! key in their verified [`CertChain`].  The resulting
//! [`AuthenticatedMeshSession`] wraps every envelope in a fresh-session,
//! direction, and counter-bound carrier signature before exposing it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_mesh_bus::AuthenticatedPeer;
use agent_mesh_protocol::{
    AgentKey, CertChain, Fingerprint, MeshError, RevocationState, SerdeSig, SignedEnvelope,
};
use agent_mesh_transport::{LiveCheck, RevocationGuard, TransportError};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum encoded Hello or Proof payload, before its four-byte prefix.
pub const MAX_HANDSHAKE_FRAME_BYTES: u32 = 16 * 1024;

/// Back-compatible concise name for [`MAX_HANDSHAKE_FRAME_BYTES`].
pub const MAX_HANDSHAKE_BYTES: u32 = MAX_HANDSHAKE_FRAME_BYTES;

/// Maximum raw JSON encoding of one [`SignedEnvelope`] in a session record.
pub const MAX_SESSION_ENVELOPE_BYTES: u32 = 16 * 1024 * 1024;

/// Back-compatible concise name for [`MAX_SESSION_ENVELOPE_BYTES`].
pub const MAX_ENVELOPE_BYTES: u32 = MAX_SESSION_ENVELOPE_BYTES;

const PROTOCOL_LABEL: &str = "agent-mesh-session";
const TRANSPORT_LABEL: &str = "ssh";
const PROTOCOL_VERSION: u16 = 1;
const RECORD_VERSION: u16 = 1;

const TRANSCRIPT_DOMAIN: &[u8] = b"agent-mesh/ssh-session/v1/transcript\0";
const PROOF_DOMAIN: &[u8] = b"agent-mesh/ssh-session/v1/proof\0";
const RECORD_DOMAIN: &[u8] = b"agent-mesh/ssh-session/v1/record\0";

const RECORD_HEADER_BYTES: usize = 32 + 1 + 8 + 4;
const RECORD_SIGNATURE_BYTES: usize = 64;

/// Which endpoint role this side has in the SSH-carried mesh session.
///
/// Roles order the transcript and domain-separate proofs and records.  They
/// are independent of which task happens to be polled first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    /// The spoke which opened the SSH channel.
    Initiator,
    /// The hub-side loopback listener which accepted it.
    Responder,
}

/// What the initiator wants the authenticated connection for.
///
/// Carried in the initiator's signed Hello, so it is bound into the transcript
/// both peers prove. The responder learns it only after authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPurpose {
    /// Independent envelopes, delivered to the bus one by one.
    #[default]
    Messages,
    /// One long-lived byte stream for a bus session, bridged over records.
    Stream,
}

impl SessionPurpose {
    fn is_messages(&self) -> bool {
        *self == Self::Messages
    }
}

impl SessionRole {
    fn opposite(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }

    fn as_byte(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }

    fn outbound_direction(self) -> RecordDirection {
        match self {
            Self::Initiator => RecordDirection::InitiatorToResponder,
            Self::Responder => RecordDirection::ResponderToInitiator,
        }
    }

    fn inbound_direction(self) -> RecordDirection {
        self.opposite().outbound_direction()
    }
}

/// Transcript-bound protocol parameters.
///
/// Wire-format and allocation limits are deliberately fixed.  The only
/// contextual input is the causal generation used to validate both certs; a
/// mismatch therefore fails the handshake instead of letting peers silently
/// apply different revocation views.  A session always runs against the
/// local [`RevocationGuard`]'s log, and that log's generation replaces
/// whatever generation was set here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionParameters {
    record_version: u16,
    max_envelope_bytes: u32,
    current_generation: Option<u64>,
}

impl SessionParameters {
    /// Parameters for protocol v1, optionally validating certs at a causal
    /// generation.  `None` uses context-free [`CertChain::verify`], which
    /// already refuses generation-bounded certs fail-closed.
    #[must_use]
    pub fn new(current_generation: Option<u64>) -> Self {
        Self {
            record_version: RECORD_VERSION,
            max_envelope_bytes: MAX_SESSION_ENVELOPE_BYTES,
            current_generation,
        }
    }

    /// Causal generation used for certificate validation.
    #[must_use]
    pub fn current_generation(&self) -> Option<u64> {
        self.current_generation
    }

    fn validate(&self) -> Result<(), SessionError> {
        if self.record_version != RECORD_VERSION
            || self.max_envelope_bytes != MAX_SESSION_ENVELOPE_BYTES
        {
            return Err(SessionError::ParameterMismatch);
        }
        Ok(())
    }
}

impl Default for SessionParameters {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Deadlines applied to authentication and each post-authentication record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTimeouts {
    /// One deadline for both handshake flights, including reads and writes.
    pub authentication: Duration,
    /// One deadline for a complete record read or write.
    pub record: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            authentication: Duration::from_secs(5),
            record: Duration::from_secs(30),
        }
    }
}

/// Errors produced by the authenticated session layer.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Authentication or a record operation exceeded its whole-operation
    /// deadline.  A timed-out session must be discarded.
    #[error("{phase} timed out after {duration:?}")]
    Timeout {
        /// Operation which timed out.
        phase: &'static str,
        /// Configured deadline.
        duration: Duration,
    },

    /// The underlying byte stream failed or closed early.
    #[error("session I/O: {0}")]
    Io(#[from] std::io::Error),

    /// A handshake frame could not be encoded or decoded.
    #[error("invalid handshake frame: {0}")]
    BadHandshakeFrame(String),

    /// A length prefix exceeded the cap for its frame class.
    #[error("{kind} frame length {actual} exceeds maximum {maximum}")]
    FrameTooLarge {
        /// Frame class.
        kind: &'static str,
        /// Claimed or encoded length.
        actual: u32,
        /// Maximum accepted length.
        maximum: u32,
    },

    /// A peer sent a frame kind which is invalid in the current flight.
    #[error("unexpected handshake frame: expected {expected}, got {actual}")]
    UnexpectedFrame {
        /// Required frame kind.
        expected: &'static str,
        /// Received frame kind.
        actual: &'static str,
    },

    /// A protocol label, transport label, or protocol version differed.
    #[error("peer uses an unsupported session protocol")]
    ProtocolMismatch,

    /// Fixed record parameters or causal generation differed.
    #[error("peer session parameters do not match")]
    ParameterMismatch,

    /// Both endpoints claimed the same role or the wrong opposite role.
    #[error("peer session role is not the required opposite role")]
    RoleMismatch,

    /// The initiator did not name this responder, or the responder did not
    /// match the exact identity the initiator named.
    #[error("session responder identity does not match the initiator's expectation")]
    UnexpectedResponder,

    /// The local AgentKey does not match or validate against its certificate.
    #[error("invalid local AgentKey identity: {0}")]
    InvalidLocalIdentity(String),

    /// The peer certificate failed signature, attenuation, or generation
    /// validation.
    #[error("peer certificate rejected: {0}")]
    BadPeerCertificate(String),

    /// The peer, or a link of its chain, is revoked by the local user's
    /// revocation log (at the handshake, or learned while the session ran).
    #[error("peer revoked: agent {0}")]
    PeerRevoked(String),

    /// No usable revocation log: missing, unreadable, invalid, another user's,
    /// or not extending what was last seen.  Fail closed.
    #[error("revocation log unavailable: {0}")]
    RevocationUnavailable(String),

    /// The peer roots at a different user.
    #[error("peer user {peer} does not match local user {local}")]
    DifferentUser {
        /// Peer root fingerprint.
        peer: String,
        /// Local root fingerprint.
        local: String,
    },

    /// Transcript identifier in a proof did not name this connection.
    #[error("peer proof names a different handshake transcript")]
    TranscriptMismatch,

    /// The peer did not prove possession of its certified AgentKey.
    #[error("peer AgentKey proof is invalid")]
    BadPeerProof,

    /// A post-authentication record named another session.
    #[error("record belongs to a different authenticated session")]
    RecordSessionMismatch,

    /// A post-authentication record traveled in the wrong direction.
    #[error("record direction is invalid for this session endpoint")]
    RecordDirectionMismatch,

    /// A record counter was replayed, skipped, or reordered.
    #[error("record counter mismatch: expected {expected}, got {actual}")]
    RecordCounterMismatch {
        /// Strict next counter.
        expected: u64,
        /// Counter on the wire.
        actual: u64,
    },

    /// A record's carrier signature did not verify under the authenticated
    /// peer's AgentKey.
    #[error("record carrier signature is invalid")]
    BadRecordSignature,

    /// A record's embedded envelope could not be encoded or decoded.
    #[error("record envelope rejected: {0}")]
    BadEnvelope(String),

    /// The per-direction record counter cannot advance further.
    #[error("session record counter exhausted")]
    CounterExhausted,

    /// A previous record error makes framing recovery unsafe.
    #[error("session half is poisoned after a previous record failure")]
    Poisoned,
}

/// A byte stream which has not yet authenticated its mesh peer.
///
/// The reader and writer are private and there is no raw-envelope method.  The
/// only state transition consumes this value and returns an authenticated
/// session after the peer proof verifies.
pub struct UnauthenticatedMeshSession<R, W> {
    reader: R,
    writer: W,
    local_agent: Arc<AgentKey>,
    role: SessionRole,
    expected_responder: Option<Fingerprint>,
    parameters: SessionParameters,
    timeouts: SessionTimeouts,
    purpose: SessionPurpose,
    revocation: RevocationGuard,
}

impl<R, W> UnauthenticatedMeshSession<R, W> {
    /// Declare what this (initiator) connection is for; default `Messages`.
    #[must_use]
    pub fn with_purpose(mut self, purpose: SessionPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    /// Create the spoke/initiator side.  The responder AgentKey fingerprint is
    /// mandatory and is carried inside the signed transcript.  Both certs are
    /// checked against `revocation`, and the session ends if it later revokes
    /// the peer.
    #[must_use]
    pub fn initiator(
        reader: R,
        writer: W,
        local_agent: Arc<AgentKey>,
        expected_responder: Fingerprint,
        parameters: SessionParameters,
        timeouts: SessionTimeouts,
        revocation: RevocationGuard,
    ) -> Self {
        Self {
            reader,
            writer,
            local_agent,
            role: SessionRole::Initiator,
            expected_responder: Some(expected_responder),
            parameters,
            timeouts,
            purpose: SessionPurpose::Messages,
            revocation,
        }
    }

    /// Create the hub/responder side.  The peer's Hello must name this exact
    /// responder before authentication succeeds.  Both certs are checked
    /// against `revocation`, and the session ends if it later revokes the peer.
    #[must_use]
    pub fn responder(
        reader: R,
        writer: W,
        local_agent: Arc<AgentKey>,
        parameters: SessionParameters,
        timeouts: SessionTimeouts,
        revocation: RevocationGuard,
    ) -> Self {
        Self {
            reader,
            writer,
            local_agent,
            role: SessionRole::Responder,
            expected_responder: None,
            parameters,
            timeouts,
            purpose: SessionPurpose::Messages,
            revocation,
        }
    }
}

impl<R, W> UnauthenticatedMeshSession<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Run both authentication flights and consume the unauthenticated state.
    ///
    /// Any error drops the only owners of the raw halves.  Callers cannot
    /// retry on a partially consumed stream.
    pub async fn authenticate(mut self) -> Result<AuthenticatedMeshSession<R, W>, SessionError> {
        let timeout = self.timeouts.authentication;
        let outcome = tokio::time::timeout(timeout, self.authenticate_inner())
            .await
            .map_err(|_| SessionError::Timeout {
                phase: "mesh session authentication",
                duration: timeout,
            })??;

        let live =
            LiveCheck::new(self.revocation, outcome.peer_cert.clone()).map_err(revocation_error)?;
        Ok(AuthenticatedMeshSession {
            reader: self.reader,
            writer: self.writer,
            local_agent: self.local_agent,
            role: self.role,
            live: Arc::new(Mutex::new(live)),
            peer: outcome.peer,
            peer_cert: outcome.peer_cert,
            peer_verifying_key: outcome.peer_verifying_key,
            transcript_id: outcome.transcript_id,
            peer_purpose: outcome.peer_purpose,
            send_counter: 0,
            receive_counter: 0,
            record_timeout: self.timeouts.record,
            send_poisoned: false,
            receive_poisoned: false,
        })
    }

    async fn authenticate_inner(&mut self) -> Result<HandshakeOutcome, SessionError> {
        // The local log decides the generation; peers on different ones
        // fail the parameter comparison instead of applying different views.
        let state = self.revocation.state().map_err(revocation_error)?;
        self.parameters.current_generation = Some(state.generation);
        self.parameters.validate()?;
        validate_local_identity(&self.local_agent, &state)?;

        let local_hello = HelloFrame::new(
            self.role,
            random_nonce(),
            self.local_agent.cert().clone(),
            self.parameters.clone(),
            self.expected_responder,
        )
        .with_purpose(self.purpose);
        let local_hello_raw = encode_auth_frame(&AuthFrame::Hello(Box::new(local_hello.clone())))?;

        // Both endpoints write and read each flight concurrently.  Sequential
        // write-then-read deadlocks on legal streams with buffers smaller than
        // a certificate-bearing Hello frame.
        let peer_hello_raw =
            exchange_auth_frame(&mut self.reader, &mut self.writer, &local_hello_raw).await?;
        let peer_hello = expect_hello(&peer_hello_raw)?;
        let peer_verifying_key = validate_peer_hello(
            &local_hello,
            &peer_hello,
            self.local_agent.cert(),
            &self.parameters,
            &state,
        )?;

        let transcript_id = match self.role {
            SessionRole::Initiator => make_transcript_id(&local_hello_raw, &peer_hello_raw),
            SessionRole::Responder => make_transcript_id(&peer_hello_raw, &local_hello_raw),
        };
        let proof_message = make_proof_message(self.role, &transcript_id);
        let local_proof = ProofFrame {
            role: self.role,
            transcript_id,
            signature: SerdeSig(self.local_agent.sign(&proof_message)),
        };
        let local_proof_raw = encode_auth_frame(&AuthFrame::Proof(local_proof))?;
        let peer_proof_raw =
            exchange_auth_frame(&mut self.reader, &mut self.writer, &local_proof_raw).await?;
        let peer_proof = expect_proof(&peer_proof_raw)?;
        verify_peer_proof(
            &peer_proof,
            self.role.opposite(),
            &transcript_id,
            &peer_verifying_key,
        )?;

        // This is the sole minting point.  Neither the Hello's claims nor its
        // valid cert alone is sufficient: proof of possession has passed.
        let peer = AuthenticatedPeer::new(
            peer_hello.cert.user_fingerprint(),
            peer_hello.cert.agent_fingerprint(),
        );

        Ok(HandshakeOutcome {
            peer,
            peer_cert: peer_hello.cert,
            peer_verifying_key,
            transcript_id,
            peer_purpose: peer_hello.purpose,
        })
    }
}

struct HandshakeOutcome {
    peer_purpose: SessionPurpose,
    peer: AuthenticatedPeer,
    peer_cert: CertChain,
    peer_verifying_key: VerifyingKey,
    transcript_id: [u8; 32],
}

/// A mutually authenticated mesh session.  Raw I/O remains private; callers
/// can exchange only carrier-signed records.
pub struct AuthenticatedMeshSession<R, W> {
    reader: R,
    writer: W,
    local_agent: Arc<AgentKey>,
    role: SessionRole,
    /// Re-checks the peer against the revocation log on every record.
    live: Arc<Mutex<LiveCheck>>,
    peer: AuthenticatedPeer,
    peer_cert: CertChain,
    peer_verifying_key: VerifyingKey,
    transcript_id: [u8; 32],
    peer_purpose: SessionPurpose,
    send_counter: u64,
    receive_counter: u64,
    record_timeout: Duration,
    send_poisoned: bool,
    receive_poisoned: bool,
}

impl<R, W> AuthenticatedMeshSession<R, W> {
    /// What the peer's signed Hello said this connection is for.
    #[must_use]
    pub fn peer_purpose(&self) -> SessionPurpose {
        self.peer_purpose
    }

    /// Transport-authenticated carrier identity.
    #[must_use]
    pub fn peer(&self) -> AuthenticatedPeer {
        self.peer
    }

    /// Exact certificate whose leaf proved possession during the handshake.
    #[must_use]
    pub fn peer_cert(&self) -> &CertChain {
        &self.peer_cert
    }

    /// Fresh connection transcript identifier bound into every record.
    #[must_use]
    pub fn transcript_id(&self) -> [u8; 32] {
        self.transcript_id
    }

    /// This endpoint's ordered session role.
    #[must_use]
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// Split after authentication for concurrent receive and reply tasks.
    /// Raw halves remain encapsulated by the authenticated reader/writer types.
    #[must_use]
    pub fn into_split(self) -> (AuthenticatedSessionReader<R>, AuthenticatedSessionWriter<W>) {
        (
            AuthenticatedSessionReader {
                reader: self.reader,
                live: self.live.clone(),
                role: self.role,
                peer: self.peer,
                peer_cert: self.peer_cert,
                peer_verifying_key: self.peer_verifying_key,
                transcript_id: self.transcript_id,
                receive_counter: self.receive_counter,
                record_timeout: self.record_timeout,
                poisoned: self.receive_poisoned,
            },
            AuthenticatedSessionWriter {
                writer: self.writer,
                live: self.live,
                local_agent: self.local_agent,
                role: self.role,
                peer: self.peer,
                transcript_id: self.transcript_id,
                send_counter: self.send_counter,
                record_timeout: self.record_timeout,
                poisoned: self.send_poisoned,
            },
        )
    }
}

impl<R, W> AuthenticatedMeshSession<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Send one carrier-signed, session-bound envelope record.
    pub async fn send_envelope(&mut self, env: &SignedEnvelope) -> Result<(), SessionError> {
        admit(&self.live, &mut self.send_poisoned)?;
        send_authenticated_record(
            &mut self.writer,
            &self.local_agent,
            RecordIoContext {
                transcript_id: &self.transcript_id,
                direction: self.role.outbound_direction(),
                timeout: self.record_timeout,
            },
            &mut self.send_counter,
            &mut self.send_poisoned,
            env,
        )
        .await
    }

    /// Receive, authenticate, then parse one session-bound envelope record.
    pub async fn recv_envelope(&mut self) -> Result<SignedEnvelope, SessionError> {
        let env = receive_authenticated_record(
            &mut self.reader,
            &self.peer_verifying_key,
            RecordIoContext {
                transcript_id: &self.transcript_id,
                direction: self.role.inbound_direction(),
                timeout: self.record_timeout,
            },
            &mut self.receive_counter,
            &mut self.receive_poisoned,
        )
        .await?;
        // Before the envelope is handed on for dispatch.
        admit(&self.live, &mut self.receive_poisoned)?;
        Ok(env)
    }
}

/// Receive half of a split authenticated session.
pub struct AuthenticatedSessionReader<R> {
    reader: R,
    live: Arc<Mutex<LiveCheck>>,
    role: SessionRole,
    peer: AuthenticatedPeer,
    peer_cert: CertChain,
    peer_verifying_key: VerifyingKey,
    transcript_id: [u8; 32],
    receive_counter: u64,
    record_timeout: Duration,
    poisoned: bool,
}

impl<R> AuthenticatedSessionReader<R> {
    /// Transport-authenticated carrier identity.
    #[must_use]
    pub fn peer(&self) -> AuthenticatedPeer {
        self.peer
    }

    /// Exact certificate whose leaf proved possession.
    #[must_use]
    pub fn peer_cert(&self) -> &CertChain {
        &self.peer_cert
    }

    /// Fresh connection transcript identifier.
    #[must_use]
    pub fn transcript_id(&self) -> [u8; 32] {
        self.transcript_id
    }

    /// Local role, which determines the only accepted record direction.
    #[must_use]
    pub fn role(&self) -> SessionRole {
        self.role
    }
}

impl<R> AuthenticatedSessionReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Receive, authenticate, then parse one session-bound envelope record.
    pub async fn recv_envelope(&mut self) -> Result<SignedEnvelope, SessionError> {
        let env = receive_authenticated_record(
            &mut self.reader,
            &self.peer_verifying_key,
            RecordIoContext {
                transcript_id: &self.transcript_id,
                direction: self.role.inbound_direction(),
                timeout: self.record_timeout,
            },
            &mut self.receive_counter,
            &mut self.poisoned,
        )
        .await?;
        // Before the envelope is handed on for dispatch.
        admit(&self.live, &mut self.poisoned)?;
        Ok(env)
    }
}

/// Send half of a split authenticated session.
pub struct AuthenticatedSessionWriter<W> {
    writer: W,
    live: Arc<Mutex<LiveCheck>>,
    local_agent: Arc<AgentKey>,
    role: SessionRole,
    peer: AuthenticatedPeer,
    transcript_id: [u8; 32],
    send_counter: u64,
    record_timeout: Duration,
    poisoned: bool,
}

impl<W> AuthenticatedSessionWriter<W> {
    /// Transport-authenticated peer this writer is connected to.
    #[must_use]
    pub fn peer(&self) -> AuthenticatedPeer {
        self.peer
    }

    /// Fresh connection transcript identifier.
    #[must_use]
    pub fn transcript_id(&self) -> [u8; 32] {
        self.transcript_id
    }

    /// Local role, which determines the only emitted record direction.
    #[must_use]
    pub fn role(&self) -> SessionRole {
        self.role
    }
}

impl<W> AuthenticatedSessionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Send one carrier-signed, session-bound envelope record.
    pub async fn send_envelope(&mut self, env: &SignedEnvelope) -> Result<(), SessionError> {
        admit(&self.live, &mut self.poisoned)?;
        send_authenticated_record(
            &mut self.writer,
            &self.local_agent,
            RecordIoContext {
                transcript_id: &self.transcript_id,
                direction: self.role.outbound_direction(),
                timeout: self.record_timeout,
            },
            &mut self.send_counter,
            &mut self.poisoned,
            env,
        )
        .await
    }
}

/// Marks a record half as unrecoverable unless the complete operation succeeds.
///
/// Async I/O futures may be dropped at any `.await` by `select!`, task abort,
/// or caller cancellation.  At that point an unknown prefix may already have
/// crossed the stream, so retrying with the same counter would desynchronize
/// framing.  Keeping this guard live across the whole operation makes that
/// failure mode structural without unsafe pin/drop machinery.
struct PoisonOnIncompleteRecord<'a> {
    poisoned: &'a mut bool,
    complete: bool,
}

impl<'a> PoisonOnIncompleteRecord<'a> {
    fn arm(poisoned: &'a mut bool) -> Self {
        Self {
            poisoned,
            complete: false,
        }
    }

    fn complete(mut self) {
        self.complete = true;
    }
}

impl Drop for PoisonOnIncompleteRecord<'_> {
    fn drop(&mut self) {
        if !self.complete {
            *self.poisoned = true;
        }
    }
}

#[derive(Clone, Copy)]
struct RecordIoContext<'a> {
    transcript_id: &'a [u8; 32],
    direction: RecordDirection,
    timeout: Duration,
}

async fn send_authenticated_record<W>(
    writer: &mut W,
    local_agent: &AgentKey,
    context: RecordIoContext<'_>,
    send_counter: &mut u64,
    poisoned: &mut bool,
    env: &SignedEnvelope,
) -> Result<(), SessionError>
where
    W: AsyncWrite + Unpin,
{
    if *poisoned {
        return Err(SessionError::Poisoned);
    }
    let next = send_counter
        .checked_add(1)
        .ok_or(SessionError::CounterExhausted)?;
    let poison_guard = PoisonOnIncompleteRecord::arm(poisoned);
    let result = tokio::time::timeout(
        context.timeout,
        write_record(
            writer,
            local_agent,
            context.transcript_id,
            context.direction,
            next,
            env,
        ),
    )
    .await;
    match result {
        Ok(Ok(())) => {
            *send_counter = next;
            poison_guard.complete();
            Ok(())
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(SessionError::Timeout {
            phase: "mesh session record write",
            duration: context.timeout,
        }),
    }
}

async fn receive_authenticated_record<R>(
    reader: &mut R,
    peer_verifying_key: &VerifyingKey,
    context: RecordIoContext<'_>,
    receive_counter: &mut u64,
    poisoned: &mut bool,
) -> Result<SignedEnvelope, SessionError>
where
    R: AsyncRead + Unpin,
{
    if *poisoned {
        return Err(SessionError::Poisoned);
    }
    let next = receive_counter
        .checked_add(1)
        .ok_or(SessionError::CounterExhausted)?;
    let poison_guard = PoisonOnIncompleteRecord::arm(poisoned);
    let result = tokio::time::timeout(
        context.timeout,
        read_record(
            reader,
            peer_verifying_key,
            context.transcript_id,
            context.direction,
            next,
        ),
    )
    .await;
    match result {
        Ok(Ok(env)) => {
            *receive_counter = next;
            poison_guard.complete();
            Ok(env)
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(SessionError::Timeout {
            phase: "mesh session record read",
            duration: context.timeout,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloFrame {
    protocol: String,
    version: u16,
    transport: String,
    role: SessionRole,
    nonce: [u8; 32],
    cert: CertChain,
    parameters: SessionParameters,
    expected_responder: Option<Fingerprint>,
    // Omitted when `Messages`, so a message-mode Hello is byte-identical to
    // one from before streams existed.
    #[serde(default, skip_serializing_if = "SessionPurpose::is_messages")]
    purpose: SessionPurpose,
}

impl HelloFrame {
    fn new(
        role: SessionRole,
        nonce: [u8; 32],
        cert: CertChain,
        parameters: SessionParameters,
        expected_responder: Option<Fingerprint>,
    ) -> Self {
        Self {
            protocol: PROTOCOL_LABEL.to_string(),
            version: PROTOCOL_VERSION,
            transport: TRANSPORT_LABEL.to_string(),
            role,
            nonce,
            cert,
            parameters,
            expected_responder,
            purpose: SessionPurpose::Messages,
        }
    }

    fn with_purpose(mut self, purpose: SessionPurpose) -> Self {
        self.purpose = purpose;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofFrame {
    role: SessionRole,
    transcript_id: [u8; 32],
    signature: SerdeSig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthFrame {
    Hello(Box<HelloFrame>),
    Proof(ProofFrame),
}

impl AuthFrame {
    fn kind(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::Proof(_) => "proof",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordDirection {
    InitiatorToResponder,
    ResponderToInitiator,
}

impl RecordDirection {
    fn as_byte(self) -> u8 {
        match self {
            Self::InitiatorToResponder => 0,
            Self::ResponderToInitiator => 1,
        }
    }

    fn from_byte(value: u8) -> Result<Self, SessionError> {
        match value {
            0 => Ok(Self::InitiatorToResponder),
            1 => Ok(Self::ResponderToInitiator),
            _ => Err(SessionError::RecordDirectionMismatch),
        }
    }
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Re-check the peer against the revocation log; a failure poisons the half,
/// so the session stays down.
fn admit(live: &Mutex<LiveCheck>, poisoned: &mut bool) -> Result<(), SessionError> {
    if *poisoned {
        return Err(SessionError::Poisoned);
    }
    let checked = live
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .admit();
    checked.map_err(|error| {
        *poisoned = true;
        revocation_error(error)
    })
}

/// A transport-level revocation failure, as the session error it is.
fn revocation_error(error: TransportError) -> SessionError {
    match error {
        TransportError::Revoked(agent) => SessionError::PeerRevoked(agent),
        other => SessionError::RevocationUnavailable(other.to_string()),
    }
}

fn validate_local_identity(agent: &AgentKey, state: &RevocationState) -> Result<(), SessionError> {
    agent
        .cert()
        .verify_with(state)
        .map_err(|error| SessionError::InvalidLocalIdentity(error.to_string()))?;
    if agent.verifying_key().as_bytes() != &agent.cert().agent_pubkey {
        return Err(SessionError::InvalidLocalIdentity(
            "signing key does not match certificate leaf".into(),
        ));
    }
    Ok(())
}

fn validate_peer_hello(
    local: &HelloFrame,
    peer: &HelloFrame,
    local_cert: &CertChain,
    parameters: &SessionParameters,
    state: &RevocationState,
) -> Result<VerifyingKey, SessionError> {
    if peer.protocol != PROTOCOL_LABEL
        || peer.version != PROTOCOL_VERSION
        || peer.transport != TRANSPORT_LABEL
    {
        return Err(SessionError::ProtocolMismatch);
    }
    if peer.role != local.role.opposite() {
        return Err(SessionError::RoleMismatch);
    }
    peer.parameters.validate()?;
    if &peer.parameters != parameters {
        return Err(SessionError::ParameterMismatch);
    }

    match local.role {
        SessionRole::Initiator => {
            if peer.expected_responder.is_some()
                || local.expected_responder != Some(peer.cert.agent_fingerprint())
            {
                return Err(SessionError::UnexpectedResponder);
            }
        }
        SessionRole::Responder => {
            if local.expected_responder.is_some()
                || peer.expected_responder != Some(local_cert.agent_fingerprint())
            {
                return Err(SessionError::UnexpectedResponder);
            }
        }
    }

    let local_user = local_cert.user_fingerprint();
    let peer_user = peer.cert.user_fingerprint();
    if peer_user != local_user {
        return Err(SessionError::DifferentUser {
            peer: peer_user.hex(),
            local: local_user.hex(),
        });
    }
    peer.cert.verify_with(state).map_err(|error| match error {
        MeshError::Revoked { agent } => SessionError::PeerRevoked(agent.hex()),
        other => SessionError::BadPeerCertificate(other.to_string()),
    })?;
    VerifyingKey::from_bytes(&peer.cert.agent_pubkey)
        .map_err(|_| SessionError::BadPeerCertificate("invalid ed25519 leaf key".into()))
}

fn make_transcript_id(initiator_hello: &[u8], responder_hello: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRANSCRIPT_DOMAIN);
    hash_length_delimited(&mut hasher, initiator_hello);
    hash_length_delimited(&mut hasher, responder_hello);
    *hasher.finalize().as_bytes()
}

fn hash_length_delimited(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("bounded frame length fits u32");
    hasher.update(&len.to_be_bytes());
    hasher.update(bytes);
}

fn make_proof_message(role: SessionRole, transcript_id: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(PROOF_DOMAIN.len() + 1 + transcript_id.len());
    message.extend_from_slice(PROOF_DOMAIN);
    message.push(role.as_byte());
    message.extend_from_slice(transcript_id);
    message
}

fn make_record_message(
    transcript_id: &[u8; 32],
    direction: RecordDirection,
    counter: u64,
    envelope_bytes: &[u8],
) -> Vec<u8> {
    let envelope_hash = blake3::hash(envelope_bytes);
    let len = u32::try_from(envelope_bytes.len()).expect("bounded envelope length fits u32");
    let mut message = Vec::with_capacity(RECORD_DOMAIN.len() + 32 + 1 + 8 + 4 + 32);
    message.extend_from_slice(RECORD_DOMAIN);
    message.extend_from_slice(transcript_id);
    message.push(direction.as_byte());
    message.extend_from_slice(&counter.to_be_bytes());
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(envelope_hash.as_bytes());
    message
}

fn verify_peer_proof(
    proof: &ProofFrame,
    expected_role: SessionRole,
    transcript_id: &[u8; 32],
    peer_key: &VerifyingKey,
) -> Result<(), SessionError> {
    if proof.role != expected_role {
        return Err(SessionError::RoleMismatch);
    }
    if &proof.transcript_id != transcript_id {
        return Err(SessionError::TranscriptMismatch);
    }
    let message = make_proof_message(expected_role, transcript_id);
    peer_key
        .verify_strict(&message, &proof.signature.0)
        .map_err(|_| SessionError::BadPeerProof)
}

fn encode_auth_frame(frame: &AuthFrame) -> Result<Vec<u8>, SessionError> {
    let bytes = serde_json::to_vec(frame)
        .map_err(|error| SessionError::BadHandshakeFrame(error.to_string()))?;
    let len = u32::try_from(bytes.len()).map_err(|_| SessionError::FrameTooLarge {
        kind: "handshake",
        actual: u32::MAX,
        maximum: MAX_HANDSHAKE_FRAME_BYTES,
    })?;
    if len > MAX_HANDSHAKE_FRAME_BYTES {
        return Err(SessionError::FrameTooLarge {
            kind: "handshake",
            actual: len,
            maximum: MAX_HANDSHAKE_FRAME_BYTES,
        });
    }
    Ok(bytes)
}

async fn exchange_auth_frame<R, W>(
    reader: &mut R,
    writer: &mut W,
    outbound: &[u8],
) -> Result<Vec<u8>, SessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (_, inbound) =
        tokio::try_join!(write_auth_frame(writer, outbound), read_auth_frame(reader))?;
    Ok(inbound)
}

async fn write_auth_frame<W>(writer: &mut W, raw: &[u8]) -> Result<(), SessionError>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(raw.len()).map_err(|_| SessionError::FrameTooLarge {
        kind: "handshake",
        actual: u32::MAX,
        maximum: MAX_HANDSHAKE_FRAME_BYTES,
    })?;
    if len > MAX_HANDSHAKE_FRAME_BYTES {
        return Err(SessionError::FrameTooLarge {
            kind: "handshake",
            actual: len,
            maximum: MAX_HANDSHAKE_FRAME_BYTES,
        });
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(raw).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_auth_frame<R>(reader: &mut R) -> Result<Vec<u8>, SessionError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_HANDSHAKE_FRAME_BYTES {
        return Err(SessionError::FrameTooLarge {
            kind: "handshake",
            actual: len,
            maximum: MAX_HANDSHAKE_FRAME_BYTES,
        });
    }
    let mut raw = vec![0u8; len as usize];
    reader.read_exact(&mut raw).await?;
    Ok(raw)
}

fn decode_auth_frame(raw: &[u8]) -> Result<AuthFrame, SessionError> {
    serde_json::from_slice(raw).map_err(|error| SessionError::BadHandshakeFrame(error.to_string()))
}

fn expect_hello(raw: &[u8]) -> Result<HelloFrame, SessionError> {
    match decode_auth_frame(raw)? {
        AuthFrame::Hello(hello) => Ok(*hello),
        frame => Err(SessionError::UnexpectedFrame {
            expected: "hello",
            actual: frame.kind(),
        }),
    }
}

fn expect_proof(raw: &[u8]) -> Result<ProofFrame, SessionError> {
    match decode_auth_frame(raw)? {
        AuthFrame::Proof(proof) => Ok(proof),
        frame => Err(SessionError::UnexpectedFrame {
            expected: "proof",
            actual: frame.kind(),
        }),
    }
}

async fn write_record<W>(
    writer: &mut W,
    local_agent: &AgentKey,
    transcript_id: &[u8; 32],
    direction: RecordDirection,
    counter: u64,
    env: &SignedEnvelope,
) -> Result<(), SessionError>
where
    W: AsyncWrite + Unpin,
{
    let envelope_bytes =
        serde_json::to_vec(env).map_err(|error| SessionError::BadEnvelope(error.to_string()))?;
    let len = u32::try_from(envelope_bytes.len()).map_err(|_| SessionError::FrameTooLarge {
        kind: "envelope",
        actual: u32::MAX,
        maximum: MAX_SESSION_ENVELOPE_BYTES,
    })?;
    if len > MAX_SESSION_ENVELOPE_BYTES {
        return Err(SessionError::FrameTooLarge {
            kind: "envelope",
            actual: len,
            maximum: MAX_SESSION_ENVELOPE_BYTES,
        });
    }

    let message = make_record_message(transcript_id, direction, counter, &envelope_bytes);
    let signature = local_agent.sign(&message).to_bytes();
    writer.write_all(transcript_id).await?;
    writer.write_all(&[direction.as_byte()]).await?;
    writer.write_all(&counter.to_be_bytes()).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&envelope_bytes).await?;
    writer.write_all(&signature).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_record<R>(
    reader: &mut R,
    peer_key: &VerifyingKey,
    transcript_id: &[u8; 32],
    expected_direction: RecordDirection,
    expected_counter: u64,
) -> Result<SignedEnvelope, SessionError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; RECORD_HEADER_BYTES];
    reader.read_exact(&mut header).await?;

    let mut record_session = [0u8; 32];
    record_session.copy_from_slice(&header[..32]);
    if &record_session != transcript_id {
        return Err(SessionError::RecordSessionMismatch);
    }
    let direction = RecordDirection::from_byte(header[32])?;
    if direction != expected_direction {
        return Err(SessionError::RecordDirectionMismatch);
    }
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&header[33..41]);
    let counter = u64::from_be_bytes(counter_bytes);
    if counter != expected_counter {
        return Err(SessionError::RecordCounterMismatch {
            expected: expected_counter,
            actual: counter,
        });
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&header[41..45]);
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_SESSION_ENVELOPE_BYTES {
        return Err(SessionError::FrameTooLarge {
            kind: "envelope",
            actual: len,
            maximum: MAX_SESSION_ENVELOPE_BYTES,
        });
    }

    let mut envelope_bytes = vec![0u8; len as usize];
    reader.read_exact(&mut envelope_bytes).await?;
    let mut signature_bytes = [0u8; RECORD_SIGNATURE_BYTES];
    reader.read_exact(&mut signature_bytes).await?;
    let signature = Signature::from_bytes(&signature_bytes);
    let message = make_record_message(transcript_id, direction, counter, &envelope_bytes);
    peer_key
        .verify_strict(&message, &signature)
        .map_err(|_| SessionError::BadRecordSignature)?;

    // Parse only after the outer carrier binding succeeds.  Carrier and inner
    // signer deliberately remain distinct; the bus admission boundary decides
    // whether a delivery mode permits them to differ.
    serde_json::from_slice(&envelope_bytes)
        .map_err(|error| SessionError::BadEnvelope(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::future::{poll_fn, Future};
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::Poll;

    use agent_mesh_bus::{BusError, DeliveryProvenance, Inbox};
    use agent_mesh_protocol::{AgentMetadata, Caveats, Recipient, Scope, UserKey};
    use serde_json::Value;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

    use super::*;

    type TestSession = AuthenticatedMeshSession<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;
    type TestPending = UnauthenticatedMeshSession<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;

    fn metadata(role: &str) -> AgentMetadata {
        AgentMetadata {
            role: role.into(),
            host: "session-test".into(),
            capabilities: vec!["test".into()],
            issued_at: "2026-08-14T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        }
    }

    /// One in-memory revocation guard per test user, keyed by the user's
    /// fingerprint, so a helper holding only an agent can get the right one.
    static GUARDS: std::sync::Mutex<
        Vec<(
            agent_mesh_protocol::Fingerprint,
            agent_mesh_transport::RevocationGuard,
        )>,
    > = std::sync::Mutex::new(Vec::new());

    fn register_user(user: &UserKey) {
        GUARDS.lock().unwrap().push((
            user.fingerprint(),
            agent_mesh_transport::RevocationGuard::in_memory(user),
        ));
    }

    trait UserOf {
        fn user_fp(&self) -> agent_mesh_protocol::Fingerprint;
    }
    impl UserOf for AgentKey {
        fn user_fp(&self) -> agent_mesh_protocol::Fingerprint {
            self.cert().user_fingerprint()
        }
    }
    impl UserOf for Arc<AgentKey> {
        fn user_fp(&self) -> agent_mesh_protocol::Fingerprint {
            self.cert().user_fingerprint()
        }
    }
    impl UserOf for CertChain {
        fn user_fp(&self) -> agent_mesh_protocol::Fingerprint {
            self.user_fingerprint()
        }
    }

    /// The test user's guard (an empty log: nothing revoked).
    fn guard_for(of: &impl UserOf) -> agent_mesh_transport::RevocationGuard {
        let fp = of.user_fp();
        let guards = GUARDS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guards
            .iter()
            .find(|(f, _)| *f == fp)
            .map(|(_, g)| g.clone())
            .expect("agent was issued by a test helper that registers its user")
    }

    fn agent(user: &UserKey, role: &str) -> Arc<AgentKey> {
        register_user(user);
        Arc::new(AgentKey::issue(user, metadata(role)))
    }

    fn short_timeouts() -> SessionTimeouts {
        SessionTimeouts {
            authentication: Duration::from_secs(1),
            record: Duration::from_millis(25),
        }
    }

    /// A record deadline no scheduler hiccup reaches. Tests that exchange
    /// records use it; a test that asserts a stall times out runs on paused
    /// time, where the deadline's length costs nothing. Only handshake-level
    /// tests keep `short_timeouts`: a 25 ms record write lost that race on a
    /// loaded macOS runner.
    fn roomy_timeouts() -> SessionTimeouts {
        SessionTimeouts {
            authentication: Duration::from_secs(1),
            record: Duration::from_secs(60),
        }
    }

    async fn poll_once_pending<F>(mut future: Pin<&mut F>)
    where
        F: Future,
    {
        poll_fn(|cx| match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("partial record operation unexpectedly completed"),
        })
        .await;
    }

    async fn authenticated_pair_with(
        initiator: Arc<AgentKey>,
        responder: Arc<AgentKey>,
        parameters: SessionParameters,
        timeouts: SessionTimeouts,
        capacity: usize,
    ) -> (TestSession, TestSession) {
        let (initiator_guard, responder_guard) = (guard_for(&initiator), guard_for(&responder));
        let (left, right) = tokio::io::duplex(capacity);
        let (left_reader, left_writer) = tokio::io::split(left);
        let (right_reader, right_writer) = tokio::io::split(right);
        let left = UnauthenticatedMeshSession::initiator(
            left_reader,
            left_writer,
            initiator,
            responder.fingerprint(),
            parameters.clone(),
            timeouts,
            initiator_guard,
        );
        let right = UnauthenticatedMeshSession::responder(
            right_reader,
            right_writer,
            responder,
            parameters,
            timeouts,
            responder_guard,
        );
        let (left, right) = tokio::join!(left.authenticate(), right.authenticate());
        (
            left.expect("initiator authenticates"),
            right.expect("responder authenticates"),
        )
    }

    async fn authenticated_pair(
        initiator: Arc<AgentKey>,
        responder: Arc<AgentKey>,
    ) -> (TestSession, TestSession) {
        authenticated_pair_with(
            initiator,
            responder,
            SessionParameters::default(),
            roomy_timeouts(),
            64,
        )
        .await
    }

    fn pending_initiator(
        stream: DuplexStream,
        local: Arc<AgentKey>,
        expected_responder: Fingerprint,
        timeouts: SessionTimeouts,
    ) -> TestPending {
        let (reader, writer) = tokio::io::split(stream);
        let guard = guard_for(&local);
        UnauthenticatedMeshSession::initiator(
            reader,
            writer,
            local,
            expected_responder,
            SessionParameters::default(),
            timeouts,
            guard,
        )
    }

    async fn responder_hello_flight<R, W, F>(
        reader: &mut R,
        writer: &mut W,
        claimed_cert: CertChain,
        nonce: [u8; 32],
        mutate: F,
    ) -> [u8; 32]
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
        F: FnOnce(&mut HelloFrame),
    {
        let initiator_raw = read_auth_frame(reader).await.expect("initiator hello");
        let initiator = expect_hello(&initiator_raw).expect("valid initiator hello");
        let mut responder = HelloFrame::new(
            SessionRole::Responder,
            nonce,
            claimed_cert,
            initiator.parameters.clone(),
            None,
        );
        mutate(&mut responder);
        let responder_raw = hello_raw(responder);
        write_auth_frame(writer, &responder_raw)
            .await
            .expect("responder hello");
        make_transcript_id(&initiator_raw, &responder_raw)
    }

    fn authentication_error(result: Result<TestSession, SessionError>) -> SessionError {
        match result {
            Ok(_) => panic!("malicious peer minted an authenticated session"),
            Err(error) => error,
        }
    }

    fn envelope(
        signer: &AgentKey,
        recipient: Fingerprint,
        sequence: u64,
        payload: Vec<u8>,
    ) -> SignedEnvelope {
        SignedEnvelope::new(
            signer,
            Recipient::Direct {
                agent_fp: recipient,
            },
            sequence,
            payload,
        )
    }

    async fn encoded_record(
        carrier: &AgentKey,
        transcript_id: &[u8; 32],
        direction: RecordDirection,
        counter: u64,
        env: &SignedEnvelope,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_record(&mut bytes, carrier, transcript_id, direction, counter, env)
            .await
            .expect("encode test record");
        bytes
    }

    fn encoded_raw_record(
        carrier: &AgentKey,
        transcript_id: &[u8; 32],
        direction: RecordDirection,
        counter: u64,
        envelope_bytes: &[u8],
    ) -> Vec<u8> {
        let message = make_record_message(transcript_id, direction, counter, envelope_bytes);
        let signature = carrier.sign(&message).to_bytes();
        let mut bytes =
            Vec::with_capacity(RECORD_HEADER_BYTES + envelope_bytes.len() + RECORD_SIGNATURE_BYTES);
        bytes.extend_from_slice(transcript_id);
        bytes.push(direction.as_byte());
        bytes.extend_from_slice(&counter.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(envelope_bytes.len())
                .expect("test envelope fits")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(envelope_bytes);
        bytes.extend_from_slice(&signature);
        bytes
    }

    fn hello_raw(hello: HelloFrame) -> Vec<u8> {
        encode_auth_frame(&AuthFrame::Hello(Box::new(hello))).expect("encode hello")
    }

    fn assert_no_secret_field(value: &Value) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    let key = key.to_ascii_lowercase();
                    assert!(!key.contains("private"));
                    assert!(!key.contains("secret"));
                    assert!(!key.contains("signing_key"));
                    assert!(!key.contains("seed"));
                    assert_no_secret_field(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    assert_no_secret_field(value);
                }
            }
            _ => {}
        }
    }

    #[tokio::test]
    async fn mutual_authentication_mints_peer_and_split_round_trips() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let (alice_session, bob_session) = authenticated_pair(alice.clone(), bob.clone()).await;

        assert_eq!(alice_session.role(), SessionRole::Initiator);
        assert_eq!(bob_session.role(), SessionRole::Responder);
        assert_eq!(alice_session.peer().agent_fp, bob.fingerprint());
        assert_eq!(bob_session.peer().agent_fp, alice.fingerprint());
        assert_eq!(alice_session.peer().user_fp, user.fingerprint());
        assert_eq!(alice_session.peer_cert(), bob.cert());
        assert_eq!(alice_session.transcript_id(), bob_session.transcript_id());
        assert_ne!(alice_session.transcript_id(), [0; 32]);

        let (mut alice_reader, mut alice_writer) = alice_session.into_split();
        let (mut bob_reader, mut bob_writer) = bob_session.into_split();
        assert_eq!(alice_reader.peer(), alice_writer.peer());
        assert_eq!(bob_reader.transcript_id(), bob_writer.transcript_id());

        let request = envelope(&alice, bob.fingerprint(), 8, b"request".to_vec());
        let (sent, received) = tokio::join!(
            alice_writer.send_envelope(&request),
            bob_reader.recv_envelope()
        );
        sent.expect("send request");
        assert_eq!(received.expect("receive request"), request);

        let response = envelope(&bob, alice.fingerprint(), 9, b"response".to_vec());
        let (sent, received) = tokio::join!(
            bob_writer.send_envelope(&response),
            alice_reader.recv_envelope()
        );
        sent.expect("send response");
        assert_eq!(received.expect("receive response"), response);
    }

    #[test]
    fn wire_hello_contains_the_certificate_but_no_private_key() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let hello = HelloFrame::new(
            SessionRole::Initiator,
            [7; 32],
            alice.cert().clone(),
            SessionParameters::default(),
            Some(alice.fingerprint()),
        );
        let raw = hello_raw(hello);
        let value: Value = serde_json::from_slice(&raw).expect("valid JSON");
        assert_eq!(
            value["hello"]["cert"],
            serde_json::to_value(alice.cert()).expect("cert JSON")
        );
        assert_no_secret_field(&value);
    }

    /// Stream mode is declared in the signed Hello (so it is in the transcript
    /// both peers prove); a message-mode Hello is unchanged on the wire.
    #[test]
    fn stream_purpose_is_in_the_hello_and_message_hello_is_unchanged() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let hello = || {
            HelloFrame::new(
                SessionRole::Initiator,
                [7; 32],
                alice.cert().clone(),
                SessionParameters::default(),
                Some(alice.fingerprint()),
            )
        };
        let messages: Value = serde_json::from_slice(&hello_raw(hello())).unwrap();
        assert!(messages["hello"].get("purpose").is_none());
        let stream_raw = hello_raw(hello().with_purpose(SessionPurpose::Stream));
        let stream: Value = serde_json::from_slice(&stream_raw).unwrap();
        assert_eq!(stream["hello"]["purpose"], "stream");
        assert_ne!(
            make_transcript_id(&hello_raw(hello()), &stream_raw),
            make_transcript_id(&stream_raw, &stream_raw)
        );
    }

    #[test]
    fn certificate_without_its_private_key_cannot_complete_the_proof() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let mallory = agent(&user, "mallory");
        let transcript_id = [8; 32];

        // Mallory can copy Alice's public certificate and knows the complete
        // transcript, but cannot make a proof which verifies under Alice's
        // certified leaf key.
        let forged = ProofFrame {
            role: SessionRole::Responder,
            transcript_id,
            signature: SerdeSig(
                mallory.sign(&make_proof_message(SessionRole::Responder, &transcript_id)),
            ),
        };
        assert!(matches!(
            verify_peer_proof(
                &forged,
                SessionRole::Responder,
                &transcript_id,
                &alice.verifying_key()
            ),
            Err(SessionError::BadPeerProof)
        ));
    }

    #[test]
    fn proof_frame_rejects_unknown_fields() {
        let proof = AuthFrame::Proof(ProofFrame {
            role: SessionRole::Responder,
            transcript_id: [9; 32],
            signature: SerdeSig(Signature::from_bytes(&[0; 64])),
        });
        let mut value = serde_json::to_value(proof).expect("proof JSON");
        value["proof"]
            .as_object_mut()
            .expect("proof object")
            .insert("unbound_field".into(), Value::Bool(true));
        let raw = serde_json::to_vec(&value).expect("mutated proof JSON");
        assert!(matches!(
            expect_proof(&raw),
            Err(SessionError::BadHandshakeFrame(_))
        ));
    }

    #[tokio::test]
    async fn authenticate_rejects_copied_cert_without_private_key() {
        let user = UserKey::generate();
        let bob = agent(&user, "bob");
        let alice = agent(&user, "alice");
        let alice_fp = alice.fingerprint();
        let copied_alice_cert = alice.cert().clone();
        drop(alice);
        let mallory = agent(&user, "mallory");
        let (local_stream, malicious_stream) = tokio::io::duplex(64);
        let pending = pending_initiator(local_stream, bob, alice_fp, short_timeouts());

        let malicious_peer = async move {
            let (mut reader, mut writer) = tokio::io::split(malicious_stream);
            let transcript_id = responder_hello_flight(
                &mut reader,
                &mut writer,
                copied_alice_cert,
                [60; 32],
                |_| {},
            )
            .await;
            let _local_proof = read_auth_frame(&mut reader).await.expect("local proof");
            let forged = ProofFrame {
                role: SessionRole::Responder,
                transcript_id,
                signature: SerdeSig(
                    mallory.sign(&make_proof_message(SessionRole::Responder, &transcript_id)),
                ),
            };
            write_auth_frame(
                &mut writer,
                &encode_auth_frame(&AuthFrame::Proof(forged)).expect("forged proof"),
            )
            .await
            .expect("send forged proof");
        };
        let (result, ()) = tokio::join!(pending.authenticate(), malicious_peer);
        assert!(matches!(
            authentication_error(result),
            SessionError::BadPeerProof
        ));
    }

    #[tokio::test]
    async fn authenticate_rejects_fresh_replay_and_literal_same_key_reflection() {
        let user = UserKey::generate();
        let bob = agent(&user, "bob");
        let alice = agent(&user, "alice");
        let old_initiator = HelloFrame::new(
            SessionRole::Initiator,
            [61; 32],
            bob.cert().clone(),
            SessionParameters::default(),
            Some(alice.fingerprint()),
        );
        let old_responder = HelloFrame::new(
            SessionRole::Responder,
            [62; 32],
            alice.cert().clone(),
            SessionParameters::default(),
            None,
        );
        let old_transcript =
            make_transcript_id(&hello_raw(old_initiator), &hello_raw(old_responder));
        let captured = ProofFrame {
            role: SessionRole::Responder,
            transcript_id: old_transcript,
            signature: SerdeSig(
                alice.sign(&make_proof_message(SessionRole::Responder, &old_transcript)),
            ),
        };
        let (local_stream, malicious_stream) = tokio::io::duplex(64);
        let pending = pending_initiator(local_stream, bob, alice.fingerprint(), short_timeouts());
        let alice_cert = alice.cert().clone();
        let replay_peer = async move {
            let (mut reader, mut writer) = tokio::io::split(malicious_stream);
            let fresh_transcript =
                responder_hello_flight(&mut reader, &mut writer, alice_cert, [63; 32], |_| {})
                    .await;
            assert_ne!(fresh_transcript, old_transcript);
            let _local_proof = read_auth_frame(&mut reader).await.expect("local proof");
            write_auth_frame(
                &mut writer,
                &encode_auth_frame(&AuthFrame::Proof(captured)).expect("captured proof"),
            )
            .await
            .expect("replay proof");
        };
        let (result, ()) = tokio::join!(pending.authenticate(), replay_peer);
        assert!(matches!(
            authentication_error(result),
            SessionError::TranscriptMismatch
        ));

        // With the same AgentKey on both endpoints, reflect the initiator's
        // exact proof bytes. The signature and transcript are valid under the
        // expected key; only the ordered proof role makes it inadmissible.
        let shared = agent(&user, "shared");
        let (local_stream, malicious_stream) = tokio::io::duplex(64);
        let pending = pending_initiator(
            local_stream,
            shared.clone(),
            shared.fingerprint(),
            short_timeouts(),
        );
        let shared_cert = shared.cert().clone();
        let reflection_peer = async move {
            let (mut reader, mut writer) = tokio::io::split(malicious_stream);
            responder_hello_flight(&mut reader, &mut writer, shared_cert, [64; 32], |_| {}).await;
            let reflected = read_auth_frame(&mut reader).await.expect("local proof");
            write_auth_frame(&mut writer, &reflected)
                .await
                .expect("reflect proof");
        };
        let (result, ()) = tokio::join!(pending.authenticate(), reflection_peer);
        assert!(matches!(
            authentication_error(result),
            SessionError::RoleMismatch
        ));
    }

    #[tokio::test]
    async fn authenticate_rejects_tampered_hello_and_proof_fields() {
        let user = UserKey::generate();
        let bob = agent(&user, "bob");
        let alice = agent(&user, "alice");

        let (local_stream, malicious_stream) = tokio::io::duplex(64);
        let pending = pending_initiator(
            local_stream,
            bob.clone(),
            alice.fingerprint(),
            short_timeouts(),
        );
        let alice_cert = alice.cert().clone();
        let tampered_hello_peer = async move {
            let (mut reader, mut writer) = tokio::io::split(malicious_stream);
            responder_hello_flight(&mut reader, &mut writer, alice_cert, [65; 32], |hello| {
                hello.transport = "tampered".into();
            })
            .await;
        };
        let (result, ()) = tokio::join!(pending.authenticate(), tampered_hello_peer);
        assert!(matches!(
            authentication_error(result),
            SessionError::ProtocolMismatch
        ));

        let (local_stream, malicious_stream) = tokio::io::duplex(64);
        let pending = pending_initiator(local_stream, bob, alice.fingerprint(), short_timeouts());
        let tampered_proof_peer = async move {
            let (mut reader, mut writer) = tokio::io::split(malicious_stream);
            let transcript_id = responder_hello_flight(
                &mut reader,
                &mut writer,
                alice.cert().clone(),
                [66; 32],
                |_| {},
            )
            .await;
            let _local_proof = read_auth_frame(&mut reader).await.expect("local proof");
            let mut tampered_id = transcript_id;
            tampered_id[0] ^= 1;
            let tampered = ProofFrame {
                role: SessionRole::Responder,
                transcript_id: tampered_id,
                signature: SerdeSig(
                    alice.sign(&make_proof_message(SessionRole::Responder, &transcript_id)),
                ),
            };
            write_auth_frame(
                &mut writer,
                &encode_auth_frame(&AuthFrame::Proof(tampered)).expect("tampered proof"),
            )
            .await
            .expect("send tampered proof");
        };
        let (result, ()) = tokio::join!(pending.authenticate(), tampered_proof_peer);
        assert!(matches!(
            authentication_error(result),
            SessionError::TranscriptMismatch
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn authentication_deadline_covers_a_stall_after_local_proof_is_read() {
        let user = UserKey::generate();
        let bob = agent(&user, "bob");
        let alice = agent(&user, "alice");
        let (local_stream, malicious_stream) = tokio::io::duplex(64);
        let pending = pending_initiator(
            local_stream,
            bob,
            alice.fingerprint(),
            SessionTimeouts {
                authentication: Duration::from_millis(10),
                record: Duration::from_secs(1),
            },
        );
        let alice_cert = alice.cert().clone();
        let (proof_seen_tx, proof_seen_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(malicious_stream);
            responder_hello_flight(&mut reader, &mut writer, alice_cert, [67; 32], |_| {}).await;
            let _local_proof = read_auth_frame(&mut reader).await.expect("local proof");
            proof_seen_tx.send(()).expect("report observed proof");
            let _ = release_rx.await;
        });

        let error = authentication_error(pending.authenticate().await);
        assert!(matches!(
            error,
            SessionError::Timeout {
                phase: "mesh session authentication",
                ..
            }
        ));
        proof_seen_rx
            .await
            .expect("peer completed Hello and read the local proof before timeout");
        let _ = release_tx.send(());
        peer.await.expect("malicious peer task");
    }

    #[test]
    fn fresh_nonce_invalidates_a_captured_proof() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let initiator = HelloFrame::new(
            SessionRole::Initiator,
            [1; 32],
            alice.cert().clone(),
            SessionParameters::default(),
            Some(bob.fingerprint()),
        );
        let responder = HelloFrame::new(
            SessionRole::Responder,
            [2; 32],
            bob.cert().clone(),
            SessionParameters::default(),
            None,
        );
        let first_id =
            make_transcript_id(&hello_raw(initiator.clone()), &hello_raw(responder.clone()));
        let captured_signature = bob.sign(&make_proof_message(SessionRole::Responder, &first_id));

        let mut fresh_responder = responder;
        fresh_responder.nonce = [3; 32];
        let fresh_id = make_transcript_id(&hello_raw(initiator), &hello_raw(fresh_responder));
        assert_ne!(first_id, fresh_id);

        let replay = ProofFrame {
            role: SessionRole::Responder,
            transcript_id: fresh_id,
            signature: SerdeSig(captured_signature),
        };
        assert!(matches!(
            verify_peer_proof(
                &replay,
                SessionRole::Responder,
                &fresh_id,
                &bob.verifying_key()
            ),
            Err(SessionError::BadPeerProof)
        ));
    }

    #[test]
    fn role_domains_stop_hello_and_proof_reflection_even_with_one_key() {
        let user = UserKey::generate();
        let shared = agent(&user, "shared");
        let reflected_hello = HelloFrame::new(
            SessionRole::Initiator,
            [4; 32],
            shared.cert().clone(),
            SessionParameters::default(),
            Some(shared.fingerprint()),
        );
        assert!(matches!(
            validate_peer_hello(
                &reflected_hello,
                &reflected_hello,
                shared.cert(),
                &SessionParameters::default(),
                &guard_for(shared.cert()).state().unwrap()
            ),
            Err(SessionError::RoleMismatch)
        ));

        let transcript_id = [5; 32];
        let reflected_signature =
            shared.sign(&make_proof_message(SessionRole::Initiator, &transcript_id));
        let reflected_proof = ProofFrame {
            role: SessionRole::Responder,
            transcript_id,
            signature: SerdeSig(reflected_signature),
        };
        assert!(matches!(
            verify_peer_proof(
                &reflected_proof,
                SessionRole::Responder,
                &transcript_id,
                &shared.verifying_key()
            ),
            Err(SessionError::BadPeerProof)
        ));
    }

    #[test]
    fn transcript_binds_every_hello_field_and_exact_raw_bytes() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let other = agent(&user, "other");
        let initiator = HelloFrame::new(
            SessionRole::Initiator,
            [10; 32],
            alice.cert().clone(),
            SessionParameters::default(),
            Some(bob.fingerprint()),
        );
        let responder = HelloFrame::new(
            SessionRole::Responder,
            [11; 32],
            bob.cert().clone(),
            SessionParameters::default(),
            None,
        );
        let initiator_raw = hello_raw(initiator.clone());
        let responder_raw = hello_raw(responder.clone());
        let baseline = make_transcript_id(&initiator_raw, &responder_raw);
        let captured_proof = bob.sign(&make_proof_message(SessionRole::Responder, &baseline));

        let mut variants = Vec::new();
        macro_rules! mutate_both {
            ($field:ident, $left:expr, $right:expr) => {{
                let mut changed = initiator.clone();
                changed.$field = $left;
                variants.push((hello_raw(changed), responder_raw.clone()));
                let mut changed = responder.clone();
                changed.$field = $right;
                variants.push((initiator_raw.clone(), hello_raw(changed)));
            }};
        }
        mutate_both!(protocol, "other-protocol".into(), "other-protocol".into());
        mutate_both!(version, 2, 2);
        mutate_both!(
            transport,
            "other-transport".into(),
            "other-transport".into()
        );
        mutate_both!(role, SessionRole::Responder, SessionRole::Initiator);
        mutate_both!(nonce, [12; 32], [13; 32]);
        mutate_both!(cert, other.cert().clone(), other.cert().clone());

        let mut changed = initiator.clone();
        changed.parameters.record_version += 1;
        variants.push((hello_raw(changed), responder_raw.clone()));
        let mut changed = responder.clone();
        changed.parameters.max_envelope_bytes -= 1;
        variants.push((initiator_raw.clone(), hello_raw(changed)));
        let mut changed = initiator.clone();
        changed.parameters.current_generation = Some(7);
        variants.push((hello_raw(changed), responder_raw.clone()));
        let mut changed = initiator.clone();
        changed.expected_responder = None;
        variants.push((hello_raw(changed), responder_raw.clone()));
        let mut changed = responder;
        changed.expected_responder = Some(alice.fingerprint());
        variants.push((initiator_raw.clone(), hello_raw(changed)));

        let mut whitespace_changed = Vec::with_capacity(initiator_raw.len() + 1);
        whitespace_changed.push(b' ');
        whitespace_changed.extend_from_slice(&initiator_raw);
        variants.push((whitespace_changed, responder_raw));

        for (changed_initiator, changed_responder) in variants {
            let changed_id = make_transcript_id(&changed_initiator, &changed_responder);
            assert_ne!(changed_id, baseline);
            let replay = ProofFrame {
                role: SessionRole::Responder,
                transcript_id: changed_id,
                signature: SerdeSig(captured_proof),
            };
            assert!(matches!(
                verify_peer_proof(
                    &replay,
                    SessionRole::Responder,
                    &changed_id,
                    &bob.verifying_key()
                ),
                Err(SessionError::BadPeerProof)
            ));
        }
    }

    #[test]
    fn hello_validation_checks_version_and_transport_independently() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let local = HelloFrame::new(
            SessionRole::Initiator,
            [18; 32],
            alice.cert().clone(),
            SessionParameters::default(),
            Some(bob.fingerprint()),
        );
        let peer = HelloFrame::new(
            SessionRole::Responder,
            [19; 32],
            bob.cert().clone(),
            SessionParameters::default(),
            None,
        );

        let mut wrong_version = peer.clone();
        wrong_version.version += 1;
        assert!(matches!(
            validate_peer_hello(
                &local,
                &wrong_version,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::ProtocolMismatch)
        ));
        let mut wrong_transport = peer;
        wrong_transport.transport = "not-ssh".into();
        assert!(matches!(
            validate_peer_hello(
                &local,
                &wrong_transport,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::ProtocolMismatch)
        ));
    }

    #[test]
    fn hello_validation_rejects_protocol_role_parameters_identity_cert_and_root() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let local = HelloFrame::new(
            SessionRole::Initiator,
            [20; 32],
            alice.cert().clone(),
            SessionParameters::default(),
            Some(bob.fingerprint()),
        );
        let peer = HelloFrame::new(
            SessionRole::Responder,
            [21; 32],
            bob.cert().clone(),
            SessionParameters::default(),
            None,
        );
        validate_peer_hello(
            &local,
            &peer,
            alice.cert(),
            &SessionParameters::default(),
            &guard_for(alice.cert()).state().unwrap(),
        )
        .expect("baseline hello");

        let mut changed = peer.clone();
        changed.protocol = "wrong".into();
        assert!(matches!(
            validate_peer_hello(
                &local,
                &changed,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::ProtocolMismatch)
        ));
        let mut changed = peer.clone();
        changed.role = SessionRole::Initiator;
        assert!(matches!(
            validate_peer_hello(
                &local,
                &changed,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::RoleMismatch)
        ));
        let mut changed = peer.clone();
        changed.parameters.current_generation = Some(1);
        assert!(matches!(
            validate_peer_hello(
                &local,
                &changed,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::ParameterMismatch)
        ));
        let mut wrong_expected = local.clone();
        wrong_expected.expected_responder = Some(alice.fingerprint());
        assert!(matches!(
            validate_peer_hello(
                &wrong_expected,
                &peer,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::UnexpectedResponder)
        ));
        let mut changed = peer.clone();
        let mut signature = changed.cert.issuer_sig.0.to_bytes();
        signature[0] ^= 1;
        changed.cert.issuer_sig = SerdeSig(Signature::from_bytes(&signature));
        assert!(matches!(
            validate_peer_hello(
                &local,
                &changed,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::BadPeerCertificate(_))
        ));

        let other_user = UserKey::generate();
        let stranger = agent(&other_user, "stranger");
        let local_for_stranger = HelloFrame::new(
            SessionRole::Initiator,
            [22; 32],
            alice.cert().clone(),
            SessionParameters::default(),
            Some(stranger.fingerprint()),
        );
        let stranger_hello = HelloFrame::new(
            SessionRole::Responder,
            [23; 32],
            stranger.cert().clone(),
            SessionParameters::default(),
            None,
        );
        assert!(matches!(
            validate_peer_hello(
                &local_for_stranger,
                &stranger_hello,
                alice.cert(),
                &SessionParameters::default(),
                &guard_for(alice.cert()).state().unwrap()
            ),
            Err(SessionError::DifferentUser { .. })
        ));
    }

    #[tokio::test]
    async fn generation_context_is_applied_to_both_certificates() {
        // The log's generation is the session's causal generation: certs scoped
        // to generation 5 authenticate under a log bumped to 5, and not under
        // an unbumped one.
        let f = LogFixture::new();
        let scoped = |role: &str| {
            let mut metadata = metadata(role);
            metadata.caveats = Caveats {
                valid_for_generation: Scope::only([5]),
                ..Caveats::top()
            };
            Arc::new(AgentKey::issue(&f.user, metadata))
        };
        let (alice, bob) = (scoped("alice"), scoped("bob"));
        let (stale, _) = pair_with_guards(
            alice.clone(),
            bob.clone(),
            f.guard(),
            RevocationGuard::in_memory(&f.user),
        )
        .await;
        assert!(stale.is_err(), "generation 0 does not admit gen-5 certs");

        f.bump(5);
        let (left, right) = pair_with_guards(alice, bob, f.guard(), f.guard()).await;
        let (left, right) = (left.unwrap(), right.unwrap());
        assert_eq!(left.transcript_id(), right.transcript_id());
    }

    #[tokio::test]
    async fn handshake_framing_rejects_malformed_oversize_and_truncated_inputs() {
        assert!(matches!(
            decode_auth_frame(b"{not-json"),
            Err(SessionError::BadHandshakeFrame(_))
        ));

        let mut oversized = Cursor::new((MAX_HANDSHAKE_FRAME_BYTES + 1).to_be_bytes().to_vec());
        assert!(matches!(
            read_auth_frame(&mut oversized).await,
            Err(SessionError::FrameTooLarge {
                kind: "handshake",
                ..
            })
        ));
        let mut output = Vec::new();
        let too_large = vec![0; MAX_HANDSHAKE_FRAME_BYTES as usize + 1];
        assert!(matches!(
            write_auth_frame(&mut output, &too_large).await,
            Err(SessionError::FrameTooLarge {
                kind: "handshake",
                ..
            })
        ));

        let mut truncated_bytes = 12u32.to_be_bytes().to_vec();
        truncated_bytes.extend_from_slice(b"short");
        let mut truncated = Cursor::new(truncated_bytes);
        assert!(matches!(
            read_auth_frame(&mut truncated).await,
            Err(SessionError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn whole_handshake_stall_hits_one_authentication_deadline() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let (local, _stalled_peer) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(local);
        let guard = guard_for(&alice);
        let pending = UnauthenticatedMeshSession::initiator(
            reader,
            writer,
            alice,
            bob.fingerprint(),
            SessionParameters::default(),
            SessionTimeouts {
                authentication: Duration::from_millis(10),
                record: Duration::from_secs(1),
            },
            guard,
        );
        let error = match pending.authenticate().await {
            Ok(_) => panic!("stalled peer authenticated"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SessionError::Timeout {
                phase: "mesh session authentication",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn first_record_is_one_and_carrier_may_differ_from_envelope_signer() {
        let user = UserKey::generate();
        let carrier = agent(&user, "carrier");
        let receiver = agent(&user, "receiver");
        let original_signer = agent(&user, "original-signer");
        let transcript_id = [30; 32];
        let env = envelope(
            &original_signer,
            receiver.fingerprint(),
            44,
            b"relayed-but-valid".to_vec(),
        );
        let bytes = encoded_record(
            &carrier,
            &transcript_id,
            RecordDirection::InitiatorToResponder,
            1,
            &env,
        )
        .await;
        assert_eq!(u64::from_be_bytes(bytes[33..41].try_into().unwrap()), 1);

        let mut input = Cursor::new(bytes);
        let received = read_record(
            &mut input,
            &carrier.verifying_key(),
            &transcript_id,
            RecordDirection::InitiatorToResponder,
            1,
        )
        .await
        .expect("outer carrier and independent inner signer are both valid");
        assert_eq!(received, env);
        assert_ne!(received.sender_agent_fp(), carrier.fingerprint());

        let inbox = Inbox::new();
        let error = inbox
            .on_envelope(
                received,
                DeliveryProvenance::Direct {
                    carrier: AuthenticatedPeer::new(user.fingerprint(), carrier.fingerprint()),
                },
                user.fingerprint(),
                receiver.fingerprint(),
            )
            .await
            .expect_err("the bus, not session framing, rejects carrier/signer mismatch");
        assert!(matches!(error, BusError::CarrierAgentMismatch { .. }));
    }

    #[tokio::test]
    async fn records_reject_cross_session_direction_counter_and_byte_tampering() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let (first_alice, first_bob) = authenticated_pair(alice.clone(), bob.clone()).await;
        let session_id = first_alice.transcript_id();
        assert_eq!(session_id, first_bob.transcript_id());
        drop((first_alice, first_bob));
        let (second_alice, second_bob) = authenticated_pair(alice.clone(), bob.clone()).await;
        let second_session_id = second_alice.transcript_id();
        assert_eq!(second_session_id, second_bob.transcript_id());
        assert_ne!(session_id, second_session_id);
        drop((second_alice, second_bob));
        let env = envelope(&alice, bob.fingerprint(), 1, b"body".to_vec());
        let original = encoded_record(
            &alice,
            &session_id,
            RecordDirection::InitiatorToResponder,
            1,
            &env,
        )
        .await;

        let mut input = Cursor::new(original.clone());
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &second_session_id,
                RecordDirection::InitiatorToResponder,
                1
            )
            .await,
            Err(SessionError::RecordSessionMismatch)
        ));
        let mut input = Cursor::new(original.clone());
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::ResponderToInitiator,
                1
            )
            .await,
            Err(SessionError::RecordDirectionMismatch)
        ));
        let mut input = Cursor::new(original.clone());
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::InitiatorToResponder,
                2
            )
            .await,
            Err(SessionError::RecordCounterMismatch {
                expected: 2,
                actual: 1
            })
        ));

        let mut changed_envelope = original.clone();
        changed_envelope[RECORD_HEADER_BYTES + 1] ^= 1;
        let mut input = Cursor::new(changed_envelope);
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::InitiatorToResponder,
                1
            )
            .await,
            Err(SessionError::BadRecordSignature)
        ));
        let mut changed_signature = original;
        let last = changed_signature.len() - 1;
        changed_signature[last] ^= 1;
        let mut input = Cursor::new(changed_signature);
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::InitiatorToResponder,
                1
            )
            .await,
            Err(SessionError::BadRecordSignature)
        ));
    }

    #[tokio::test]
    async fn records_reject_replay_malformed_oversize_and_truncation() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let session_id = [50; 32];
        let env = envelope(&alice, bob.fingerprint(), 1, b"body".to_vec());
        let record = encoded_record(
            &alice,
            &session_id,
            RecordDirection::InitiatorToResponder,
            1,
            &env,
        )
        .await;
        let mut replayed = record.clone();
        replayed.extend_from_slice(&record);
        let mut input = Cursor::new(replayed);
        read_record(
            &mut input,
            &alice.verifying_key(),
            &session_id,
            RecordDirection::InitiatorToResponder,
            1,
        )
        .await
        .expect("first record");
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::InitiatorToResponder,
                2
            )
            .await,
            Err(SessionError::RecordCounterMismatch {
                expected: 2,
                actual: 1
            })
        ));

        let malformed = encoded_raw_record(
            &alice,
            &session_id,
            RecordDirection::InitiatorToResponder,
            1,
            b"not-json",
        );
        let mut input = Cursor::new(malformed);
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::InitiatorToResponder,
                1
            )
            .await,
            Err(SessionError::BadEnvelope(_))
        ));

        let mut oversized = Vec::new();
        oversized.extend_from_slice(&session_id);
        oversized.push(RecordDirection::InitiatorToResponder.as_byte());
        oversized.extend_from_slice(&1u64.to_be_bytes());
        oversized.extend_from_slice(&(MAX_SESSION_ENVELOPE_BYTES + 1).to_be_bytes());
        let mut input = Cursor::new(oversized);
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::InitiatorToResponder,
                1
            )
            .await,
            Err(SessionError::FrameTooLarge {
                kind: "envelope",
                ..
            })
        ));

        let mut truncated = record;
        truncated.pop();
        let mut input = Cursor::new(truncated);
        assert!(matches!(
            read_record(
                &mut input,
                &alice.verifying_key(),
                &session_id,
                RecordDirection::InitiatorToResponder,
                1
            )
            .await,
            Err(SessionError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn cancelling_partial_writes_poisons_unsplit_and_split_writers() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let large = envelope(&alice, bob.fingerprint(), 70, vec![0; 4096]);
        let next = envelope(&alice, bob.fingerprint(), 71, b"must-not-send".to_vec());

        let (mut alice_session, mut bob_session) = authenticated_pair_with(
            alice.clone(),
            bob.clone(),
            SessionParameters::default(),
            roomy_timeouts(),
            64,
        )
        .await;
        {
            let mut operation = Box::pin(alice_session.send_envelope(&large));
            poll_once_pending(operation.as_mut()).await;
        }
        assert!(alice_session.send_poisoned);
        assert_eq!(alice_session.send_counter, 0);
        let mut partial = [0u8; 64];
        let partial_len = bob_session
            .reader
            .read(&mut partial)
            .await
            .expect("read partially emitted record");
        assert!(partial_len > 0);
        assert!(partial_len < serde_json::to_vec(&large).unwrap().len());
        assert!(matches!(
            alice_session.send_envelope(&next).await,
            Err(SessionError::Poisoned)
        ));

        let (alice_session, bob_session) = authenticated_pair_with(
            alice.clone(),
            bob,
            SessionParameters::default(),
            roomy_timeouts(),
            64,
        )
        .await;
        let (_alice_reader, mut alice_writer) = alice_session.into_split();
        let (mut bob_reader, _bob_writer) = bob_session.into_split();
        {
            let mut operation = Box::pin(alice_writer.send_envelope(&large));
            poll_once_pending(operation.as_mut()).await;
        }
        assert!(alice_writer.poisoned);
        assert_eq!(alice_writer.send_counter, 0);
        let partial_len = bob_reader
            .reader
            .read(&mut partial)
            .await
            .expect("read partially emitted split record");
        assert!(partial_len > 0);
        assert!(partial_len < serde_json::to_vec(&large).unwrap().len());
        assert!(matches!(
            alice_writer.send_envelope(&next).await,
            Err(SessionError::Poisoned)
        ));
    }

    #[tokio::test]
    async fn cancelling_partial_reads_poisons_unsplit_and_split_readers() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let env = envelope(&alice, bob.fingerprint(), 72, vec![0; 4096]);

        let (mut alice_session, mut bob_session) = authenticated_pair_with(
            alice.clone(),
            bob.clone(),
            SessionParameters::default(),
            roomy_timeouts(),
            64,
        )
        .await;
        let record = encoded_record(
            &alice,
            &alice_session.transcript_id,
            RecordDirection::InitiatorToResponder,
            1,
            &env,
        )
        .await;
        let partial_len = RECORD_HEADER_BYTES + 8;
        alice_session
            .writer
            .write_all(&record[..partial_len])
            .await
            .expect("write partial record");
        {
            let mut operation = Box::pin(bob_session.recv_envelope());
            poll_once_pending(operation.as_mut()).await;
        }
        assert!(bob_session.receive_poisoned);
        assert_eq!(bob_session.receive_counter, 0);
        assert!(matches!(
            bob_session.recv_envelope().await,
            Err(SessionError::Poisoned)
        ));

        let (alice_session, bob_session) = authenticated_pair_with(
            alice.clone(),
            bob,
            SessionParameters::default(),
            roomy_timeouts(),
            64,
        )
        .await;
        let (_alice_reader, mut alice_writer) = alice_session.into_split();
        let (mut bob_reader, _bob_writer) = bob_session.into_split();
        let record = encoded_record(
            &alice,
            &alice_writer.transcript_id,
            RecordDirection::InitiatorToResponder,
            1,
            &env,
        )
        .await;
        alice_writer
            .writer
            .write_all(&record[..partial_len])
            .await
            .expect("write partial split record");
        {
            let mut operation = Box::pin(bob_reader.recv_envelope());
            poll_once_pending(operation.as_mut()).await;
        }
        assert!(bob_reader.poisoned);
        assert_eq!(bob_reader.receive_counter, 0);
        assert!(matches!(
            bob_reader.recv_envelope().await,
            Err(SessionError::Poisoned)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn record_read_and_write_stalls_timeout_and_poison_the_half() {
        let user = UserKey::generate();
        let alice = agent(&user, "alice");
        let bob = agent(&user, "bob");
        let (alice_session, bob_session) = authenticated_pair(alice.clone(), bob.clone()).await;
        let (mut alice_reader, _alice_writer) = alice_session.into_split();
        let (_bob_reader, _bob_writer) = bob_session.into_split();
        assert!(matches!(
            alice_reader.recv_envelope().await,
            Err(SessionError::Timeout {
                phase: "mesh session record read",
                ..
            })
        ));
        assert!(matches!(
            alice_reader.recv_envelope().await,
            Err(SessionError::Poisoned)
        ));

        let (alice_session, bob_session) = authenticated_pair(alice.clone(), bob.clone()).await;
        let (_alice_reader, mut alice_writer) = alice_session.into_split();
        let (_bob_reader, _bob_writer) = bob_session.into_split();
        let large = envelope(&alice, bob.fingerprint(), 2, vec![0; 4096]);
        assert!(matches!(
            alice_writer.send_envelope(&large).await,
            Err(SessionError::Timeout {
                phase: "mesh session record write",
                ..
            })
        ));
        assert!(matches!(
            alice_writer.send_envelope(&large).await,
            Err(SessionError::Poisoned)
        ));
    }

    /// A user with a persisted revocation log in a temp dir.
    struct LogFixture {
        user: UserKey,
        dir: tempfile::TempDir,
    }

    impl LogFixture {
        fn new() -> Self {
            let f = Self {
                user: UserKey::generate(),
                dir: tempfile::tempdir().unwrap(),
            };
            let log = agent_mesh_protocol::RevocationLog::genesis(&f.user).unwrap();
            f.write(&log);
            f
        }

        fn path(&self) -> std::path::PathBuf {
            self.dir.path().join("revocation.json")
        }

        fn write(&self, log: &agent_mesh_protocol::RevocationLog) {
            std::fs::write(self.path(), serde_json::to_vec(log).unwrap()).unwrap();
        }

        fn guard(&self) -> RevocationGuard {
            RevocationGuard::open(self.path(), self.user.fingerprint()).unwrap()
        }

        fn bump(&self, current: u64) {
            let mut log: agent_mesh_protocol::RevocationLog =
                serde_json::from_slice(&std::fs::read(self.path()).unwrap()).unwrap();
            log.append(
                &self.user,
                agent_mesh_protocol::RevocationEntry::Generation { current },
            )
            .unwrap();
            self.write(&log);
        }

        fn revoke(&self, agent: &AgentKey) {
            let mut log: agent_mesh_protocol::RevocationLog =
                serde_json::from_slice(&std::fs::read(self.path()).unwrap()).unwrap();
            let agent = agent.fingerprint();
            log.append(
                &self.user,
                agent_mesh_protocol::RevocationEntry::Revoke { agent },
            )
            .unwrap();
            self.write(&log);
        }
    }

    /// Both ends authenticate over a pipe, each against its own guard.
    async fn pair_with_guards(
        initiator: Arc<AgentKey>,
        responder: Arc<AgentKey>,
        initiator_guard: RevocationGuard,
        responder_guard: RevocationGuard,
    ) -> (
        Result<TestSession, SessionError>,
        Result<TestSession, SessionError>,
    ) {
        let (left, right) = tokio::io::duplex(64 * 1024);
        let (left_reader, left_writer) = tokio::io::split(left);
        let (right_reader, right_writer) = tokio::io::split(right);
        let left = UnauthenticatedMeshSession::initiator(
            left_reader,
            left_writer,
            initiator,
            responder.fingerprint(),
            SessionParameters::default(),
            roomy_timeouts(),
            initiator_guard,
        );
        let right = UnauthenticatedMeshSession::responder(
            right_reader,
            right_writer,
            responder,
            SessionParameters::default(),
            roomy_timeouts(),
            responder_guard,
        );
        tokio::join!(left.authenticate(), right.authenticate())
    }

    /// A revoked agent cannot complete the SSH session handshake, whichever
    /// end it sits at: the end holding the log refuses it by name.
    #[tokio::test]
    async fn a_revoked_agent_cannot_complete_the_session_handshake() {
        let f = LogFixture::new();
        let (alice, bob) = (agent(&f.user, "alice"), agent(&f.user, "bob"));
        f.revoke(&alice);
        let (_, responder) = pair_with_guards(
            alice.clone(),
            bob.clone(),
            RevocationGuard::in_memory(&f.user),
            f.guard(),
        )
        .await;
        assert!(
            matches!(responder, Err(SessionError::PeerRevoked(_))),
            "responder must refuse a revoked initiator: {:?}",
            responder.map(|_| ())
        );
        let f = LogFixture::new();
        let (alice, bob) = (agent(&f.user, "alice"), agent(&f.user, "bob"));
        f.revoke(&bob);
        let (initiator, _) =
            pair_with_guards(alice, bob, f.guard(), RevocationGuard::in_memory(&f.user)).await;
        assert!(
            matches!(initiator, Err(SessionError::PeerRevoked(_))),
            "initiator must refuse a revoked responder: {:?}",
            initiator.map(|_| ())
        );
    }

    /// With no usable log the handshake fails closed.
    #[tokio::test]
    async fn a_missing_log_cannot_authenticate_anyone() {
        let f = LogFixture::new();
        let (alice, bob) = (agent(&f.user, "alice"), agent(&f.user, "bob"));
        let guard = f.guard();
        std::fs::write(f.path(), b"not a log").unwrap();
        let (left, _) =
            pair_with_guards(alice, bob, guard, RevocationGuard::in_memory(&f.user)).await;
        assert!(
            matches!(left, Err(SessionError::RevocationUnavailable(_))),
            "{:?}",
            left.map(|_| ())
        );
    }

    /// A revocation the log learns mid-session ends it before the revoked
    /// peer's next envelope is returned for dispatch, and the half stays down.
    #[tokio::test]
    async fn revoking_a_connected_peer_ends_its_session_before_its_next_envelope() {
        let f = LogFixture::new();
        let (alice, bob) = (agent(&f.user, "alice"), agent(&f.user, "bob"));
        let (alice_session, bob_session) = pair_with_guards(
            alice.clone(),
            bob.clone(),
            RevocationGuard::in_memory(&f.user),
            f.guard(),
        )
        .await;
        let (mut alice_session, mut bob_session) = (alice_session.unwrap(), bob_session.unwrap());

        alice_session
            .send_envelope(&envelope(&alice, bob.fingerprint(), 0, b"one".to_vec()))
            .await
            .unwrap();
        let first = bob_session.recv_envelope().await.unwrap();
        assert_eq!(first.payload.as_ref(), b"one");

        f.revoke(&alice);
        alice_session
            .send_envelope(&envelope(&alice, bob.fingerprint(), 1, b"two".to_vec()))
            .await
            .unwrap();
        let second = bob_session.recv_envelope().await;
        assert!(
            matches!(second, Err(SessionError::PeerRevoked(_))),
            "the envelope of a revoked peer must not be dispatched: {:?}",
            second.map(|e| e.payload)
        );
        assert!(matches!(
            bob_session.recv_envelope().await,
            Err(SessionError::Poisoned)
        ));
        let reply = envelope(&bob, alice.fingerprint(), 0, b"late".to_vec());
        assert!(
            bob_session.send_envelope(&reply).await.is_err(),
            "nothing is sent to a revoked peer"
        );
    }
}
