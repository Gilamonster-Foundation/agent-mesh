//! Crate-wide error type for `agent-mesh-transport`.
//!
//! The transport layer composes failures from several distinct sources
//! — iroh's QUIC stack, app-level handshake, envelope verification —
//! and surfaces them as a single enum so callers can match on intent
//! without dragging in iroh types.

use thiserror::Error;

/// Errors that can arise from the transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Anything failing in the underlying iroh / QUIC stack — bind,
    /// connect, accept, stream I/O. Boxed as a string so callers
    /// don't need to depend on iroh's error types.
    #[error("iroh error: {0}")]
    Iroh(String),

    /// The app-level handshake failed before either side could agree
    /// on identity. Distinct from `DifferentUser` (which is a *correct*
    /// auto-team rejection) — this is a malformed or unparseable
    /// handshake frame.
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// The peer presented a valid cert chain that belonged to a
    /// different user than ours. No pact exists to bridge them, so
    /// the connection is refused per the auto-team rule.
    #[error("auto-team check failed: peer user {peer_user} differs from our user {our_user}, no pact exists")]
    DifferentUser {
        /// Peer's user fingerprint (hex).
        peer_user: String,
        /// Our user fingerprint (hex).
        our_user: String,
    },

    /// The peer's cert chain was structurally valid but failed
    /// cryptographic verification (bad user signature, tampered
    /// metadata, etc.).
    #[error("cert chain rejected: {0}")]
    BadCertChain(String),

    /// A received `SignedEnvelope` failed `verify()` — bad signature,
    /// payload CID mismatch, or cert chain issue.
    #[error("envelope rejected: {0}")]
    BadEnvelope(String),

    /// The peer closed the connection mid-exchange.
    #[error("connection closed by peer")]
    PeerClosed,

    /// Raw I/O failure outside the iroh stack (rare — mostly
    /// surfacing during length-prefix reads).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// An error bubbled up from `agent-mesh-core` (cert verify,
    /// envelope decode).
    #[error("core error: {0}")]
    Core(#[from] agent_mesh_core::MeshError),
}

/// Convenience alias for the crate's `Result` type.
pub type Result<T> = std::result::Result<T, TransportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iroh_error_renders_useful_message() {
        let e = TransportError::Iroh("bind failed".into());
        assert!(format!("{e}").contains("bind failed"));
    }

    #[test]
    fn different_user_includes_both_fingerprints() {
        let e = TransportError::DifferentUser {
            peer_user: "abc".into(),
            our_user: "def".into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("abc"));
        assert!(msg.contains("def"));
    }

    #[test]
    fn core_error_converts_via_from() {
        let core_err = agent_mesh_core::MeshError::BadSignature;
        let e: TransportError = core_err.into();
        assert!(matches!(e, TransportError::Core(_)));
    }

    #[test]
    fn io_error_converts_via_from() {
        let io = std::io::Error::other("eof");
        let e: TransportError = io.into();
        assert!(matches!(e, TransportError::Io(_)));
    }
}
