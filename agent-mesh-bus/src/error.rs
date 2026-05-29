//! Crate-wide error type for `agent-mesh-bus`.
//!
//! The bus composes failures from the underlying transport (handshake,
//! envelope verification), the application protocol (correlation lost,
//! handler missing), and replay defense (nonce + sequence). One enum
//! surfaces them so callers can match on intent without dragging
//! transport types into their signatures.

use thiserror::Error;

/// Errors that can arise from the high-level bus API.
#[derive(Debug, Error)]
pub enum BusError {
    /// The bus's accept loop is no longer running — typically because
    /// the endpoint was closed.
    #[error("not running")]
    NotRunning,

    /// No peer has been registered as a subscriber/handler for the
    /// named topic. Returned by `publish` when nobody is listening.
    #[error("no peer for topic {0}")]
    NoSubscriber(String),

    /// A peer fingerprint did not resolve via mDNS (or the resolver
    /// timed out before the announcement arrived).
    #[error("peer not reachable: {0}")]
    Unreachable(String),

    /// An in-flight request exceeded its caller-supplied timeout.
    #[error("request timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// The waiter for an in-flight request was dropped before the
    /// reply arrived. Usually means the bus shut down mid-request.
    #[error("reply correlation lost")]
    LostReply,

    /// An incoming envelope's nonce was already in the cache.
    #[error("replay rejected: nonce already seen")]
    Replay,

    /// An incoming envelope's sequence number was not strictly greater
    /// than the highest seen from this peer.
    #[error("sequence error: peer={peer_fp}, expected {expected}, got {actual}")]
    BadSequence {
        /// Sender's agent fingerprint, hex-encoded for log lines.
        peer_fp: String,
        /// Next sequence number we'd have accepted.
        expected: u64,
        /// Sequence number that arrived instead.
        actual: u64,
    },

    /// Anything bubbling up from the transport layer (handshake, dial,
    /// envelope I/O, auto-team rejection).
    #[error("transport: {0}")]
    Transport(#[from] agent_mesh_transport::TransportError),

    /// Anything bubbling up from agent-mesh-core (cert verify,
    /// envelope decode, etc.).
    #[error("core: {0}")]
    Core(#[from] agent_mesh_core::MeshError),

    /// JSON encode/decode failure on the bus's `BusMessage` framing.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience alias for the crate's `Result` type.
pub type Result<T> = std::result::Result<T, BusError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_renders_useful_message() {
        let e = BusError::Replay;
        assert!(format!("{e}").contains("replay"));
    }

    #[test]
    fn bad_sequence_includes_peer_and_numbers() {
        let e = BusError::BadSequence {
            peer_fp: "abc123".into(),
            expected: 5,
            actual: 3,
        };
        let msg = format!("{e}");
        assert!(msg.contains("abc123"));
        assert!(msg.contains('5'));
        assert!(msg.contains('3'));
    }

    #[test]
    fn timeout_renders_duration() {
        let e = BusError::Timeout(std::time::Duration::from_secs(2));
        assert!(format!("{e}").contains('2'));
    }

    #[test]
    fn transport_error_converts_via_from() {
        let t = agent_mesh_transport::TransportError::Iroh("bind failed".into());
        let e: BusError = t.into();
        assert!(matches!(e, BusError::Transport(_)));
    }

    #[test]
    fn core_error_converts_via_from() {
        let c = agent_mesh_core::MeshError::BadSignature;
        let e: BusError = c.into();
        assert!(matches!(e, BusError::Core(_)));
    }

    #[test]
    fn json_error_converts_via_from() {
        let r: std::result::Result<serde_json::Value, _> = serde_json::from_str("not-json");
        let je = r.unwrap_err();
        let e: BusError = je.into();
        assert!(matches!(e, BusError::Json(_)));
    }
}
