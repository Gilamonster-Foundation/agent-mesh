//! ALPN identifier for the agent-mesh QUIC protocol.
//!
//! ALPN ("Application-Layer Protocol Negotiation") is negotiated as
//! part of the QUIC handshake. By advertising a single, versioned
//! string we guarantee that peers running an incompatible protocol
//! version fail closed at the TLS layer instead of attempting a
//! malformed app-level handshake.

/// ALPN identifier for agent-mesh v1.
///
/// Bumping this value is a breaking change: peers using the older
/// ALPN will be unable to negotiate a connection.
pub const ALPN: &[u8] = b"agent-mesh/v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_stable_v1_token() {
        // Pin the exact bytes — bumping this value is a wire-breaking
        // change and should require an explicit test update.
        assert_eq!(ALPN, b"agent-mesh/v1");
    }

    #[test]
    fn alpn_is_ascii_and_under_255_bytes() {
        // ALPN tokens are length-prefixed by a single byte in the
        // TLS encoding; keep them comfortably under that limit.
        assert!(ALPN.len() < 255);
        assert!(ALPN.iter().all(u8::is_ascii));
    }
}
