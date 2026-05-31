//! App-level cert-chain handshake on top of QUIC + ALPN.
//!
//! ALPN already guarantees the peer is speaking `agent-mesh/v1`.
//! What QUIC alone doesn't enforce is the **auto-team rule**: two
//! agents trust each other iff their cert chains chain to the same
//! `user_pubkey`. The handshake is the first thing both sides do
//! on a freshly-opened bidi stream and is fail-closed — any error
//! results in the connection being torn down before any payload
//! traffic is exchanged.
//!
//! Wire format (length-prefixed JSON, repeated):
//!
//! ```text
//! [4-byte BE length][JSON bytes]
//! ```
//!
//! Frames exchanged:
//!
//! 1. dialer  → acceptor:  `HelloMsg { cert_chain }`
//! 2. acceptor: verifies cert, checks `user_fp == our_user_fp`
//!    - if NO  → sends `RejectMsg { reason }`, closes; both sides err
//!    - if YES → sends `HelloMsg { cert_chain: ours }`
//! 3. dialer  : verifies acceptor's cert + same-user
//!    - if NO  → closes, dialer errs; acceptor sees stream EOF
//!    - if YES → handshake complete; both sides hold each other's
//!      verified [`CertChain`]
//!
//! After step 3 the stream is "open" — callers move on to the
//! envelope framing module.

use crate::error::{Result, TransportError};
use agent_mesh_protocol::CertChain;
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

/// Max accepted frame size on the handshake stream. Cert chains are
/// small (a few hundred bytes); anything larger is a bug or attack.
const MAX_FRAME_BYTES: u32 = 16 * 1024;

/// "Hello" frame: my cert chain, please verify and accept me.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloMsg {
    /// The sender's cert chain — proves which user signed off on this
    /// agent and what role/host/capabilities they claim.
    pub cert_chain: CertChain,
}

/// "Reject" frame: handshake refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectMsg {
    /// Machine-readable reason. Currently only `"DifferentUser"` and
    /// `"BadCertChain"` are produced; future versions may add more.
    pub reason: String,
}

/// Drive the handshake to completion and return the verified peer
/// cert chain.
///
/// * `our_cert` — our agent's cert chain (cheap to clone).
/// * `send` / `recv` — the bidi stream just opened over QUIC.
/// * `is_dialer` — whether we initiated the connection. The dialer
///   sends first; the acceptor sends second (or rejects).
///
/// On success returns the peer's verified `CertChain`. On failure
/// returns a `TransportError` whose variant tells callers whether
/// the failure was protocol (`Handshake`), trust (`DifferentUser`,
/// `BadCertChain`), or network (`Io`, `Iroh`).
pub async fn do_handshake(
    our_cert: &CertChain,
    send: &mut SendStream,
    recv: &mut RecvStream,
    is_dialer: bool,
) -> Result<CertChain> {
    let our_user_fp = our_cert.user_fingerprint();
    let hello = HelloMsg {
        cert_chain: our_cert.clone(),
    };

    if is_dialer {
        write_frame(send, &hello).await?;
        let peer_cert = read_peer_hello_or_reject(recv).await?;
        ensure_trustable(&peer_cert, &our_user_fp)?;
        Ok(peer_cert)
    } else {
        // Acceptor: read first, decide, respond.
        let peer_hello: HelloMsg = read_frame(recv).await?;
        let peer_cert = peer_hello.cert_chain;
        match ensure_trustable(&peer_cert, &our_user_fp) {
            Ok(()) => {
                write_frame(send, &hello).await?;
                Ok(peer_cert)
            }
            Err(e) => {
                let reason = match &e {
                    TransportError::DifferentUser { .. } => "DifferentUser",
                    TransportError::BadCertChain(_) => "BadCertChain",
                    _ => "Other",
                };
                let _ = write_frame(
                    send,
                    &RejectMsg {
                        reason: reason.to_string(),
                    },
                )
                .await;
                // Flush + half-close the send side so the dialer's
                // read sees the Reject frame before the connection
                // tears down. Without this, dropping the stream too
                // quickly can lose the in-flight bytes.
                let _ = send.finish();
                let _ = send.stopped().await;
                Err(e)
            }
        }
    }
}

/// Verify the peer's cert chain and enforce the auto-team rule.
fn ensure_trustable(
    peer_cert: &CertChain,
    our_user_fp: &agent_mesh_protocol::Fingerprint,
) -> Result<()> {
    peer_cert
        .verify()
        .map_err(|e| TransportError::BadCertChain(e.to_string()))?;
    let peer_user_fp = peer_cert.user_fingerprint();
    if &peer_user_fp != our_user_fp {
        return Err(TransportError::DifferentUser {
            peer_user: peer_user_fp.hex(),
            our_user: our_user_fp.hex(),
        });
    }
    Ok(())
}

/// Read the dialer-side response — either the peer's Hello (ok) or a
/// RejectMsg (translate to a clean error).
async fn read_peer_hello_or_reject(recv: &mut RecvStream) -> Result<CertChain> {
    let bytes = read_frame_raw(recv).await?;
    // Try Hello first; on parse failure, try Reject.
    if let Ok(hello) = serde_json::from_slice::<HelloMsg>(&bytes) {
        return Ok(hello.cert_chain);
    }
    if let Ok(reject) = serde_json::from_slice::<RejectMsg>(&bytes) {
        return Err(match reject.reason.as_str() {
            "DifferentUser" => TransportError::DifferentUser {
                peer_user: "<unknown>".into(),
                our_user: "<self>".into(),
            },
            "BadCertChain" => TransportError::BadCertChain("peer rejected our cert".into()),
            other => TransportError::Handshake(format!("peer rejected: {other}")),
        });
    }
    Err(TransportError::Handshake(
        "unrecognized handshake frame".into(),
    ))
}

/// Serialize `msg` as JSON and write `[4-byte BE length][bytes]`.
async fn write_frame<T: Serialize>(send: &mut SendStream, msg: &T) -> Result<()> {
    let bytes = serde_json::to_vec(msg)
        .map_err(|e| TransportError::Handshake(format!("serialize: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| TransportError::Handshake("frame too large to encode".into()))?;
    if len > MAX_FRAME_BYTES {
        return Err(TransportError::Handshake(format!(
            "frame {len} bytes exceeds MAX_FRAME_BYTES={MAX_FRAME_BYTES}"
        )));
    }
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| TransportError::Iroh(format!("write len: {e}")))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| TransportError::Iroh(format!("write body: {e}")))?;
    Ok(())
}

/// Read `[4-byte BE length][bytes]` and deserialize.
async fn read_frame<T: for<'de> Deserialize<'de>>(recv: &mut RecvStream) -> Result<T> {
    let bytes = read_frame_raw(recv).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| TransportError::Handshake(format!("deserialize: {e}")))
}

/// Read `[4-byte BE length][bytes]` and return the raw payload.
async fn read_frame_raw(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::Iroh(format!("read len: {e}")))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(TransportError::Handshake(format!(
            "incoming frame {len} bytes exceeds MAX_FRAME_BYTES={MAX_FRAME_BYTES}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| TransportError::Iroh(format!("read body: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};

    fn fixture_cert(user: &UserKey, role: &str) -> CertChain {
        AgentKey::issue(
            user,
            AgentMetadata {
                role: role.into(),
                host: "test-host".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        )
        .cert()
        .clone()
    }

    #[test]
    fn ensure_trustable_accepts_same_user() {
        let user = UserKey::generate();
        let cert = fixture_cert(&user, "worker");
        let fp = user.fingerprint();
        assert!(ensure_trustable(&cert, &fp).is_ok());
    }

    #[test]
    fn ensure_trustable_rejects_different_user() {
        let user_a = UserKey::generate();
        let user_b = UserKey::generate();
        let cert = fixture_cert(&user_a, "worker");
        let err = ensure_trustable(&cert, &user_b.fingerprint()).unwrap_err();
        match err {
            TransportError::DifferentUser { .. } => {}
            other => panic!("expected DifferentUser, got {other:?}"),
        }
    }

    #[test]
    fn ensure_trustable_rejects_tampered_cert() {
        let user = UserKey::generate();
        let mut cert = fixture_cert(&user, "worker");
        cert.metadata.role = "tampered".into();
        let err = ensure_trustable(&cert, &user.fingerprint()).unwrap_err();
        match err {
            TransportError::BadCertChain(_) => {}
            other => panic!("expected BadCertChain, got {other:?}"),
        }
    }

    #[test]
    fn hello_and_reject_serde_roundtrip() {
        let user = UserKey::generate();
        let cert = fixture_cert(&user, "worker");
        let hello = HelloMsg {
            cert_chain: cert.clone(),
        };
        let json = serde_json::to_vec(&hello).unwrap();
        let back: HelloMsg = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.cert_chain, cert);

        let reject = RejectMsg {
            reason: "DifferentUser".into(),
        };
        let json = serde_json::to_vec(&reject).unwrap();
        let back: RejectMsg = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.reason, "DifferentUser");
    }
}
