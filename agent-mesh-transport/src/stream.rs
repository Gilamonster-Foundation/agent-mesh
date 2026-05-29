//! [`SignedEnvelope`] framing over an iroh bidi stream.
//!
//! Same wire shape as [`crate::handshake`]: a 4-byte BE length prefix
//! followed by the JSON-encoded envelope. Envelopes are verified
//! end-to-end on receipt — cert chain, payload CID, and agent
//! signature all checked before the bytes leave this module.

use crate::error::{Result, TransportError};
use agent_mesh_core::SignedEnvelope;
use iroh::endpoint::{RecvStream, SendStream};

/// Max accepted envelope size. Envelopes ship arbitrary payloads, so
/// the cap is generous — but bounded, to keep a malformed length
/// prefix from forcing the receiver to allocate gigabytes.
pub const MAX_ENVELOPE_BYTES: u32 = 16 * 1024 * 1024;

/// Send a [`SignedEnvelope`] over `send` with a length prefix.
///
/// The envelope itself is opaque to this function — sign/encode is
/// the caller's job, and verify is the receiver's. Payload framing
/// is symmetric with [`recv_envelope`].
pub async fn send_envelope(send: &mut SendStream, env: &SignedEnvelope) -> Result<()> {
    let bytes = serde_json::to_vec(env)
        .map_err(|e| TransportError::BadEnvelope(format!("serialize: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| TransportError::BadEnvelope("envelope too large to encode".into()))?;
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::BadEnvelope(format!(
            "envelope {len} bytes exceeds MAX_ENVELOPE_BYTES={MAX_ENVELOPE_BYTES}"
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

/// Read a [`SignedEnvelope`] from `recv` and verify it before
/// returning.
///
/// Verification covers:
///
/// 1. cert chain (user signature over agent metadata)
/// 2. payload CID matches `BLAKE3(payload)`
/// 3. agent signature over `(recipient, nonce, sequence, payload_cid)`
///
/// A failing envelope yields [`TransportError::BadEnvelope`] without
/// surfacing the verifier internals.
pub async fn recv_envelope(recv: &mut RecvStream) -> Result<SignedEnvelope> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::Iroh(format!("read len: {e}")))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::BadEnvelope(format!(
            "incoming envelope {len} bytes exceeds MAX_ENVELOPE_BYTES={MAX_ENVELOPE_BYTES}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| TransportError::Iroh(format!("read body: {e}")))?;
    let env: SignedEnvelope = serde_json::from_slice(&buf)
        .map_err(|e| TransportError::BadEnvelope(format!("deserialize: {e}")))?;
    env.verify()
        .map_err(|e| TransportError::BadEnvelope(e.to_string()))?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::{AgentKey, AgentMetadata, Fingerprint, Recipient, UserKey};

    fn fixture_envelope() -> SignedEnvelope {
        let user = UserKey::generate();
        let agent = AgentKey::issue(
            &user,
            AgentMetadata {
                role: "worker".into(),
                host: "test-host".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T00:00:00Z".into(),
                expires_at: None,
            },
        );
        SignedEnvelope::new(
            &agent,
            Recipient::Direct {
                agent_fp: Fingerprint::of_bytes(b"recipient"),
            },
            1,
            b"hello".to_vec(),
        )
    }

    #[test]
    fn envelope_serde_roundtrip_via_json() {
        // The framing module relies on `serde_json::{to_vec,from_slice}`
        // being lossless for SignedEnvelope. Anchor that assumption
        // here so a future codec swap notices.
        let env = fixture_envelope();
        let bytes = serde_json::to_vec(&env).unwrap();
        let back: SignedEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, env);
        back.verify().unwrap();
    }

    // 16 MiB is enough for any realistic payload while still
    // bounding allocation under a malformed length prefix. Anchor
    // the bounds as a const assertion so a future tweak to the cap
    // notices.
    const _: () = {
        assert!(MAX_ENVELOPE_BYTES >= 1024 * 1024);
        assert!(MAX_ENVELOPE_BYTES <= 64 * 1024 * 1024);
    };
}
