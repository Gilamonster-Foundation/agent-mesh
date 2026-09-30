//! [`SignedEnvelope`] framing over an iroh bidi stream.
//!
//! Same wire shape as [`crate::handshake`]: a 4-byte BE length prefix
//! followed by the JSON-encoded envelope. Envelopes are verified
//! end-to-end on receipt — cert chain, payload CID, and agent
//! signature all checked before the bytes leave this module.
//!
//! The framing is generic over tokio's byte-stream traits: an iroh
//! [`SendStream`](iroh::endpoint::SendStream) /
//! [`RecvStream`](iroh::endpoint::RecvStream) in production, an in-memory
//! pipe in tests.

use crate::error::{Result, TransportError};
use agent_mesh_protocol::SignedEnvelope;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Max accepted envelope size. Envelopes ship arbitrary payloads, so
/// the cap is generous — but bounded, to keep a malformed length
/// prefix from forcing the receiver to allocate gigabytes.
pub const MAX_ENVELOPE_BYTES: u32 = 16 * 1024 * 1024;

/// Send a [`SignedEnvelope`] over `send` with a length prefix.
///
/// The envelope itself is opaque to this function — sign/encode is
/// the caller's job, and verify is the receiver's. Payload framing
/// is symmetric with [`recv_envelope`].
pub async fn send_envelope<W: AsyncWrite + Unpin>(
    send: &mut W,
    env: &SignedEnvelope,
) -> Result<()> {
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
pub async fn recv_envelope<R: AsyncRead + Unpin>(recv: &mut R) -> Result<SignedEnvelope> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::Iroh(format!("read len: {e}")))?;
    let mut buf = vec![0u8; body_len(len_buf)?];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| TransportError::Iroh(format!("read body: {e}")))?;
    decode_envelope(&buf)
}

/// The body length a 4-byte prefix announces, refused past
/// [`MAX_ENVELOPE_BYTES`] before anything is allocated for it.
fn body_len(prefix: [u8; 4]) -> Result<usize> {
    let len = u32::from_be_bytes(prefix);
    if len > MAX_ENVELOPE_BYTES {
        return Err(TransportError::BadEnvelope(format!(
            "incoming envelope {len} bytes exceeds MAX_ENVELOPE_BYTES={MAX_ENVELOPE_BYTES}"
        )));
    }
    Ok(len as usize)
}

fn decode_envelope(body: &[u8]) -> Result<SignedEnvelope> {
    let env: SignedEnvelope = serde_json::from_slice(body)
        .map_err(|e| TransportError::BadEnvelope(format!("deserialize: {e}")))?;
    env.verify()
        .map_err(|e| TransportError::BadEnvelope(e.to_string()))?;
    Ok(env)
}

/// A stream of envelopes read off `R`, for a stream that carries more than
/// one.
///
/// [`Self::next`] is **cancel-safe**: bytes already read stay buffered when
/// its future is dropped, so it can sit in a `select!` beside other work
/// without tearing a frame. [`recv_envelope`] reads exactly one envelope and
/// no further, so it can hand the rest of a stream to a reader like this.
pub struct EnvelopeReader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> EnvelopeReader<R> {
    /// Read envelopes from `inner`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    /// The next verified envelope, or `None` when the stream ends cleanly
    /// between envelopes. A stream that ends partway through one is
    /// [`TransportError::PeerClosed`].
    ///
    /// # Errors
    /// A read failure, a truncated or oversized frame, or an envelope that
    /// does not decode or verify.
    pub async fn next(&mut self) -> Result<Option<SignedEnvelope>> {
        loop {
            // `first_chunk` would say this, but postdates the 1.75 MSRV.
            if let Ok(prefix) = <[u8; 4]>::try_from(self.buf.get(..4).unwrap_or_default()) {
                let end = 4 + body_len(prefix)?;
                if self.buf.len() >= end {
                    let env = decode_envelope(&self.buf[4..end]);
                    self.buf.drain(..end);
                    return env.map(Some);
                }
                self.buf.reserve(end - self.buf.len());
            }
            let read = self
                .inner
                .read_buf(&mut self.buf)
                .await
                .map_err(|e| TransportError::Iroh(format!("read: {e}")))?;
            if read == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(TransportError::PeerClosed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, Fingerprint, Recipient, UserKey};

    fn fixture_envelope() -> SignedEnvelope {
        envelope_of(b"hello".to_vec())
    }

    fn envelope_of(payload: Vec<u8>) -> SignedEnvelope {
        let user = UserKey::generate();
        let agent = AgentKey::issue(
            &user,
            AgentMetadata {
                role: "worker".into(),
                host: "test-host".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        );
        SignedEnvelope::new(
            &agent,
            Recipient::Direct {
                agent_fp: Fingerprint::of_bytes(b"recipient"),
            },
            1,
            payload,
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

    /// Frames split across reads, a dropped `next` mid-frame, a clean end, and
    /// a cut one: the reader keeps every byte it has taken until a whole
    /// envelope is there.
    #[tokio::test]
    async fn reader_is_cancel_safe_and_tells_a_clean_end_from_a_cut_one() {
        let env = fixture_envelope();
        let (mut a, b) = tokio::io::duplex(1 << 16);
        let mut reader = EnvelopeReader::new(b);
        send_envelope(&mut a, &env).await.unwrap();
        let bytes = serde_json::to_vec(&env).unwrap();
        let prefix = u32::try_from(bytes.len()).unwrap().to_be_bytes();
        a.write_all(&prefix).await.unwrap();
        a.write_all(&bytes[..10]).await.unwrap();

        assert_eq!(reader.next().await.unwrap(), Some(env.clone()));
        let stalled = tokio::time::timeout(std::time::Duration::from_millis(50), reader.next());
        assert!(stalled.await.is_err(), "half a frame is not an envelope");
        a.write_all(&bytes[10..]).await.unwrap();
        assert_eq!(reader.next().await.unwrap(), Some(env.clone()));
        drop(a);
        assert_eq!(reader.next().await.unwrap(), None, "clean end");

        let (mut a, b) = tokio::io::duplex(1 << 16);
        a.write_all(&prefix).await.unwrap();
        a.write_all(&bytes[..10]).await.unwrap();
        drop(a);
        assert!(matches!(
            EnvelopeReader::new(b).next().await,
            Err(TransportError::PeerClosed)
        ));
    }

    #[tokio::test]
    async fn an_oversized_prefix_is_refused_before_its_body_arrives() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_ENVELOPE_BYTES + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            recv_envelope(&mut b).await,
            Err(TransportError::BadEnvelope(_))
        ));
        a.write_all(&(MAX_ENVELOPE_BYTES + 1).to_be_bytes())
            .await
            .unwrap();
        let mut reader = EnvelopeReader::new(b);
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), reader.next());
        assert!(matches!(
            read.await,
            Ok(Err(TransportError::BadEnvelope(_)))
        ));
    }

    /// Once a large envelope has grown the buffer, one read can take in
    /// several small ones; each is still delivered, none dropped.
    #[tokio::test]
    async fn envelopes_read_together_are_all_delivered() {
        let big = envelope_of(vec![9; 8192]);
        let (small, other) = (fixture_envelope(), envelope_of(b"second".to_vec()));
        let (mut a, b) = tokio::io::duplex(1 << 20);
        let mut reader = EnvelopeReader::new(b);
        send_envelope(&mut a, &big).await.unwrap();
        assert_eq!(reader.next().await.unwrap(), Some(big));
        send_envelope(&mut a, &small).await.unwrap();
        send_envelope(&mut a, &other).await.unwrap();
        drop(a);
        assert_eq!(reader.next().await.unwrap(), Some(small));
        assert_eq!(reader.next().await.unwrap(), Some(other));
        assert_eq!(reader.next().await.unwrap(), None);
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
