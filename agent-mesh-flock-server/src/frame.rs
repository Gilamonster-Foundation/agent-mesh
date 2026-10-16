//! The frame: the unit of one admission transaction, and the crate's only
//! hand-made byte format.
//!
//! ```text
//! frame  = len:u32be | check:u32be | payload[len]
//! check  = first 4 bytes of blake3(len:u32be || "flock-frame/v1")
//! payload = canonical dag-cbor of `Frame`
//! ```
//!
//! Identity is never minted here. Event, record and certificate ids are
//! content ids from `content-addressable`; the header only lets recovery tell
//! a torn tail (header or payload cut short) from a damaged one (header check
//! fails, or the payload does not decode and verify).

use crate::ServerError;
use agent_mesh_flock::Event;
use agent_mesh_protocol::{AgentKey, Assertion, CertChain};
use content_addressable::canonical::{from_canonical_dagcbor_checked, to_canonical_dagcbor};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use serde::{Deserialize, Serialize};

/// Bytes before the payload.
pub const HEADER_LEN: usize = 8;
const TAG: &[u8] = b"flock-frame/v1";

/// The server-signed admission record's payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRecord {
    /// Contiguous from 1.
    pub index: u64,
    /// The flock epoch the event was verified at.
    pub epoch: u64,
    /// The admitted event node.
    pub event: ContentId,
    /// The certificate chain the event's signature was verified with.
    pub cert: ContentId,
}

/// One admitted event with everything a fresh reader needs to verify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// The event node.
    pub event: MerkleNode<Event>,
    /// The author's detached signature (carries the certificate).
    pub event_sig: Assertion,
    /// `parents: {previous record, or genesis}`.
    pub record: MerkleNode<AdmissionRecord>,
    /// The server's signature over the record's id.
    pub record_sig: Assertion,
}

/// One transaction: the requested event first, then any records it caused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// Admissions in index order.
    pub sealed: Vec<Sealed>,
}

/// The content id of a certificate chain.
///
/// # Errors
/// Encoding failure.
pub fn cert_cid(cert: &CertChain) -> Result<ContentId, ServerError> {
    let bytes = to_canonical_dagcbor(cert).map_err(|e| ServerError::Encoding(e.to_string()))?;
    Ok(ContentId::from_canonical_bytes(&bytes))
}

/// Seal `event` as admission `index` at `epoch`, chained after `prev` (the
/// previous record id, or the genesis id for the first), signed by `server`.
///
/// # Errors
/// Encoding failure.
pub fn seal(
    server: &AgentKey,
    prev: ContentId,
    index: u64,
    epoch: u64,
    event: MerkleNode<Event>,
    event_sig: Assertion,
) -> Result<Sealed, ServerError> {
    let enc = |e: content_addressable::ContentError| ServerError::Encoding(e.to_string());
    let record = MerkleNode::new(
        AdmissionRecord {
            index,
            epoch,
            event: event.content_id().map_err(enc)?,
            cert: cert_cid(event_sig.author())?,
        },
        [prev],
    );
    let record_sig = Assertion::sign(server, &record.content_id().map_err(enc)?);
    Ok(Sealed {
        event,
        event_sig,
        record,
        record_sig,
    })
}

fn check(len: [u8; 4]) -> [u8; 4] {
    let mut h = blake3::Hasher::new();
    h.update(&len);
    h.update(TAG);
    let mut out = [0u8; 4];
    out.copy_from_slice(&h.finalize().as_bytes()[..4]);
    out
}

/// Header plus payload for `frame`.
///
/// # Errors
/// Encoding failure, or a payload over 4 GiB.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, ServerError> {
    let payload = to_canonical_dagcbor(frame).map_err(|e| ServerError::Encoding(e.to_string()))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| ServerError::Encoding("frame too large".into()))?
        .to_be_bytes();
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&len);
    out.extend_from_slice(&check(len));
    out.extend_from_slice(&payload);
    Ok(out)
}

/// What sits at an offset in the log bytes.
#[derive(Debug)]
pub enum Next {
    /// Nothing left.
    End,
    /// An incomplete final frame: the header or payload is cut short.
    Torn,
    /// A whole frame and the offset just after it.
    Frame(Frame, usize),
}

/// Read the frame at `at`.
///
/// # Errors
/// A reason when a complete header fails its check or a complete payload does
/// not decode canonically: committed history is damaged.
pub fn next(bytes: &[u8], at: usize) -> Result<Next, String> {
    let rest = &bytes[at..];
    if rest.is_empty() {
        return Ok(Next::End);
    }
    if rest.len() < HEADER_LEN {
        return Ok(Next::Torn);
    }
    let len: [u8; 4] = rest[..4].try_into().expect("4 bytes");
    if rest[4..8] != check(len) {
        return Err("frame header check failed".into());
    }
    let end = HEADER_LEN + u32::from_be_bytes(len) as usize;
    if rest.len() < end {
        return Ok(Next::Torn);
    }
    let frame = from_canonical_dagcbor_checked::<Frame>(&rest[HEADER_LEN..end])
        .map_err(|e| format!("frame payload: {e}"))?;
    Ok(Next::Frame(frame, at + end))
}
