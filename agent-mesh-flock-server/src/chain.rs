//! Verifying the signed admission chain, entry by entry.
//!
//! A reader, or the server recovering, checks for each entry: the record is
//! signed by the server key itself (a member's delegated key is not enough),
//! extends the previous record (the first extends genesis), carries the next
//! index, names this event and the certificate its signature chains through,
//! and moves the epoch only as an `epoch` event does.

use crate::frame::{cert_cid, AdmissionRecord, Sealed};
use crate::ServerError;
use agent_mesh_flock::Kind;
use content_addressable::{ContentAddressable, ContentError, ContentId};

/// Running state of a chain: what the next record must extend.
#[derive(Debug, Clone)]
pub struct Chain {
    /// The previous record id, or the genesis id.
    pub prev: ContentId,
    /// The next index (from 1).
    pub next_index: u64,
    /// The current epoch (from 0).
    pub epoch: u64,
    /// The server's agent public key, from genesis.
    pub server_pub: [u8; 32],
}

impl Chain {
    /// Start after genesis.
    #[must_use]
    pub fn new(genesis: ContentId, server_pub: [u8; 32]) -> Self {
        Self {
            prev: genesis,
            next_index: 1,
            epoch: 0,
            server_pub,
        }
    }

    /// The epoch a record for an event of `kind` must carry.
    #[must_use]
    pub fn epoch_for(&self, kind: Kind) -> u64 {
        self.epoch + u64::from(kind == Kind::Epoch)
    }

    /// Step past a verified or just-written record.
    pub fn advance(&mut self, record: ContentId, rec: &AdmissionRecord) {
        self.prev = record;
        self.next_index += 1;
        self.epoch = rec.epoch;
    }
}

fn enc(e: ContentError) -> ServerError {
    ServerError::Encoding(e.to_string())
}

fn bad(why: &str) -> ServerError {
    ServerError::Signer(why.into())
}

/// Verify `sealed` is the next record of `chain`: signed by the server key,
/// extending the previous record, contiguous, naming its event and the
/// certificate that event was signed with, at the epoch the event implies.
/// Returns the event id and the record id. Who signed the event, and whether
/// the model admits it, is for the caller to establish at `record.epoch`.
///
/// # Errors
/// [`ServerError::Signer`] when the chain or a signature does not verify.
pub fn verify_record(
    chain: &Chain,
    sealed: &Sealed,
) -> Result<(ContentId, ContentId), ServerError> {
    let rec = &sealed.record.payload;
    let record_id = sealed.record.content_id().map_err(enc)?;
    if sealed.record_sig.author().agent_pubkey != chain.server_pub {
        return Err(bad("record is not signed by the server key"));
    }
    sealed
        .record_sig
        .verify(&record_id, &chain.server_pub, rec.epoch)
        .map_err(|e| bad(&format!("record signature: {e}")))?;
    if sealed.record.parents != std::iter::once(chain.prev).collect() {
        return Err(bad("record does not extend the previous record"));
    }
    if rec.index != chain.next_index {
        return Err(bad("index is not the next one"));
    }
    let event_id = sealed.event.content_id().map_err(enc)?;
    if rec.event != event_id {
        return Err(bad("record names another event"));
    }
    if rec.cert != cert_cid(sealed.event_sig.author())? {
        return Err(bad("record names another certificate"));
    }
    if rec.epoch != chain.epoch_for(sealed.event.payload.kind) {
        return Err(bad("epoch does not follow the logged transitions"));
    }
    Ok((event_id, record_id))
}
