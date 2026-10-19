//! The refusal audit chain: refused events, kept out of the board and out of
//! the admission index, but recorded in their own signed, hash-linked history.
//!
//! Each record is `MerkleNode { parents: {previous refusal, or genesis},
//! payload: RefusalRecord }` with the server's `Assertion` over its id, one
//! per frame, in the file `refusals`.

use crate::ServerError;
use agent_mesh_flock::Refusal;
#[cfg(feature = "serve")]
use agent_mesh_protocol::AgentKey;
use agent_mesh_protocol::Assertion;
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use serde::{Deserialize, Serialize};

/// Why the table refused an event: [`Refusal`] as stored data, not Debug text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// See [`Refusal::Unencodable`].
    Unencodable,
    /// See [`Refusal::WrongFlock`].
    WrongFlock,
    /// See [`Refusal::AuthorMismatch`].
    AuthorMismatch,
    /// See [`Refusal::BadParents`].
    BadParents,
    /// See [`Refusal::BodyKindMismatch`].
    BodyKindMismatch,
    /// See [`Refusal::PendingSession`].
    PendingSession,
    /// See [`Refusal::UnknownMember`].
    UnknownMember,
    /// See [`Refusal::NotAllowed`].
    NotAllowed,
    /// See [`Refusal::BadPrev`].
    BadPrev,
    /// A second child of the author's head.
    WriterFork,
    /// A required reference role is absent.
    MissingRef(String),
    /// A reference role this kind does not take.
    UnexpectedRef(String),
    /// A referenced event is not in this flock's log.
    UnknownRef(String),
    /// A referenced event is of the wrong kind.
    WrongRefKind(String),
    /// A referenced event is in another lane.
    CrossLane,
    /// The signer is not the addressee.
    NotAddressee,
    /// The herdr adapter never acks.
    AdapterCannotAck,
    /// A verdict's head differs from its review's.
    HeadMismatch,
    /// `replaces` is not the current roster.
    StaleRoster,
    /// The frame it would commit is too large to deliver to a watcher.
    TooLarge,
    /// Only a server-signed roster changes operator devices.
    DevicesLocked,
    /// `devices` on a member that is not an operator.
    DevicesOnNonOperator,
    /// Two roster members share a name.
    DuplicateMember,
    /// Only a server-signed roster changes the file roots.
    RootsLocked,
    /// A root name that is empty, too long, not plain, or declared twice.
    BadRoot,
    /// A pane or tab claim that is empty, too long or not printable.
    BadClaim,
    /// A `job-end` that does not say exactly one of an exit code and a signal.
    BadExit,
}

impl From<&Refusal> for Reason {
    fn from(r: &Refusal) -> Self {
        match r {
            Refusal::Unencodable => Self::Unencodable,
            Refusal::WrongFlock => Self::WrongFlock,
            Refusal::AuthorMismatch => Self::AuthorMismatch,
            Refusal::BadParents => Self::BadParents,
            Refusal::BodyKindMismatch => Self::BodyKindMismatch,
            Refusal::PendingSession => Self::PendingSession,
            Refusal::UnknownMember => Self::UnknownMember,
            Refusal::NotAllowed => Self::NotAllowed,
            Refusal::BadPrev => Self::BadPrev,
            Refusal::WriterFork => Self::WriterFork,
            Refusal::MissingRef(s) => Self::MissingRef((*s).into()),
            Refusal::UnexpectedRef(s) => Self::UnexpectedRef(s.clone()),
            Refusal::UnknownRef(s) => Self::UnknownRef((*s).into()),
            Refusal::WrongRefKind(s) => Self::WrongRefKind((*s).into()),
            Refusal::CrossLane => Self::CrossLane,
            Refusal::NotAddressee => Self::NotAddressee,
            Refusal::AdapterCannotAck => Self::AdapterCannotAck,
            Refusal::HeadMismatch => Self::HeadMismatch,
            Refusal::StaleRoster => Self::StaleRoster,
            Refusal::TooLarge => Self::TooLarge,
            Refusal::DevicesLocked => Self::DevicesLocked,
            Refusal::DevicesOnNonOperator => Self::DevicesOnNonOperator,
            Refusal::DuplicateMember => Self::DuplicateMember,
            Refusal::RootsLocked => Self::RootsLocked,
            Refusal::BadRoot => Self::BadRoot,
            Refusal::BadClaim => Self::BadClaim,
            Refusal::BadExit => Self::BadExit,
        }
    }
}

/// The payload of one refusal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalRecord {
    /// The refused event node.
    pub event: ContentId,
    /// The event's claimed author fingerprint, hex.
    pub author: String,
    /// Why.
    pub reason: Reason,
    /// How many events were admitted when it was refused.
    pub admitted: u64,
}

/// One refusal and the server's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalEntry {
    /// The record node.
    pub record: MerkleNode<RefusalRecord>,
    /// The server's assertion over the record's id.
    pub sig: Assertion,
}

impl RefusalEntry {
    /// Record a refusal after `prev` (the previous refusal id, or genesis).
    ///
    /// # Errors
    /// Encoding failure.
    #[cfg(feature = "serve")]
    pub fn sign(
        server: &AgentKey,
        prev: ContentId,
        record: RefusalRecord,
    ) -> Result<Self, ServerError> {
        let record = MerkleNode::new(record, [prev]);
        let id = record
            .content_id()
            .map_err(|e| ServerError::Encoding(e.to_string()))?;
        Ok(Self {
            sig: Assertion::sign(server, &id),
            record,
        })
    }

    /// Check this entry extends `prev`, is signed by the server key itself,
    /// and does not claim more admissions than exist or fewer than the last.
    ///
    /// # Errors
    /// [`ServerError::Signer`] naming what failed.
    pub fn verify(
        &self,
        prev: &ContentId,
        server_pub: &[u8; 32],
        epoch: u64,
        last_admitted: u64,
        total_admitted: u64,
    ) -> Result<ContentId, ServerError> {
        let bad = |why: &str| ServerError::Signer(format!("refusal chain: {why}"));
        let id = self
            .record
            .content_id()
            .map_err(|e| ServerError::Encoding(e.to_string()))?;
        if &self.sig.author().agent_pubkey != server_pub {
            return Err(bad("not signed by the server key"));
        }
        self.sig
            .verify(&id, server_pub, epoch)
            .map_err(|e| bad(&e.to_string()))?;
        if self.record.parents != std::iter::once(*prev).collect() {
            return Err(bad("does not extend the previous refusal"));
        }
        let at = self.record.payload.admitted;
        if at < last_admitted || at > total_admitted {
            return Err(bad("admission count out of order"));
        }
        Ok(id)
    }
}
