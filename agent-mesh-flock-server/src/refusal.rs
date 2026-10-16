//! The refusal audit chain: refused events, kept out of the board and out of
//! the admission index, but recorded in their own signed, hash-linked history.
//!
//! Each record is `MerkleNode { parents: {previous refusal, or genesis},
//! payload: RefusalRecord }` with the server's `Assertion` over its id, one
//! per frame, in the file `refusals`.

use agent_mesh_flock::Refusal;
use agent_mesh_protocol::Assertion;
use content_addressable::{ContentId, MerkleNode};
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
