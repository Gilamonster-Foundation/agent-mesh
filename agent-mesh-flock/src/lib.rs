//! The pure model of a flock: what an event is, who may admit which, and the
//! board that folds from the admitted log.
//!
//! No I/O, no async, no clock. A caller (the server, step 3) resolves who
//! signed (verifying the detached [`agent_mesh_protocol::Assertion`] and
//! certificate at the current epoch) into a [`Signer`], then asks [`admit`].
//! Identity is `content_addressable::MerkleNode`; nothing here encodes bytes.

mod admission;
mod board;
mod event;
mod signer;

pub use admission::{admit, roots_well_formed, roster_well_formed, ConflictKind, Refusal, Verdict};
pub use board::{AttemptState, AttemptView, Board, Entry, LaneView, LogEntry};
pub use event::{
    Body, EndReason, Event, FileRef, Genesis, HandoffApproval, Kind, Member, Outcome, Role,
};
pub use signer::{Signer, SignerClass};
