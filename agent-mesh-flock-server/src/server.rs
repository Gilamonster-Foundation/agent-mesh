//! The server: one process, one log, one admission transaction at a time.

use crate::{CrashPlan, ServerError, SignerResolver};
use agent_mesh_flock::{Board, ConflictKind, Event};
use agent_mesh_protocol::Assertion;
use content_addressable::{ContentId, MerkleNode};
use std::path::Path;

/// What an admission returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The event's admission index.
    pub index: u64,
    /// It was already admitted; nothing was written.
    pub duplicate: bool,
    /// Admitted as a conflict.
    pub conflict: Option<ConflictKind>,
}

/// An open flock server.
pub struct Server {}

impl Server {
    /// Open the flock in `dir`: lock the log, recover, rebuild state.
    ///
    /// # Errors
    /// [`ServerError::Locked`], corruption, or a signer the resolver refuses.
    pub fn open(_dir: &Path, _resolver: Box<dyn SignerResolver>) -> Result<Self, ServerError> {
        todo!()
    }

    /// The flock id.
    #[must_use]
    pub fn flock(&self) -> ContentId {
        todo!()
    }

    /// The derived board.
    #[must_use]
    pub fn board(&self) -> &Board {
        todo!()
    }

    /// The server's agent public key.
    #[must_use]
    pub fn server_pub(&self) -> [u8; 32] {
        todo!()
    }

    /// The latest admission record's id (the genesis id before any): what
    /// the next record must extend.
    #[must_use]
    pub fn head_record(&self) -> ContentId {
        todo!()
    }

    /// How many events are admitted.
    #[must_use]
    pub fn admitted(&self) -> u64 {
        todo!()
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        todo!()
    }

    /// Test-only: arm a crash for the next append.
    #[doc(hidden)]
    pub fn plan_crash(&mut self, _plan: Option<CrashPlan>) {
        todo!()
    }

    /// One admission transaction.
    ///
    /// # Errors
    /// [`ServerError::Signer`], [`ServerError::Refused`], I/O.
    pub fn admit(
        &mut self,
        _node: MerkleNode<Event>,
        _sig: Assertion,
    ) -> Result<Receipt, ServerError> {
        todo!()
    }
}
