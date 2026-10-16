//! Verifying the signed admission chain, entry by entry.

use crate::frame::Sealed;
use crate::{ServerError, SignerResolver};
use agent_mesh_flock::{Board, Signer};
use content_addressable::ContentId;

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

/// Verify `sealed` extends `chain` and resolve its event's signer.
///
/// # Errors
/// [`ServerError::Signer`] when the chain or signatures do not verify.
pub fn verify_entry(
    _chain: &Chain,
    _board: &Board,
    _sealed: &Sealed,
    _resolver: &dyn SignerResolver,
) -> Result<Signer, ServerError> {
    todo!()
}
