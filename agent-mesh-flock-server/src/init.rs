//! `init`: mint the server key and genesis, once.

use crate::ServerError;
use agent_mesh_flock::{Genesis, Member};
use agent_mesh_protocol::{Assertion, UserKey};
use content_addressable::{ContentId, MerkleNode};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Server key file name inside a flock directory.
pub const KEY_FILE: &str = "server.key";
/// Signed genesis file name.
pub const GENESIS_FILE: &str = "genesis";
/// The log file name.
pub const LOG_FILE: &str = "log";
/// Refused-event journal file name.
pub const REFUSALS_FILE: &str = "refusals.log";

/// What the caller chooses for a new flock.
#[derive(Debug, Clone)]
pub struct InitSpec {
    /// Flock name.
    pub name: String,
    /// The first roster.
    pub roster: Vec<Member>,
    /// Distinguishes flocks of the same name and roster.
    pub salt: String,
    /// Host label for the server certificate.
    pub host: String,
    /// RFC 3339 issue claim for the server certificate.
    pub issued_at: String,
}

/// The genesis node and the server's signature over its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGenesis {
    /// The genesis node.
    pub node: MerkleNode<Genesis>,
    /// The server's assertion over `node`'s id.
    pub sig: Assertion,
}

/// Create the flock in `dir`: server key under `user`, signed genesis, empty log.
/// Returns the flock id (the genesis CID).
///
/// # Errors
/// I/O, or the directory already holds a flock.
pub fn init(_dir: &Path, _user: &UserKey, _spec: InitSpec) -> Result<ContentId, ServerError> {
    todo!()
}

/// Read and re-verify the genesis in `dir`.
///
/// # Errors
/// I/O, a bad signature, or a certificate that is not the signer's.
pub fn load_genesis(_dir: &Path) -> Result<SignedGenesis, ServerError> {
    todo!()
}
