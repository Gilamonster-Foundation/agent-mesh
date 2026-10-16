//! The server key at rest: seed and certificate in a 0600 file.

use crate::ServerError;
use agent_mesh_protocol::AgentKey;
use std::path::Path;

/// Write `key` to `path` (mode 0600, refuses to overwrite).
///
/// # Errors
/// I/O, or the file exists.
pub fn store_server_key(_path: &Path, _key: &AgentKey) -> Result<(), ServerError> {
    todo!()
}

/// Load the key stored by [`store_server_key`] with `AgentKey::from_seed_and_cert`.
///
/// # Errors
/// I/O, a mode wider than 0600, or a seed that does not match the certificate.
pub fn load_server_key(_path: &Path) -> Result<AgentKey, ServerError> {
    todo!()
}
