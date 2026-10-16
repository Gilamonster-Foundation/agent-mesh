//! The server key at rest: seed and certificate in a 0600 file.
//!
//! `AgentKey` has no save or load API of its own; this is the flock's
//! contract for it: `{"seed": <64 hex>, "cert": <CertChain>}`, loaded with
//! `AgentKey::from_seed_and_cert`, which rejects a seed that does not match
//! the certificate.

use crate::ServerError;
use agent_mesh_protocol::AgentKey;
#[cfg(unix)]
use agent_mesh_protocol::CertChain;
#[cfg(unix)]
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
struct KeyFile {
    seed: String,
    cert: CertChain,
}

/// Write `key` to `path` (mode 0600, refuses to overwrite).
///
/// # Errors
/// I/O, or the file exists.
#[cfg(unix)]
pub fn store_server_key(path: &Path, key: &AgentKey) -> Result<(), ServerError> {
    use std::os::unix::fs::OpenOptionsExt;
    let body = serde_json::to_vec(&KeyFile {
        seed: hex::encode(key.signing_key_bytes()),
        cert: key.cert().clone(),
    })
    .map_err(|e| ServerError::Encoding(e.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&body)?;
    file.sync_all()?;
    Ok(())
}

/// Load the key stored by [`store_server_key`] with `AgentKey::from_seed_and_cert`.
///
/// # Errors
/// I/O, a mode wider than 0600, or a seed that does not match the certificate.
#[cfg(unix)]
pub fn load_server_key(path: &Path) -> Result<AgentKey, ServerError> {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
        return Err(ServerError::KeyFileMode);
    }
    let bad = |why: String| ServerError::BadFiles(format!("key file: {why}"));
    let file: KeyFile =
        serde_json::from_slice(&std::fs::read(path)?).map_err(|e| bad(e.to_string()))?;
    let seed: [u8; 32] = hex::decode(&file.seed)
        .map_err(|e| bad(e.to_string()))?
        .try_into()
        .map_err(|_| bad("seed is not 32 bytes".into()))?;
    AgentKey::from_seed_and_cert(&seed, file.cert).map_err(|e| bad(e.to_string()))
}

/// Non-unix hosts are not supported for the server yet.
#[cfg(not(unix))]
pub fn store_server_key(_path: &Path, _key: &AgentKey) -> Result<(), ServerError> {
    Err(ServerError::BadFiles(
        "the flock server needs a unix host".into(),
    ))
}

/// Non-unix hosts are not supported for the server yet.
#[cfg(not(unix))]
pub fn load_server_key(_path: &Path) -> Result<AgentKey, ServerError> {
    Err(ServerError::BadFiles(
        "the flock server needs a unix host".into(),
    ))
}
