//! `init`: mint the server key and genesis, once.

use crate::{store_server_key, ServerError};
use agent_mesh_flock::{Genesis, Member};
use agent_mesh_protocol::{AgentKey, AgentMetadata, Assertion, Caveats, UserKey};
use content_addressable::canonical::{from_canonical_dagcbor_checked, to_canonical_dagcbor};
use content_addressable::{ContentAddressable, ContentId, MerkleNode};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Server key file name inside a flock directory.
pub const KEY_FILE: &str = "server.key";
/// Signed genesis file name.
pub const GENESIS_FILE: &str = "genesis";
/// The log file name.
pub const LOG_FILE: &str = "log";
/// Refused-event journal file name.
pub const REFUSALS_FILE: &str = "refusals";

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
pub fn init(dir: &Path, user: &UserKey, spec: InitSpec) -> Result<ContentId, ServerError> {
    for name in [KEY_FILE, GENESIS_FILE, LOG_FILE] {
        if dir.join(name).exists() {
            return Err(ServerError::AlreadyInitialised(name.into()));
        }
    }
    if !agent_mesh_flock::roster_well_formed(&spec.roster) {
        return Err(ServerError::Session(
            "duplicate member names, or devices under a member that is not an operator".into(),
        ));
    }
    std::fs::create_dir_all(dir)?;
    let server = AgentKey::issue(
        user,
        AgentMetadata {
            role: "flock-server".into(),
            host: spec.host,
            capabilities: vec![],
            issued_at: spec.issued_at,
            expires_at: None,
            caveats: Caveats::top(),
        },
    );
    store_server_key(&dir.join(KEY_FILE), &server)?;
    let node = Genesis {
        kind: "genesis".into(),
        name: spec.name,
        server_cert: server.cert().clone(),
        roster: spec.roster,
        salt: spec.salt,
    }
    .node();
    let flock = node.content_id().map_err(enc)?;
    let sig = Assertion::sign(&server, &flock);
    let bytes = to_canonical_dagcbor(&SignedGenesis { node, sig }).map_err(enc)?;
    // genesis appears whole or not at all
    let tmp = dir.join("genesis.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(GENESIS_FILE))?;
    for name in [LOG_FILE, REFUSALS_FILE] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))?
            .sync_all()?;
    }
    File::open(dir)?.sync_all()?;
    Ok(flock)
}

fn enc(e: content_addressable::ContentError) -> ServerError {
    ServerError::Encoding(e.to_string())
}

/// Read and re-verify the genesis in `dir`. A restart calls this and never
/// mints a new one.
///
/// # Errors
/// I/O, a bad signature, or a certificate that is not the signer's.
pub fn load_genesis(dir: &Path) -> Result<SignedGenesis, ServerError> {
    let bad = |why: String| ServerError::BadFiles(format!("genesis: {why}"));
    let g: SignedGenesis = from_canonical_dagcbor_checked(&std::fs::read(dir.join(GENESIS_FILE))?)
        .map_err(|e| bad(e.to_string()))?;
    let cert = &g.node.payload.server_cert;
    if g.node.payload.kind != "genesis" || !g.node.parents.is_empty() {
        return Err(bad("not a genesis node".into()));
    }
    if g.sig.author() != cert {
        return Err(bad(
            "signed by a key that is not the server certificate".into()
        ));
    }
    if !agent_mesh_flock::roster_well_formed(&g.node.payload.roster) {
        return Err(bad(
            "duplicate member names, or devices under a member that is not an operator".into(),
        ));
    }
    let flock = g.node.content_id().map_err(enc)?;
    g.sig
        .verify(&flock, &cert.agent_pubkey, 0)
        .map_err(|e| bad(e.to_string()))?;
    Ok(g)
}
