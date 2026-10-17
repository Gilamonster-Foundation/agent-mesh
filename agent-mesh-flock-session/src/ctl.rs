//! The CLI-facing protocol on the session's socket: one request per
//! connection, in the server wire's framing.

use crate::SessionError;
use agent_mesh_flock::{Body, Kind};
use agent_mesh_flock_server::wire::{read_msg, write_msg};
use content_addressable::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// What the CLI asks of the session.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtlReq {
    /// Who is this session?
    Whoami,
    /// Sign and admit one event with the held key.
    Emit {
        /// The event kind.
        kind: Kind,
        /// Named references.
        refs: BTreeMap<String, ContentId>,
        /// The body.
        body: Body,
    },
    /// Say goodbye and exit.
    End,
}

/// The session's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtlResp {
    /// Answer to `Whoami`.
    Who {
        /// The flock id.
        flock: ContentId,
        /// The roster member.
        member: String,
        /// The session fingerprint, hex.
        session: String,
        /// A replacement that signs nothing yet.
        pending: bool,
    },
    /// Answer to `Emit`.
    Admitted {
        /// The event id.
        event: ContentId,
        /// Its admission index.
        index: u64,
    },
    /// The session is closing.
    Ended,
    /// Refused or failed.
    Err(String),
}

/// One request to a session socket.
///
/// # Errors
/// Connection, wire, or a refusal from the session.
pub fn call(socket: &Path, req: &CtlReq) -> Result<CtlResp, SessionError> {
    let mut s = UnixStream::connect(socket)?;
    write_msg(&mut s, req)?;
    match read_msg::<CtlResp>(&mut s)? {
        Some(CtlResp::Err(why)) => Err(SessionError::Refused(why)),
        Some(r) => Ok(r),
        None => Err(SessionError::Unexpected),
    }
}
