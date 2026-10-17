//! The local socket protocol: `len:u32be | payload`, the payload canonical
//! dag-cbor from `content-addressable` (the codec the frames use). Messages
//! are transient requests, not identities: nothing here is hashed or signed
//! as a whole, and every certificate, challenge and event inside is the
//! protocol's own type.

use crate::ServerError;
use agent_mesh_flock::Event;
use agent_mesh_protocol::agent_key::PossessionChallenge;
use agent_mesh_protocol::{Assertion, CertChain};
use content_addressable::canonical::{from_canonical_dagcbor_checked, to_canonical_dagcbor};
use content_addressable::{ContentId, MerkleNode};
use ed25519_dalek::Signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// The largest message either side will read.
pub const MAX_MESSAGE: usize = 1 << 20;

/// A session (or the operator) to the server.
// Transient, one in flight per connection: boxing buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Req {
    /// Which flock, and at which epoch.
    Hello,
    /// Mint an invite for a member (the local owner's surface).
    Invite {
        /// The roster member.
        member: String,
    },
    /// Enrollment steps 2-3.
    EnrollBegin {
        /// The bearer token.
        token: String,
        /// The member it is for.
        member: String,
        /// The session's public key.
        pubkey: [u8; 32],
    },
    /// Enrollment step 4; binds this connection to the new session.
    EnrollFinish {
        /// The challenge from `EnrollBegin`.
        challenge: PossessionChallenge,
        /// The key's proof of possession.
        proof: Signature,
    },
    /// Ask to renew if the certificate is behind the epoch.
    Renew {
        /// The session's latest certificate.
        last: CertChain,
    },
    /// Answer a renewal challenge.
    RenewFinish {
        /// The challenge from `Renew`.
        challenge: PossessionChallenge,
        /// The key's proof of possession.
        proof: Signature,
    },
    /// The session's last admitted event.
    Head {
        /// The session's fingerprint, hex.
        session: String,
    },
    /// Admit a session-signed event.
    Admit {
        /// The event node.
        node: MerkleNode<Event>,
        /// The session's signature.
        sig: Assertion,
    },
    /// A clean goodbye: the session is recorded `closed`, not `lost`.
    End,
}

/// The server's answer.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resp {
    /// Answer to `Hello`.
    Hello {
        /// The flock id.
        flock: ContentId,
        /// The current epoch.
        epoch: u64,
    },
    /// Answer to `Invite`.
    Invited {
        /// The bearer token, shown once.
        token: String,
    },
    /// A possession challenge to sign.
    Challenge(PossessionChallenge),
    /// Enrollment done.
    Enrolled {
        /// The session fingerprint, hex.
        session: String,
        /// Its bounded certificate.
        cert: CertChain,
        /// A replacement: it signs nothing until a hand-off.
        pending: bool,
    },
    /// A renewed certificate.
    Cert(CertChain),
    /// The certificate is already for the current epoch.
    Current,
    /// Answer to `Head`.
    Head(Option<ContentId>),
    /// Answer to `Admit`.
    Admitted {
        /// Admission index.
        index: u64,
        /// It was already there.
        duplicate: bool,
    },
    /// Done.
    Ok,
    /// Refused or failed.
    Err(String),
}

/// Write one message.
///
/// # Errors
/// Encoding or I/O.
pub fn write_msg<T: Serialize>(w: &mut impl Write, msg: &T) -> Result<(), ServerError> {
    let bytes = to_canonical_dagcbor(msg).map_err(|e| ServerError::Encoding(e.to_string()))?;
    let len = u32::try_from(bytes.len())
        .ok()
        .filter(|n| *n as usize <= MAX_MESSAGE)
        .ok_or_else(|| ServerError::Encoding("message too large".into()))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&bytes)?;
    Ok(w.flush()?)
}

/// Read one message; `Ok(None)` is a clean end of stream before any byte.
///
/// # Errors
/// A cut-short, oversized or undecodable message, or I/O.
pub fn read_msg<T: DeserializeOwned + Serialize>(
    r: &mut impl Read,
) -> Result<Option<T>, ServerError> {
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut head[got..])? {
            0 if got == 0 => return Ok(None),
            0 => return Err(ServerError::Encoding("cut-short message".into())),
            n => got += n,
        }
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_MESSAGE {
        return Err(ServerError::Encoding("message too large".into()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    from_canonical_dagcbor_checked(&buf)
        .map(Some)
        .map_err(|e| ServerError::Encoding(e.to_string()))
}
