//! The local socket protocol: `len:u32be | payload`, the payload canonical
//! dag-cbor from `content-addressable` (the codec the frames use). Messages
//! are transient requests, not identities: nothing here is hashed or signed
//! as a whole, and every certificate, challenge and event inside is the
//! protocol's own type.

use crate::{Head, Sealed, ServerError};
#[cfg(feature = "serve")]
use agent_mesh_flock::Event;
#[cfg(feature = "serve")]
use agent_mesh_protocol::agent_key::PossessionChallenge;
use agent_mesh_protocol::Assertion;
#[cfg(feature = "serve")]
use agent_mesh_protocol::CertChain;
use content_addressable::canonical::{from_canonical_dagcbor_checked, to_canonical_dagcbor};
use content_addressable::MerkleNode;
use content_addressable::{ContentId, RawContentId};
#[cfg(feature = "serve")]
use ed25519_dalek::Signature;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// The largest message either side will read.
pub const MAX_MESSAGE: usize = 1 << 20;

/// The largest cited file the server will serve: one message, with room for
/// the response around the bytes. Larger files are `Unavailable` (chunking is
/// a later step).
pub const MAX_FILE: usize = MAX_MESSAGE - 4096;

/// A signature as a byte string: dalek's own serde writes 64 integers.
#[cfg(feature = "serve")]
mod sig_bytes {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, ser: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(&sig.to_bytes()).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Signature, D::Error> {
        let b = serde_bytes::ByteBuf::deserialize(de)?;
        let arr: [u8; 64] = b
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected a 64-byte signature"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

/// A session (or the operator) to the server.
// Transient, one in flight per connection: boxing buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Req {
    /// Which flock, and at which epoch.
    Hello,
    /// The flock's genesis node: the public root a remote attacher checks
    /// against the flock id it was given.
    Genesis,
    /// Mint an invite for a member (the local owner's surface).
    #[cfg(feature = "serve")]
    Invite {
        /// The roster member.
        member: String,
    },
    /// Enrollment steps 2-3.
    #[cfg(feature = "serve")]
    EnrollBegin {
        /// The bearer token.
        token: String,
        /// The member it is for.
        member: String,
        /// The session's public key.
        #[serde(with = "serde_bytes")]
        pubkey: [u8; 32],
    },
    /// Enrollment step 4; binds this connection to the new session.
    #[cfg(feature = "serve")]
    EnrollFinish {
        /// The challenge from `EnrollBegin`.
        challenge: PossessionChallenge,
        /// The key's proof of possession.
        #[serde(with = "sig_bytes")]
        proof: Signature,
    },
    /// Ask to renew if the certificate is behind the epoch.
    #[cfg(feature = "serve")]
    Renew {
        /// The session's latest certificate.
        last: CertChain,
    },
    /// Answer a renewal challenge.
    #[cfg(feature = "serve")]
    RenewFinish {
        /// The challenge from `Renew`.
        challenge: PossessionChallenge,
        /// The key's proof of possession.
        #[serde(with = "sig_bytes")]
        proof: Signature,
    },
    /// The session's last admitted event.
    #[cfg(feature = "serve")]
    Head {
        /// The session's fingerprint, hex.
        session: String,
    },
    /// Admit a session-signed event.
    #[cfg(feature = "serve")]
    Admit {
        /// The event node.
        node: MerkleNode<Event>,
        /// The session's signature.
        sig: Assertion,
    },
    /// A clean goodbye: the session is recorded `closed`, not `lost`.
    #[cfg(feature = "serve")]
    End,
    /// Ask for a stream challenge (the first step of `Watch`).
    WatchBegin,
    /// Turn this connection into a stream of frames after `from` (from the
    /// start with none). `proof` is the session key's signature over the
    /// challenge's id; it is what authorizes the stream, whoever is on the
    /// other end of the socket.
    Watch {
        /// The saved head to resume from.
        from: Option<Head>,
        /// The signature over [`StreamChallenge::id`].
        proof: Box<Assertion>,
    },
    /// Prove membership on this connection (after `WatchBegin`, with the
    /// same signature a `Watch` carries) so that it may ask for cited files.
    /// One try per challenge.
    Prove {
        /// The signature over [`StreamChallenge::id`].
        proof: Box<Assertion>,
    },
    /// The id of the bytes now at `path` under the declared root `root`.
    FileStat {
        /// A root name the roster declares.
        root: String,
        /// Path under it.
        path: String,
    },
    /// The bytes at `path` under `root`, if they still hash to `id`.
    File {
        /// A root name the roster declares.
        root: String,
        /// Path under it.
        path: String,
        /// The id the file was cited with.
        id: RawContentId,
    },
}

/// What a session signs to open a stream: fresh and bound to this flock and
/// this connection. Transient: identified by content, never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamChallenge {
    /// The flock.
    pub flock: ContentId,
    /// Fresh per connection and used once.
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 32],
}

impl StreamChallenge {
    /// The id the session signs.
    ///
    /// # Errors
    /// Encoding failure.
    pub fn id(&self) -> Result<ContentId, ServerError> {
        use content_addressable::ContentAddressable as _;
        MerkleNode::genesis(self.clone())
            .content_id()
            .map_err(|e| ServerError::Encoding(e.to_string()))
    }
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
    /// Answer to `Genesis`.
    Genesis(crate::SignedGenesis),
    /// Answer to `Invite`.
    #[cfg(feature = "serve")]
    Invited {
        /// The bearer token, shown once.
        token: String,
    },
    /// A possession challenge to sign.
    #[cfg(feature = "serve")]
    Challenge(PossessionChallenge),
    /// Enrollment done.
    #[cfg(feature = "serve")]
    Enrolled {
        /// The session fingerprint, hex.
        session: String,
        /// Its bounded certificate.
        cert: CertChain,
        /// A replacement: it signs nothing until a hand-off.
        pending: bool,
    },
    /// A renewed certificate.
    #[cfg(feature = "serve")]
    Cert(CertChain),
    /// The certificate is already for the current epoch.
    #[cfg(feature = "serve")]
    Current,
    /// Answer to `Head`.
    #[cfg(feature = "serve")]
    Head(Option<ContentId>),
    /// Answer to `Admit`.
    #[cfg(feature = "serve")]
    Admitted {
        /// Admission index.
        index: u64,
        /// It was already there.
        duplicate: bool,
    },
    /// A stream challenge to sign.
    StreamChallenge(StreamChallenge),
    /// One committed frame of the stream, whole.
    Frame(Vec<Sealed>),
    /// The replay is over: everything up to this index has been delivered;
    /// what follows is live.
    Caught {
        /// The last index of the replay.
        index: u64,
    },
    /// The server's history is shorter than the resume token's index.
    Behind {
        /// How many events the server has.
        have: u64,
    },
    /// The resume token is not on this server's history: another record at
    /// that index, or not the end of a frame.
    Diverged,
    /// The stream is over.
    Closed {
        /// Why.
        reason: String,
    },
    /// Membership proved; file requests are open on this connection.
    Proved,
    /// Answer to `FileStat`: what the file hashes to now.
    FileId {
        /// The id of the current bytes.
        id: RawContentId,
    },
    /// Answer to `File`: the bytes, which hash to the cited id (a reader
    /// recomputes this, it does not trust the server).
    File {
        /// The file's bytes.
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    /// The file is not what was cited. Reported, not served.
    ChangedSinceCited {
        /// What the bytes hash to now.
        current: RawContentId,
    },
    /// The file cannot be served, and why.
    Unavailable {
        /// Unknown root, outside the root, not a regular file, missing, too
        /// large.
        reason: String,
    },
    /// Done.
    #[cfg(feature = "serve")]
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

/// Whether `frame` can be delivered to a watcher as one [`Resp::Frame`]: the
/// message limit applies to the response, which carries the admission record
/// and its signatures on top of the event. (The request that caused it also
/// carries the author's certificate chain, which the frame only cites, so for
/// a single event the request limit is reached first; a server-built
/// transaction of several events can still exceed this one.)
///
/// # Errors
/// Encoding failure.
pub fn frame_fits(frame: &[Sealed]) -> Result<bool, ServerError> {
    let bytes = to_canonical_dagcbor(&Resp::Frame(frame.to_vec()))
        .map_err(|e| ServerError::Encoding(e.to_string()))?;
    Ok(bytes.len() <= MAX_MESSAGE)
}
