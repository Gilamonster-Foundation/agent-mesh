//! [`RatchetMessage`] — the serializable wire form of one ratchet-encrypted
//! payload.
//!
//! This is a thin, self-describing wrapper over a vodozemac
//! [`OlmMessage`](vodozemac::olm::OlmMessage). It carries the Olm message
//! *type* (pre-key vs. normal) alongside the ciphertext bytes so a peer can
//! reconstruct the exact `OlmMessage` without guessing. The first message a
//! session sends is always a `PreKey` message (it bootstraps the receiver's
//! inbound session); every subsequent message is `Normal`.
//!
//! A `RatchetMessage` is meant to ride *inside* an
//! `agent_mesh_protocol::SignedEnvelope` on the bus — the envelope provides
//! the mesh's signing/replay defenses at the transport layer, while the
//! ratchet provides message-layer forward secrecy and post-compromise
//! security. See the crate-level docs for the bus-integration TODO.

use serde::{Deserialize, Serialize};
use vodozemac::olm::OlmMessage;

use crate::error::{RatchetError, Result};

/// One ratchet-encrypted message, ready to place on the wire.
///
/// `message_type` is the Olm discriminant (`0` = pre-key, `1` = normal) and
/// `ciphertext` is the opaque Olm body. Use [`RatchetMessage::is_prekey`] to
/// branch on session establishment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Olm message discriminant: `0` = pre-key (opens a session), `1` =
    /// normal (advances an established session).
    pub message_type: usize,
    /// Opaque Olm ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// Build a `RatchetMessage` from a vodozemac [`OlmMessage`].
    #[must_use]
    pub fn from_olm(msg: &OlmMessage) -> Self {
        let (message_type, ciphertext) = msg.to_parts();
        Self {
            message_type,
            ciphertext,
        }
    }

    /// Reconstruct the vodozemac [`OlmMessage`] this wire message describes.
    ///
    /// Returns [`RatchetError::MalformedMessage`] if the bytes don't parse as
    /// the declared Olm message type.
    pub fn to_olm(&self) -> Result<OlmMessage> {
        OlmMessage::from_parts(self.message_type, &self.ciphertext)
            .map_err(|e| RatchetError::MalformedMessage(e.to_string()))
    }

    /// `true` if this is a pre-key message — i.e. one that opens (or could
    /// open) an inbound session on the receiver.
    #[must_use]
    pub fn is_prekey(&self) -> bool {
        self.message_type == 0
    }
}
