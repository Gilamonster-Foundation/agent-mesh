//! [`RatchetSession`] — an established 1:1 Double Ratchet session.
//!
//! Wraps [`vodozemac::olm::Session`]. Each [`encrypt`](RatchetSession::encrypt)
//! advances the sending chain (so per-message keys differ and a captured key
//! can't decrypt earlier *or* later messages — forward secrecy), and each
//! [`decrypt`](RatchetSession::decrypt) advances the receiving chain. A DH
//! ratchet step on reply gives post-compromise security.

use vodozemac::olm::Session;

use crate::error::{RatchetError, Result};
use crate::message::RatchetMessage;

/// An established secure session with one peer.
pub struct RatchetSession {
    inner: Session,
}

impl RatchetSession {
    /// Wrap a raw vodozemac [`Session`].
    pub(crate) fn from_olm(inner: Session) -> Self {
        Self { inner }
    }

    /// A stable identifier for this session (vodozemac's session id), useful
    /// for routing and de-duplication. Both peers of a session agree on it.
    #[must_use]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    /// Encrypt `plaintext`, advancing the ratchet, and return the wire
    /// message.
    ///
    /// The first message from the initiating side is a pre-key message
    /// (`RatchetMessage::is_prekey()` is `true`); subsequent ones are normal.
    pub fn encrypt(&mut self, plaintext: impl AsRef<[u8]>) -> Result<RatchetMessage> {
        let olm = self
            .inner
            .encrypt(plaintext.as_ref())
            .map_err(|e| RatchetError::Encryption(e.to_string()))?;
        Ok(RatchetMessage::from_olm(&olm))
    }

    /// Decrypt a wire message, advancing the ratchet, and return the
    /// plaintext.
    ///
    /// Returns [`RatchetError::Decryption`] for a wrong key, a corrupted or
    /// tampered message, or a replay attempted after the ratchet has advanced
    /// past that message key.
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>> {
        let olm = message.to_olm()?;
        self.inner
            .decrypt(&olm)
            .map_err(|e| RatchetError::Decryption(e.to_string()))
    }
}
