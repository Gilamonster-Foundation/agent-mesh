//! [`RatchetAccount`] — an Olm account wrapped for the agent-mesh.
//!
//! Holds the long-lived Olm identity key and a pool of one-time prekeys, and
//! mints authenticated [`SignedPrekeyBundle`]s + opens [`RatchetSession`]s.

use agent_mesh_protocol::{AgentKey, Fingerprint};
use vodozemac::olm::{Account, AccountPickle, SessionConfig};

use crate::bundle::SignedPrekeyBundle;
use crate::error::{RatchetError, Result};
use crate::message::RatchetMessage;
use crate::session::RatchetSession;

/// An Olm account plus the helpers needed to bind it to a mesh identity.
///
/// This wraps [`vodozemac::olm::Account`]. The Olm account carries its own
/// Curve25519 identity (used for the X3DH-style handshake) and Ed25519
/// signing key — but agent-mesh authenticity is anchored on the *mesh*
/// ed25519 identity ([`AgentKey`]), so [`RatchetAccount::signed_prekey_bundle`]
/// signs the published Olm keys with the agent key, not the Olm key.
pub struct RatchetAccount {
    inner: Account,
}

impl RatchetAccount {
    /// Create a fresh account with random Olm identity keys.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Account::new(),
        }
    }

    /// Reconstruct an account from a vodozemac [`AccountPickle`].
    ///
    /// Used for persistence and for deterministic test vectors (unpickling a
    /// fixed pickle reproduces a fixed account). vodozemac's pickle format is
    /// serde-serializable, so a caller can store it however the mesh stores
    /// other key material.
    #[must_use]
    pub fn from_pickle(pickle: AccountPickle) -> Self {
        Self {
            inner: Account::from_pickle(pickle),
        }
    }

    /// Export the account as a [`AccountPickle`] for persistence.
    #[must_use]
    pub fn pickle(&self) -> AccountPickle {
        self.inner.pickle()
    }

    /// Generate `count` fresh one-time prekeys into the account's pool.
    ///
    /// A bundle publishes exactly one of these; generate enough to cover the
    /// number of distinct peers expected to initiate before a republish.
    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    /// How many unpublished one-time keys remain in the pool.
    #[must_use]
    pub fn one_time_key_count(&self) -> usize {
        self.inner.one_time_keys().len()
    }

    /// The Olm Curve25519 identity key, base64-encoded (for display / logging).
    #[must_use]
    pub fn curve_identity_base64(&self) -> String {
        self.inner.curve25519_key().to_base64()
    }

    /// Build a [`SignedPrekeyBundle`] authenticated by `agent` (the mesh
    /// identity that owns this account).
    ///
    /// Consumes one one-time key from the pool (it must have been generated
    /// first via [`generate_one_time_keys`](Self::generate_one_time_keys)).
    /// Returns [`RatchetError::NoOneTimeKey`] if the pool is empty.
    pub fn signed_prekey_bundle(&mut self, agent: &AgentKey) -> Result<SignedPrekeyBundle> {
        let one_time_key = self
            .inner
            .one_time_keys()
            .values()
            .next()
            .copied()
            .ok_or(RatchetError::NoOneTimeKey)?;
        let bundle = SignedPrekeyBundle::create(&self.inner, one_time_key, agent);
        // Mark the published keys as published so the account's view of which
        // keys are "live" stays consistent with what's on the wire.
        self.inner.mark_keys_as_published();
        Ok(bundle)
    }

    /// **Initiator side**: open an outbound session against a peer's verified
    /// prekey bundle.
    ///
    /// `peer_bundle` must already have passed
    /// [`SignedPrekeyBundle::verify`] against the expected user fingerprint;
    /// pass that fingerprint here so this call re-checks authenticity and
    /// can't be misused to talk to an unverified bundle.
    pub fn initiate(
        &self,
        peer_bundle: &SignedPrekeyBundle,
        expected_user: &Fingerprint,
    ) -> Result<RatchetSession> {
        let (identity_key, one_time_key) = peer_bundle.verify(expected_user)?;
        let session = self
            .inner
            .create_outbound_session(SessionConfig::default(), identity_key, one_time_key)
            .map_err(|e| RatchetError::SessionCreation(e.to_string()))?;
        Ok(RatchetSession::from_olm(session))
    }

    /// **Responder side**: open an inbound session from the first message a
    /// peer sent (which must be a pre-key message), recovering both the
    /// session and the first plaintext in one step.
    ///
    /// `peer_identity` is the peer's Olm Curve25519 identity key — obtained
    /// from *their* verified [`SignedPrekeyBundle`] (decode with
    /// [`SignedPrekeyBundle::curve_identity_key`]). Binding the inbound
    /// session to that verified key is what ties the Olm handshake back to the
    /// peer's mesh identity on the responder side.
    pub fn accept(
        &mut self,
        peer_identity: vodozemac::Curve25519PublicKey,
        first_message: &RatchetMessage,
    ) -> Result<(RatchetSession, Vec<u8>)> {
        let olm = first_message.to_olm()?;
        let prekey = match olm {
            vodozemac::olm::OlmMessage::PreKey(p) => p,
            vodozemac::olm::OlmMessage::Normal(_) => return Err(RatchetError::NotAPreKeyMessage),
        };
        let result = self
            .inner
            .create_inbound_session(SessionConfig::default(), peer_identity, &prekey)
            .map_err(|e| RatchetError::SessionCreation(e.to_string()))?;
        Ok((RatchetSession::from_olm(result.session), result.plaintext))
    }
}

impl Default for RatchetAccount {
    fn default() -> Self {
        Self::new()
    }
}
