//! [`SignedPrekeyBundle`] — a peer's Olm prekey material, signed by the
//! agent-mesh ed25519 identity.
//!
//! ## Why this exists
//!
//! vodozemac's Olm gives us a Double Ratchet, but it has its *own* Curve25519
//! identity keys that are unrelated to the agent-mesh ed25519 identity
//! ([`AgentKey`] / [`UserKey`]). On its own, an attacker could hand a peer a
//! prekey bundle for a Curve25519 identity they control and impersonate
//! anyone — Olm by itself answers "can we talk securely?" but not "are you who
//! the mesh says you are?".
//!
//! A `SignedPrekeyBundle` closes that gap. It binds the Olm Curve25519
//! identity + a one-time prekey to a mesh identity by:
//!
//! 1. embedding the publisher's [`CertChain`] (which roots at a [`UserKey`]
//!    and is independently verifiable), and
//! 2. carrying an ed25519 signature, produced by the publisher's [`AgentKey`],
//!    over the canonical bundle bytes (`curve_identity || one_time_key`).
//!
//! A verifier therefore checks three things in [`SignedPrekeyBundle::verify`]:
//! the cert chain is internally valid, it roots at the [`Fingerprint`] the
//! verifier already trusts, and the signature over the Olm keys was made by
//! the agent key named in that cert. Only then are the Olm keys trusted enough
//! to open an outbound session against.

use agent_mesh_protocol::{AgentKey, CertChain, Fingerprint};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use vodozemac::olm::Account;
use vodozemac::Curve25519PublicKey;

use crate::error::{RatchetError, Result};

/// A peer's Olm prekey material, authenticated by their agent-mesh identity.
///
/// Construct one with [`crate::RatchetAccount::signed_prekey_bundle`]; verify
/// a received one with [`SignedPrekeyBundle::verify`] before using its keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPrekeyBundle {
    /// The publisher's Olm Curve25519 identity key, base64-encoded (the
    /// canonical vodozemac wire encoding).
    pub curve_identity: String,
    /// One Olm one-time prekey, base64-encoded. Consumed by the peer that
    /// opens an outbound session against this bundle.
    pub one_time_key: String,
    /// The publisher's agent-mesh cert chain (roots at a `UserKey`).
    pub cert: CertChain,
    /// ed25519 signature by the publisher's `AgentKey` over the canonical
    /// bundle bytes (see [`SignedPrekeyBundle::signing_payload`]). 64 bytes.
    pub agent_sig: Vec<u8>,
}

impl SignedPrekeyBundle {
    /// Canonical bytes that the agent key signs / a verifier re-derives.
    ///
    /// `curve_identity_bytes (32) || one_time_key_bytes (32)`. Using the raw
    /// 32-byte forms (rather than the base64 strings) keeps the payload
    /// independent of encoding choices.
    #[must_use]
    pub fn signing_payload(
        curve_identity: &Curve25519PublicKey,
        one_time_key: &Curve25519PublicKey,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(curve_identity.as_bytes());
        out.extend_from_slice(one_time_key.as_bytes());
        out
    }

    /// Assemble and sign a bundle for the keys produced by `account`, using
    /// `agent` (the mesh identity) to authenticate it.
    ///
    /// The caller is responsible for having generated a one-time key on the
    /// account first; this is wired up by
    /// [`crate::RatchetAccount::signed_prekey_bundle`].
    pub(crate) fn create(
        account: &Account,
        one_time_key: Curve25519PublicKey,
        agent: &AgentKey,
    ) -> Self {
        let curve_identity = account.curve25519_key();
        let payload = Self::signing_payload(&curve_identity, &one_time_key);
        let sig = agent.sign(&payload);
        Self {
            curve_identity: curve_identity.to_base64(),
            one_time_key: one_time_key.to_base64(),
            cert: agent.cert().clone(),
            agent_sig: sig.to_bytes().to_vec(),
        }
    }

    /// Decode the Olm Curve25519 identity key.
    pub fn curve_identity_key(&self) -> Result<Curve25519PublicKey> {
        Curve25519PublicKey::from_base64(&self.curve_identity)
            .map_err(|e| RatchetError::InvalidCurveKey(e.to_string()))
    }

    /// Decode the Olm one-time prekey.
    pub fn one_time_prekey(&self) -> Result<Curve25519PublicKey> {
        Curve25519PublicKey::from_base64(&self.one_time_key)
            .map_err(|e| RatchetError::InvalidCurveKey(e.to_string()))
    }

    /// Verify the bundle is authentic and rooted at the expected mesh user.
    ///
    /// Checks, in order:
    ///
    /// 1. the cert chain verifies (signatures + attenuation, per
    ///    [`CertChain::verify`]);
    /// 2. the cert roots at `expected_user` (the [`Fingerprint`] of the
    ///    `UserKey` the verifier already trusts);
    /// 3. the `agent_sig` over `curve_identity || one_time_key` was made by
    ///    the agent key named in the cert.
    ///
    /// On success returns the decoded `(curve_identity, one_time_key)` ready
    /// to feed into [`crate::RatchetAccount::initiate`]. Any failure yields
    /// [`RatchetError::BundleVerification`].
    pub fn verify(
        &self,
        expected_user: &Fingerprint,
    ) -> Result<(Curve25519PublicKey, Curve25519PublicKey)> {
        // 1. cert chain validity (signatures + attenuation).
        self.cert
            .verify()
            .map_err(|e| RatchetError::BundleVerification(format!("cert chain: {e}")))?;

        // 2. it must root at the user the verifier trusts.
        if self.cert.user_fingerprint() != *expected_user {
            return Err(RatchetError::BundleVerification(
                "cert chain does not root at the expected user fingerprint".into(),
            ));
        }

        // 3. the agent key named in the cert must have signed the Olm keys.
        let curve_identity = self.curve_identity_key()?;
        let one_time_key = self.one_time_prekey()?;
        let payload = Self::signing_payload(&curve_identity, &one_time_key);

        let vk = VerifyingKey::from_bytes(&self.cert.agent_pubkey)
            .map_err(|e| RatchetError::BundleVerification(format!("bad agent pubkey: {e}")))?;
        let sig = signature_from_slice(&self.agent_sig)?;
        vk.verify(&payload, &sig).map_err(|_| {
            RatchetError::BundleVerification("agent signature over Olm keys is invalid".into())
        })?;

        Ok((curve_identity, one_time_key))
    }

    /// Fingerprint of the agent that published this bundle (its mesh
    /// identity), for logging / display.
    #[must_use]
    pub fn agent_fingerprint(&self) -> Fingerprint {
        self.cert.agent_fingerprint()
    }
}

/// Parse a 64-byte ed25519 signature, erroring uniformly on the wrong length.
fn signature_from_slice(bytes: &[u8]) -> Result<Signature> {
    let arr: [u8; 64] = bytes.try_into().map_err(|_| {
        RatchetError::BundleVerification(format!("expected 64-byte signature, got {}", bytes.len()))
    })?;
    Ok(Signature::from_bytes(&arr))
}
