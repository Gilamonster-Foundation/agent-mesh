//! [`AgentKey`] — a short-lived per-agent ed25519 sub-key, certified
//! by a [`UserKey`].
//!
//! Agent keys are issued in memory (`AgentKey::issue`) and never
//! persisted. Each one carries a [`CertChain`] proving the user
//! signed off on this agent's identity and metadata. Peers verify the
//! cert chain once on first contact and cache the agent's public key.

use crate::caveats::Caveats;
use crate::fingerprint::Fingerprint;
use crate::user_key::{UserKey, UserPublic};
use crate::{MeshError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A short-lived per-agent keypair, signed by the user's root key.
///
/// `AgentKey` deliberately omits any save/load API: agent keys live
/// in memory for the lifetime of the agent process and are
/// regenerated on restart. The certificate ([`AgentKey::cert`])
/// stores enough provenance for peers to trust the public half.
pub struct AgentKey {
    signing: SigningKey,
    cert: CertChain,
}

impl AgentKey {
    /// Issue a new agent key, signed by the given user.
    ///
    /// The user's private key is used exactly once here to sign
    /// `(agent_pubkey || canonical_metadata_bytes)`, producing the
    /// `user_sig` field of the embedded [`CertChain`].
    pub fn issue(user: &UserKey, metadata: AgentMetadata) -> Self {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let agent_pubkey_bytes: [u8; 32] = *signing.verifying_key().as_bytes();

        let to_sign = sign_payload(&agent_pubkey_bytes, &metadata);
        let sig = user.sign(&to_sign);

        let cert = CertChain {
            agent_pubkey: agent_pubkey_bytes,
            metadata,
            user_pubkey: user.public(),
            user_sig: SerdeSig(sig),
        };
        Self { signing, cert }
    }

    /// Sign a message with the agent's sub-key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// BLAKE3 fingerprint of the agent's public key bytes.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_bytes(&self.cert.agent_pubkey)
    }

    /// Borrow the cert chain proving this agent's authority.
    #[must_use]
    pub fn cert(&self) -> &CertChain {
        &self.cert
    }

    /// Raw 32-byte ed25519 public key for this agent.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.cert.agent_pubkey
    }

    /// Expose the raw 32-byte ed25519 signing key bytes.
    ///
    /// This is the ONLY method that surfaces an agent's private bytes.
    /// It exists for one reason: the transport layer
    /// (`agent-mesh-transport`) needs to construct an `iroh` `SecretKey`
    /// from the same ed25519 seed so the agent's pubkey doubles as its
    /// iroh `EndpointId`. Callers must NOT persist or transmit these
    /// bytes — the agent key is ephemeral by design.
    #[must_use]
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Reconstruct an `AgentKey` from a 32-byte ed25519 seed and an
    /// existing cert chain.
    ///
    /// Mirror of [`signing_key_bytes`](Self::signing_key_bytes): used
    /// by the PyO3 bindings (and any FFI consumer) to ship an
    /// `AgentKey` across a tokio-spawn boundary without forcing
    /// `Clone` on the underlying ed25519 signing key. Returns
    /// [`MeshError::BadSignature`] if the seed produces a public key
    /// that doesn't match the cert chain's `agent_pubkey` — i.e.
    /// rejects a forged pairing.
    pub fn from_seed_and_cert(seed: &[u8; 32], cert: CertChain) -> Result<Self> {
        let signing = ed25519_dalek::SigningKey::from_bytes(seed);
        let derived_pub: [u8; 32] = *signing.verifying_key().as_bytes();
        if derived_pub != cert.agent_pubkey {
            return Err(MeshError::BadSignature);
        }
        Ok(Self { signing, cert })
    }
}

/// Metadata claimed by an agent at certificate-issue time. These
/// fields are signed by the user; they cannot be tampered with
/// without invalidating the cert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMetadata {
    /// Role label — e.g. `"inference-worker"`, `"orchestrator"`.
    pub role: String,
    /// Host hint — e.g. `"host-a"`, `"host-b"`.
    pub host: String,
    /// Capabilities advertised to the mesh — e.g. `["ollama", "vllm"]`.
    pub capabilities: Vec<String>,
    /// Issue time, RFC 3339 string. Wall-clock is allowed here
    /// because it's a *claim* in a signed cert, not a coordination
    /// primitive.
    pub issued_at: String,
    /// Optional expiry, RFC 3339. `None` means the cert has no
    /// declared expiry; consumers may still impose their own.
    pub expires_at: Option<String>,
    /// The agent's attenuated authority — the capability set it was minted
    /// with. Part of the signed payload, so it cannot be tampered with
    /// without invalidating the cert: a verifier can read these caveats and
    /// trust them. Defaults to [`Caveats::top`] (unrestricted), which is the
    /// back-compatible "no caveats declared" authority.
    ///
    /// Enforcing `child ⊑ parent` across a delegation chain is the next step
    /// (see [`crate::caveats`] and issue #35); this field is the signed
    /// substrate that step builds on.
    #[serde(default)]
    pub caveats: Caveats,
}

/// The proof that this agent serves a specific user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertChain {
    pub agent_pubkey: [u8; 32],
    pub metadata: AgentMetadata,
    pub user_pubkey: UserPublic,
    pub user_sig: SerdeSig,
}

impl CertChain {
    /// Verify the cert: the embedded `user_pubkey` must have signed
    /// `(agent_pubkey || metadata_bytes)` and produced `user_sig`.
    pub fn verify(&self) -> Result<()> {
        let to_verify = sign_payload(&self.agent_pubkey, &self.metadata);
        self.user_pubkey.verify(&to_verify, &self.user_sig.0)
    }

    /// Fingerprint of the agent's public key.
    #[must_use]
    pub fn agent_fingerprint(&self) -> Fingerprint {
        Fingerprint::of_bytes(&self.agent_pubkey)
    }

    /// Fingerprint of the issuing user's public key.
    #[must_use]
    pub fn user_fingerprint(&self) -> Fingerprint {
        self.user_pubkey.fingerprint()
    }
}

/// Newtype wrapping [`Signature`] so it can roundtrip through serde
/// (the dalek type intentionally doesn't derive `Serialize`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerdeSig(pub Signature);

impl Serialize for SerdeSig {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let bytes: [u8; 64] = self.0.to_bytes();
        bytes.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for SerdeSig {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(de)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64-byte signature"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(Signature::from_bytes(&arr)))
    }
}

/// Canonical byte payload for cert signing/verification.
fn sign_payload(agent_pubkey: &[u8; 32], metadata: &AgentMetadata) -> Vec<u8> {
    let meta_bytes =
        serde_json::to_vec(metadata).expect("AgentMetadata serializes deterministically");
    let mut out = Vec::with_capacity(32 + meta_bytes.len());
    out.extend_from_slice(agent_pubkey);
    out.extend_from_slice(&meta_bytes);
    out
}

impl MeshError {
    /// Helper used in tests to assert cert-chain failures uniformly.
    #[cfg(test)]
    pub(crate) fn is_bad_signature(&self) -> bool {
        matches!(self, Self::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_metadata(role: &str) -> AgentMetadata {
        AgentMetadata {
            role: role.to_string(),
            host: "test-host".to_string(),
            capabilities: vec!["test".to_string()],
            issued_at: "2026-05-28T12:00:00Z".to_string(),
            expires_at: None,
            caveats: Caveats::top(),
        }
    }

    #[test]
    fn issue_agent_key_signed_by_user() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        assert_eq!(agent.cert().user_pubkey, user.public());
        assert_eq!(agent.cert().agent_pubkey, agent.public_bytes());
    }

    #[test]
    fn verify_cert_chain_succeeds() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        agent.cert().verify().expect("fresh cert verifies");
    }

    #[test]
    fn tampered_metadata_fails_verify() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let mut cert = agent.cert().clone();
        cert.metadata.role = "evil".to_string();
        assert!(cert.verify().unwrap_err().is_bad_signature());
    }

    /// A fixture with no explicit caveats is unrestricted (`⊤`).
    #[test]
    fn fixture_caveats_default_to_top() {
        assert_eq!(fixture_metadata("worker").caveats, Caveats::top());
    }

    /// Bounded caveats are part of the signed payload: they survive a serde
    /// round-trip and the cert still verifies.
    #[test]
    fn bounded_caveats_roundtrip_and_verify() {
        let mut meta = fixture_metadata("worker");
        meta.caveats = Caveats {
            exec: crate::Scope::only(["git".to_string()]),
            max_calls: crate::CountBound::AtMost(8),
            ..Caveats::top()
        };
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, meta.clone());
        agent.cert().verify().expect("fresh cert verifies");

        let json = serde_json::to_string(agent.cert()).unwrap();
        let parsed: CertChain = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metadata.caveats, meta.caveats);
        parsed.verify().expect("roundtripped cert verifies");
    }

    /// Widening an agent's caveats after issue must invalidate the cert —
    /// proof the caveats are signed, so a verifier can trust them.
    #[test]
    fn tampered_caveats_fails_verify() {
        let mut meta = fixture_metadata("worker");
        meta.caveats = Caveats {
            exec: crate::Scope::only(["git".to_string()]),
            ..Caveats::top()
        };
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, meta);
        let mut cert = agent.cert().clone();
        cert.metadata.caveats = Caveats::top(); // amplify post-issue
        assert!(cert.verify().unwrap_err().is_bad_signature());
    }

    /// Back-compat: metadata serialized without a `caveats` field (older wire
    /// format) deserializes with `⊤` caveats via `#[serde(default)]`.
    #[test]
    fn absent_caveats_default_to_top() {
        let json = r#"{"role":"w","host":"h","capabilities":[],"issued_at":"2026-05-28T00:00:00Z","expires_at":null}"#;
        let meta: AgentMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.caveats, Caveats::top());
    }

    #[test]
    fn tampered_agent_pubkey_fails_verify() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let mut cert = agent.cert().clone();
        cert.agent_pubkey[0] ^= 0xff;
        assert!(cert.verify().unwrap_err().is_bad_signature());
    }

    #[test]
    fn wrong_user_fails_verify() {
        let user = UserKey::generate();
        let other = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let mut cert = agent.cert().clone();
        cert.user_pubkey = other.public();
        assert!(cert.verify().unwrap_err().is_bad_signature());
    }

    #[test]
    fn serde_roundtrip_cert_chain() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let json = serde_json::to_string(agent.cert()).unwrap();
        let parsed: CertChain = serde_json::from_str(&json).unwrap();
        assert_eq!(&parsed, agent.cert());
        parsed.verify().expect("roundtripped cert still verifies");
    }

    #[test]
    fn fingerprints_match() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let cert = agent.cert();
        assert_eq!(agent.fingerprint(), cert.agent_fingerprint());
        assert_eq!(cert.user_fingerprint(), user.fingerprint());
    }

    #[test]
    fn agent_sign_distinct_from_user_sign() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let user_sig = user.sign(b"x");
        let agent_sig = agent.sign(b"x");
        // distinct keys produce distinct signatures
        assert_ne!(user_sig.to_bytes(), agent_sig.to_bytes());
    }

    #[test]
    fn signing_key_bytes_roundtrip_signs_identically() {
        use ed25519_dalek::Signer;
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let bytes = agent.signing_key_bytes();
        assert_eq!(bytes.len(), 32);
        // Rebuilding a SigningKey from those bytes must produce the
        // same signature byte-for-byte — i.e. the seed roundtrips.
        let rebuilt = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let msg = b"transport-layer-handshake";
        let from_agent = agent.sign(msg);
        let from_rebuilt = rebuilt.sign(msg);
        assert_eq!(from_agent.to_bytes(), from_rebuilt.to_bytes());
    }

    #[test]
    fn from_seed_and_cert_roundtrips() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        let seed = agent.signing_key_bytes();
        let cert = agent.cert().clone();
        let rebuilt = AgentKey::from_seed_and_cert(&seed, cert).expect("seed+cert valid");
        assert_eq!(rebuilt.fingerprint(), agent.fingerprint());
        // And the rebuilt key signs identically (seed roundtrip).
        let msg = b"rebuild-test";
        assert_eq!(rebuilt.sign(msg).to_bytes(), agent.sign(msg).to_bytes());
    }

    #[test]
    fn from_seed_and_cert_rejects_mismatched_pairing() {
        let user = UserKey::generate();
        let agent_a = AgentKey::issue(&user, fixture_metadata("a"));
        let agent_b = AgentKey::issue(&user, fixture_metadata("b"));
        // Pair B's seed with A's cert — must be rejected.
        let res =
            AgentKey::from_seed_and_cert(&agent_b.signing_key_bytes(), agent_a.cert().clone());
        match res {
            Ok(_) => panic!("mismatched pairing must reject"),
            Err(e) => assert!(matches!(e, MeshError::BadSignature)),
        }
    }

    #[test]
    fn metadata_with_expiry_roundtrips() {
        let mut meta = fixture_metadata("worker");
        meta.expires_at = Some("2027-01-01T00:00:00Z".to_string());
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, meta.clone());
        let cert = agent.cert();
        assert_eq!(
            cert.metadata.expires_at.as_deref(),
            Some("2027-01-01T00:00:00Z")
        );
        let json = serde_json::to_string(cert).unwrap();
        let parsed: CertChain = serde_json::from_str(&json).unwrap();
        parsed.verify().unwrap();
    }
}
