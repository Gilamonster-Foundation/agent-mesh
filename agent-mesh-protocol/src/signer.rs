//! [`MeshSigner`] — the signing seam that decouples *holding a key* from
//! *being an [`AgentKey`]*.
//!
//! Today an agent's ed25519 seed lives in process memory (see
//! [`AgentKey::signing_key_bytes`](crate::AgentKey::signing_key_bytes)). That
//! is fine for a server process, but it is a non-starter for a phone: a
//! platform keystore (Android Keystore, iOS Secure Enclave) will sign on your
//! behalf but will **never** export the raw seed.
//!
//! `MeshSigner` is the abstraction that lets those two worlds share one signing
//! path. A signer can produce signatures and reveal its public half — nothing
//! more. The software implementation ([`AgentKey`]) signs with the seed it
//! holds; a future keystore-backed signer signs through an opaque handle. The
//! envelope and (eventually) transport layers sign via `&dyn MeshSigner` so
//! they never need the seed itself.
//!
//! The signer carries no provenance — the [`CertChain`](crate::CertChain) does
//! that. A caller pairs a `MeshSigner` with the matching cert chain (its
//! `agent_pubkey` must equal the signer's [`MeshSigner::verifying_key`]), and
//! the verifier checks the signature against the pubkey *in the cert*. A signer
//! whose key doesn't match the cert simply produces envelopes that fail
//! [`verify`](crate::SignedEnvelope::verify).

use ed25519_dalek::{Signature, VerifyingKey};

/// Something that can sign mesh messages without necessarily exposing its
/// private key.
///
/// Implemented by [`AgentKey`](crate::AgentKey) for the software (in-memory
/// seed) case. Platform-keystore implementations (Android/iOS) are explicitly
/// out of scope here — this trait is the seam they will plug into without
/// touching the envelope/transport call sites.
///
/// `Send + Sync` so a signer can be shared behind an `Arc` across the
/// tokio-spawn boundaries the transport layer uses.
pub trait MeshSigner: Send + Sync {
    /// The ed25519 public half of this signer's key. Must match the
    /// `agent_pubkey` of the [`CertChain`](crate::CertChain) it is paired with,
    /// or the resulting signatures will not verify against the cert.
    fn verifying_key(&self) -> VerifyingKey;

    /// Produce an ed25519 signature over `msg`.
    fn sign(&self, msg: &[u8]) -> Signature;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentKey, AgentMetadata, Caveats, UserKey};
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    fn fixture_agent() -> AgentKey {
        let user = UserKey::generate();
        AgentKey::issue(
            &user,
            AgentMetadata {
                role: "worker".into(),
                host: "test-host".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        )
    }

    /// A test-double signer that holds a bare `SigningKey` but is NOT an
    /// `AgentKey` — proving the seam works for non-`AgentKey` holders such as a
    /// platform keystore wrapper.
    struct RawSigner {
        signing: SigningKey,
    }

    impl MeshSigner for RawSigner {
        fn verifying_key(&self) -> VerifyingKey {
            self.signing.verifying_key()
        }
        fn sign(&self, msg: &[u8]) -> Signature {
            self.signing.sign(msg)
        }
    }

    #[test]
    fn agent_key_is_a_mesh_signer() {
        let agent = fixture_agent();
        let signer: &dyn MeshSigner = &agent;
        let msg = b"sign-via-trait";
        let sig = signer.sign(msg);
        // The trait's verifying_key must match the agent's cert pubkey, and the
        // signature must verify under it.
        assert_eq!(signer.verifying_key().as_bytes(), &agent.public_bytes());
        signer
            .verifying_key()
            .verify(msg, &sig)
            .expect("trait signature verifies under trait verifying_key");
    }

    #[test]
    fn agent_key_trait_sign_matches_inherent_sign() {
        let agent = fixture_agent();
        let msg = b"identical";
        let via_trait = MeshSigner::sign(&agent, msg);
        let via_inherent = agent.sign(msg);
        assert_eq!(via_trait.to_bytes(), via_inherent.to_bytes());
    }

    #[test]
    fn raw_signer_double_signs_and_verifies() {
        // A non-AgentKey signer (holds a key, not a cert) still satisfies the
        // seam: it signs and exposes a matching verifying key.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let expected_vk = signing.verifying_key();
        let signer = RawSigner { signing };
        let msg = b"raw-signer";
        let sig = MeshSigner::sign(&signer, msg);
        assert_eq!(signer.verifying_key().as_bytes(), expected_vk.as_bytes());
        signer
            .verifying_key()
            .verify(msg, &sig)
            .expect("raw signer signature verifies");
    }

    #[test]
    fn signer_is_object_safe_and_send_sync() {
        // Compile-time proof: MeshSigner is object-safe and Send+Sync, so it can
        // live behind Arc<dyn MeshSigner> and cross spawn boundaries.
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn MeshSigner>();
        let agent = fixture_agent();
        let _boxed: std::sync::Arc<dyn MeshSigner> = std::sync::Arc::new(agent);
    }
}
