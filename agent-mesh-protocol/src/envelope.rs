//! Signed wire envelope. Every message between mesh peers is wrapped
//! in one of these — the cert chain proves the sender belongs to a
//! user, the agent signature proves the message wasn't tampered
//! with, and the payload CID lets receivers reject mismatched bodies
//! before paying for downstream parsing.

use crate::agent_key::{AgentKey, CertChain, SerdeSig};
use crate::fingerprint::Fingerprint;
use crate::signer::MeshSigner;
use crate::{MeshError, Result};
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Domain-separation tag for envelope signatures.
const ENVELOPE_TAG: &[u8] = b"agent-mesh-envelope-v1";

/// Recipient of an envelope — direct peer, named topic, or anycast.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recipient {
    /// Direct peer, addressed by agent pubkey fingerprint.
    Direct { agent_fp: Fingerprint },
    /// Pub/sub topic — a string name, scoped to the sender's user
    /// namespace.
    Topic { name: String },
    /// Anycast: any agent claiming the named capability.
    Anycast { capability: String },
}

/// A wire envelope, signed by the sender's agent key.
///
/// Fields, in the order they're produced by [`Self::new`]:
///
/// * `cert_chain` — proves the sender's agent identity.
/// * `recipient` — addressing tag.
/// * `nonce` — 24 random bytes; replay-protection scope.
/// * `sequence` — monotonic per-session counter.
/// * `payload_cid` — BLAKE3 of `payload`.
/// * `payload` — opaque bytes (the actual message).
/// * `agent_sig` — signature over
///   `ENVELOPE_TAG || recipient_bytes || nonce || seq || payload_cid`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub cert_chain: CertChain,
    pub recipient: Recipient,
    pub nonce: [u8; 24],
    pub sequence: u64,
    pub payload_cid: [u8; 32],
    pub payload: ByteBuf,
    pub agent_sig: SerdeSig,
}

impl SignedEnvelope {
    /// Build and sign a new envelope.
    ///
    /// The 24-byte `nonce` is drawn from `rand::thread_rng`; callers
    /// don't manage it. The `sequence` is supplied by the caller —
    /// it's session-scoped state, not crate state.
    pub fn new(sender: &AgentKey, recipient: Recipient, sequence: u64, payload: Vec<u8>) -> Self {
        // Thin wrapper over the signer seam: an `AgentKey` is a software
        // `MeshSigner`, and its own cert is the provenance. Kept so existing
        // callers (and all current tests) are unchanged.
        Self::new_with_signer(sender, sender.cert().clone(), recipient, sequence, payload)
    }

    /// Build and sign a new envelope using an explicit [`MeshSigner`] and a
    /// matching [`CertChain`].
    ///
    /// This is the seam that lets a non-exportable / platform key (a phone
    /// keystore) sign an envelope **without** the raw seed: the `signer`
    /// produces the signature, and the `cert_chain` carries the provenance
    /// (issued via [`AgentKey::delegate_external`](crate::AgentKey::delegate_external)).
    /// For the wire envelope to [`verify`](Self::verify), the signer's
    /// [`verifying_key`](MeshSigner::verifying_key) must equal
    /// `cert_chain.agent_pubkey` — verification checks the signature against the
    /// pubkey *in the cert*, so a mismatched signer simply yields a
    /// [`MeshError::BadSignature`] at verify time.
    ///
    /// [`new`](Self::new) is a thin wrapper over this, passing the `AgentKey`
    /// as both signer and cert source.
    pub fn new_with_signer<S: MeshSigner + ?Sized>(
        signer: &S,
        cert_chain: CertChain,
        recipient: Recipient,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Self {
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let payload_cid: [u8; 32] = *blake3::hash(&payload).as_bytes();

        let to_sign = signing_message(&recipient, &nonce, sequence, &payload_cid);
        let sig = signer.sign(&to_sign);

        Self {
            cert_chain,
            recipient,
            nonce,
            sequence,
            payload_cid,
            payload: ByteBuf::from(payload),
            agent_sig: SerdeSig(sig),
        }
    }

    /// Verify the envelope end-to-end:
    ///
    /// 1. Cert chain is valid (user sig over agent metadata).
    /// 2. `payload_cid` matches the actual `payload` BLAKE3.
    /// 3. Agent signature is valid over
    ///    `(recipient, nonce, sequence, payload_cid)`.
    pub fn verify(&self) -> Result<()> {
        self.cert_chain.verify()?;

        let actual_cid: [u8; 32] = *blake3::hash(&self.payload).as_bytes();
        if actual_cid != self.payload_cid {
            return Err(MeshError::MalformedEnvelope("payload_cid mismatch".into()));
        }

        let agent_vk = VerifyingKey::from_bytes(&self.cert_chain.agent_pubkey)
            .map_err(|e| MeshError::InvalidKey(e.to_string()))?;
        let to_verify = signing_message(
            &self.recipient,
            &self.nonce,
            self.sequence,
            &self.payload_cid,
        );
        agent_vk
            .verify(&to_verify, &self.agent_sig.0)
            .map_err(|_| MeshError::BadSignature)?;
        Ok(())
    }

    /// Fingerprint of the sending agent.
    #[must_use]
    pub fn sender_agent_fp(&self) -> Fingerprint {
        self.cert_chain.agent_fingerprint()
    }

    /// Fingerprint of the user the sender belongs to.
    #[must_use]
    pub fn sender_user_fp(&self) -> Fingerprint {
        self.cert_chain.user_fingerprint()
    }
}

fn signing_message(
    recipient: &Recipient,
    nonce: &[u8; 24],
    sequence: u64,
    payload_cid: &[u8; 32],
) -> Vec<u8> {
    let recipient_bytes =
        serde_json::to_vec(recipient).expect("Recipient serializes deterministically");
    let mut msg = Vec::with_capacity(ENVELOPE_TAG.len() + recipient_bytes.len() + 24 + 8 + 32);
    msg.extend_from_slice(ENVELOPE_TAG);
    msg.extend_from_slice(&recipient_bytes);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&sequence.to_be_bytes());
    msg.extend_from_slice(payload_cid);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_key::AgentMetadata;
    use crate::UserKey;
    use std::collections::HashSet;

    fn fixture_user_and_agent() -> (UserKey, AgentKey) {
        let user = UserKey::generate();
        let agent = AgentKey::issue(
            &user,
            AgentMetadata {
                role: "worker".to_string(),
                host: "test-host".to_string(),
                capabilities: vec!["test".to_string()],
                issued_at: "2026-05-28T12:00:00Z".to_string(),
                expires_at: None,
                caveats: crate::Caveats::top(),
            },
        );
        (user, agent)
    }

    fn direct_recipient() -> Recipient {
        Recipient::Direct {
            agent_fp: Fingerprint::of_bytes(b"some peer"),
        }
    }

    #[test]
    fn roundtrip_envelope_verifies() {
        let (_user, agent) = fixture_user_and_agent();
        let env = SignedEnvelope::new(&agent, direct_recipient(), 1, b"hello".to_vec());
        env.verify().expect("fresh envelope verifies");
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let (_user, agent) = fixture_user_and_agent();
        let mut env = SignedEnvelope::new(&agent, direct_recipient(), 1, b"original".to_vec());
        env.payload = ByteBuf::from(b"tampered".to_vec());
        let err = env.verify().unwrap_err();
        match err {
            MeshError::MalformedEnvelope(_) => {}
            other => panic!("expected MalformedEnvelope, got {other:?}"),
        }
    }

    #[test]
    fn tampered_recipient_fails_verify() {
        let (_user, agent) = fixture_user_and_agent();
        let mut env = SignedEnvelope::new(&agent, direct_recipient(), 1, b"x".to_vec());
        env.recipient = Recipient::Topic {
            name: "other".to_string(),
        };
        assert!(matches!(env.verify().unwrap_err(), MeshError::BadSignature));
    }

    #[test]
    fn tampered_sequence_fails_verify() {
        let (_user, agent) = fixture_user_and_agent();
        let mut env = SignedEnvelope::new(&agent, direct_recipient(), 1, b"x".to_vec());
        env.sequence = 999;
        assert!(matches!(env.verify().unwrap_err(), MeshError::BadSignature));
    }

    #[test]
    fn tampered_nonce_fails_verify() {
        let (_user, agent) = fixture_user_and_agent();
        let mut env = SignedEnvelope::new(&agent, direct_recipient(), 1, b"x".to_vec());
        env.nonce[0] ^= 0xff;
        assert!(matches!(env.verify().unwrap_err(), MeshError::BadSignature));
    }

    #[test]
    fn mismatched_payload_cid_fails() {
        let (_user, agent) = fixture_user_and_agent();
        let mut env = SignedEnvelope::new(&agent, direct_recipient(), 1, b"x".to_vec());
        env.payload_cid[0] ^= 0xff;
        let err = env.verify().unwrap_err();
        match err {
            MeshError::MalformedEnvelope(_) => {}
            other => panic!("expected MalformedEnvelope, got {other:?}"),
        }
    }

    #[test]
    fn serde_roundtrip_envelope() {
        let (_user, agent) = fixture_user_and_agent();
        let env = SignedEnvelope::new(&agent, direct_recipient(), 7, b"payload".to_vec());
        let json = serde_json::to_string(&env).unwrap();
        let parsed: SignedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
        parsed.verify().expect("roundtripped envelope verifies");
    }

    #[test]
    fn unique_nonces_across_envelopes() {
        let (_user, agent) = fixture_user_and_agent();
        let mut seen = HashSet::new();
        for i in 0..100 {
            let env = SignedEnvelope::new(&agent, direct_recipient(), i, b"x".to_vec());
            assert!(seen.insert(env.nonce), "duplicate nonce after {i} draws");
        }
    }

    #[test]
    fn sender_fingerprints_match_cert_chain() {
        let (user, agent) = fixture_user_and_agent();
        let env = SignedEnvelope::new(&agent, direct_recipient(), 1, b"x".to_vec());
        assert_eq!(env.sender_agent_fp(), agent.fingerprint());
        assert_eq!(env.sender_user_fp(), user.fingerprint());
    }

    #[test]
    fn topic_and_anycast_recipients_roundtrip() {
        let (_user, agent) = fixture_user_and_agent();
        for r in [
            Recipient::Topic {
                name: "drake/work".to_string(),
            },
            Recipient::Anycast {
                capability: "ollama".to_string(),
            },
        ] {
            let env = SignedEnvelope::new(&agent, r.clone(), 1, b"x".to_vec());
            env.verify().expect("verify");
            let json = serde_json::to_string(&env).unwrap();
            let parsed: SignedEnvelope = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.recipient, r);
        }
    }

    #[test]
    fn empty_payload_is_legal() {
        let (_user, agent) = fixture_user_and_agent();
        let env = SignedEnvelope::new(&agent, direct_recipient(), 1, vec![]);
        env.verify().expect("empty payload is fine");
    }

    // ── Signer seam (MeshSigner) — phone enrollment, PR #202 P1 ─────────────

    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

    /// A signer that holds a bare ed25519 key and is NOT an `AgentKey` —
    /// stands in for a platform-keystore-backed signer.
    struct ExternalSigner {
        signing: SigningKey,
    }

    impl crate::signer::MeshSigner for ExternalSigner {
        fn verifying_key(&self) -> VerifyingKey {
            self.signing.verifying_key()
        }
        fn sign(&self, msg: &[u8]) -> Signature {
            self.signing.sign(msg)
        }
    }

    /// The full phone path: a worker delegates to an external pubkey, the
    /// holder signs an envelope through a `MeshSigner` (never an `AgentKey`),
    /// and the envelope verifies and roots at the user.
    #[test]
    fn external_signer_envelope_verifies_via_seam() {
        let user = crate::UserKey::generate();
        let worker = AgentKey::issue(
            &user,
            AgentMetadata {
                role: "worker".into(),
                host: "test-host".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T12:00:00Z".into(),
                expires_at: None,
                caveats: crate::Caveats::top(),
            },
        );

        let phone_seed = [42u8; 32];
        let phone = ExternalSigner {
            signing: SigningKey::from_bytes(&phone_seed),
        };
        let phone_cert = worker
            .delegate_external(
                phone.verifying_key(),
                AgentMetadata {
                    role: "phone".into(),
                    host: "phone-host".into(),
                    capabilities: vec!["chat".into()],
                    issued_at: "2026-05-28T12:00:00Z".into(),
                    expires_at: None,
                    caveats: crate::Caveats::top(),
                },
            )
            .expect("external delegation");

        // Sign WITHOUT an AgentKey — purely through the signer seam.
        let env = SignedEnvelope::new_with_signer(
            &phone,
            phone_cert,
            direct_recipient(),
            1,
            b"seam".to_vec(),
        );
        env.verify().expect("seam-signed envelope verifies");
        assert_eq!(env.sender_user_fp(), user.fingerprint());
    }

    /// A signer whose key does NOT match the paired cert produces an envelope
    /// that fails verification — the seam can't be abused to forge identity.
    #[test]
    fn mismatched_signer_and_cert_fails_verify() {
        let (_user, agent) = fixture_user_and_agent();
        // Sign with a stranger's key but ship the agent's cert.
        let stranger = ExternalSigner {
            signing: SigningKey::from_bytes(&[7u8; 32]),
        };
        let env = SignedEnvelope::new_with_signer(
            &stranger,
            agent.cert().clone(),
            direct_recipient(),
            1,
            b"forge".to_vec(),
        );
        assert!(matches!(env.verify().unwrap_err(), MeshError::BadSignature));
    }

    /// `new` and `new_with_signer` are the same operation for an `AgentKey`:
    /// signing the same bytes yields a verifiable envelope either way.
    #[test]
    fn new_is_thin_wrapper_over_new_with_signer() {
        let (_user, agent) = fixture_user_and_agent();
        let via_signer = SignedEnvelope::new_with_signer(
            &agent,
            agent.cert().clone(),
            direct_recipient(),
            5,
            b"x".to_vec(),
        );
        via_signer.verify().expect("signer path verifies");
        assert_eq!(via_signer.cert_chain, *agent.cert());
    }
}
