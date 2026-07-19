//! [`AgentKey`] — a short-lived per-agent ed25519 sub-key, certified
//! by a [`UserKey`].
//!
//! Agent keys are issued in memory (`AgentKey::issue`) and never
//! persisted. Each one carries a [`CertChain`] proving the user
//! signed off on this agent's identity and metadata. Peers verify the
//! cert chain once on first contact and cache the agent's public key.

use crate::caveats::{Caveats, Scope};
use crate::fingerprint::Fingerprint;
use crate::user_key::{UserKey, UserPublic};
use crate::{MeshError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Domain-separation tag for proof-of-possession signatures, so a PoP can never
/// be confused with a cert-issue signature or any other signed payload (§9.2).
const POP_DOMAIN: &[u8] = b"agent-mesh/possession-challenge/v1";

/// A proof-of-possession challenge (§9.2). A certifier issues it for a `subject`
/// pubkey; the holder of that subject's *private* key must sign
/// [`signing_bytes`](PossessionChallenge::signing_bytes) to prove possession
/// before the certifier will vouch for the pubkey. Binding both pubkeys + a
/// fresh nonce stops a proof minted for one `(issuer, subject)` pair — or one
/// session — from being replayed into another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PossessionChallenge {
    /// The agent that issued this challenge and will sign the resulting cert.
    pub issuer_pubkey: [u8; 32],
    /// The externally-held pubkey whose possession must be proven.
    pub subject_pubkey: [u8; 32],
    /// Fresh random nonce — makes each challenge single-use.
    pub nonce: [u8; 32],
}

impl PossessionChallenge {
    /// The canonical, domain-separated bytes the **subject** signs to answer the
    /// challenge. Returned for any holder (in-memory key, phone keystore, HSM) to
    /// sign with whatever mechanism it has; the result is the PoP proof.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(POP_DOMAIN.len() + 96);
        v.extend_from_slice(POP_DOMAIN);
        v.extend_from_slice(&self.issuer_pubkey);
        v.extend_from_slice(&self.subject_pubkey);
        v.extend_from_slice(&self.nonce);
        v
    }
}

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
    /// `issuer_sig` of the embedded [`CertChain`] (a root [`Issuer::User`]).
    /// Use [`AgentKey::delegate`] to mint an *attenuated* sub-agent.
    pub fn issue(user: &UserKey, metadata: AgentMetadata) -> Self {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let agent_pubkey_bytes: [u8; 32] = *signing.verifying_key().as_bytes();

        let to_sign = sign_payload(&agent_pubkey_bytes, &metadata);
        let sig = user.sign(&to_sign);

        let cert = CertChain {
            agent_pubkey: agent_pubkey_bytes,
            metadata,
            issuer: Issuer::User(user.public()),
            issuer_sig: SerdeSig(sig),
        };
        Self { signing, cert }
    }

    /// Delegate a **sub-agent** key from this agent — attenuation-only.
    ///
    /// The child's caveats must be `⊑` this agent's caveats (the parent
    /// authority), otherwise [`MeshError::CaveatAmplification`] is returned
    /// and no key is minted. The sub-cert is signed by *this* agent's key and
    /// embeds this agent's cert as its parent, so it roots at the same user
    /// and every verifier re-checks attenuation at each link. A confused or
    /// compromised agent therefore cannot mint a child with more authority
    /// than it holds.
    pub fn delegate(&self, metadata: AgentMetadata) -> Result<Self> {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let sub_pubkey: [u8; 32] = *signing.verifying_key().as_bytes();
        let cert = self.certify_pubkey(sub_pubkey, metadata)?;
        Ok(Self { signing, cert })
    }

    /// Issue a [`PossessionChallenge`] for certifying `subject_pubkey` under this
    /// agent (§9.2). The certifier holds the returned challenge, sends it to the
    /// subject out of band, and passes the subject's signed answer back into
    /// [`delegate_external`](Self::delegate_external). The nonce is fresh, so each
    /// challenge is single-use.
    #[must_use]
    pub fn possession_challenge(&self, subject_pubkey: [u8; 32]) -> PossessionChallenge {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        PossessionChallenge {
            issuer_pubkey: self.cert.agent_pubkey,
            subject_pubkey,
            nonce,
        }
    }

    /// Certify an **externally-held** public key into a [`CertChain`] signed by
    /// this agent — attenuation-only, *without* minting or holding the external
    /// party's secret, and **only against a proof of possession** (§9.2).
    ///
    /// This is the seam phone enrollment needs. A worker agent (itself delegated
    /// from a [`UserKey`]) can vouch for a phone's keystore-resident public key:
    /// it produces a sub-cert rooted at the same user, with caveats `⊑` this
    /// agent's authority, signed by this agent's key. The phone never reveals its
    /// private key — it keeps its seed (or a non-exportable keystore handle) and
    /// reconstructs its own [`AgentKey`] via
    /// [`from_seed_and_cert`](Self::from_seed_and_cert).
    ///
    /// **Proof of possession.** `challenge` must have been issued by *this* agent
    /// (via [`possession_challenge`](Self::possession_challenge)) and `proof` must
    /// be the subject's signature over [`PossessionChallenge::signing_bytes`].
    /// Without this, an agent could certify *any* pubkey — a victim's, or one it
    /// does not control — which a cross-cloud join must never allow. The cert is
    /// minted over `challenge.subject_pubkey`.
    ///
    /// # Errors
    /// - [`MeshError::InvalidCertChain`] if `challenge.issuer_pubkey` is not this
    ///   agent (a challenge it did not issue);
    /// - [`MeshError::BadSignature`] if the PoP does not verify;
    /// - [`MeshError::CaveatAmplification`] if `metadata`'s caveats are not `⊑`
    ///   this agent's, exactly like [`delegate`](Self::delegate).
    pub fn delegate_external(
        &self,
        challenge: &PossessionChallenge,
        proof: &Signature,
        metadata: AgentMetadata,
    ) -> Result<CertChain> {
        // The challenge must be one THIS agent issued — not attacker-chosen.
        if challenge.issuer_pubkey != self.cert.agent_pubkey {
            return Err(MeshError::InvalidCertChain(
                "possession challenge was not issued by this agent".into(),
            ));
        }
        // Proof of possession: the subject's private key must have signed the
        // challenge. This is the §9.2 gate — certify only a pubkey whose holder
        // proved possession.
        verify_detached(&challenge.subject_pubkey, &challenge.signing_bytes(), proof)?;
        self.certify_pubkey(challenge.subject_pubkey, metadata)
    }

    /// Shared cert-minting body for [`delegate`](Self::delegate) and
    /// [`delegate_external`](Self::delegate_external): attenuation-check, then
    /// sign `(pubkey || metadata)` with this agent's key, embedding this
    /// agent's cert as the parent so the chain roots at the same user.
    fn certify_pubkey(&self, pubkey: [u8; 32], metadata: AgentMetadata) -> Result<CertChain> {
        if !metadata.caveats.leq(&self.cert.metadata.caveats) {
            return Err(MeshError::CaveatAmplification);
        }
        let to_sign = sign_payload(&pubkey, &metadata);
        let sig = self.signing.sign(&to_sign);
        Ok(CertChain {
            agent_pubkey: pubkey,
            metadata,
            issuer: Issuer::Agent {
                pubkey: self.cert.agent_pubkey,
                parent: Box::new(self.cert.clone()),
            },
            issuer_sig: SerdeSig(sig),
        })
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

    /// The ed25519 verifying (public) half of this agent's key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

/// `AgentKey` is the software (in-memory seed) [`MeshSigner`]: it signs with
/// the seed it holds. This is today's behavior, surfaced through the trait so
/// the envelope/transport layers can sign via `&dyn MeshSigner` and a future
/// non-exportable keystore signer drops in at the same call sites.
impl crate::signer::MeshSigner for AgentKey {
    fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
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
    /// [`AgentKey::delegate`] enforces `child ⊑ parent` at mint time, and
    /// [`CertChain::verify`] re-checks attenuation at every link — so a chain
    /// that amplifies authority is rejected even if each signature is valid
    /// (see [`crate::caveats`] and issue #35).
    #[serde(default)]
    pub caveats: Caveats,
}

/// Who signed a [`CertChain`] — the trust anchor for that link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Issuer {
    /// Root: signed directly by the user's key (the trust anchor).
    User(UserPublic),
    /// Delegated: signed by a parent agent. Carries the parent's full cert so
    /// the chain roots at an [`Issuer::User`] and attenuation is checkable per
    /// link.
    Agent {
        /// The parent agent's ed25519 public key. Must equal the embedded
        /// `parent.agent_pubkey`.
        pubkey: [u8; 32],
        /// The parent's cert (recursively verifiable, attenuation-checked).
        parent: Box<CertChain>,
    },
}

/// The proof that this agent serves a specific user — directly (root) or
/// through a chain of attenuating delegations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertChain {
    pub agent_pubkey: [u8; 32],
    pub metadata: AgentMetadata,
    /// Who signed this cert: the root user, or a parent agent + its cert.
    pub issuer: Issuer,
    /// The issuer's signature over `(agent_pubkey || metadata_bytes)`.
    pub issuer_sig: SerdeSig,
}

impl CertChain {
    /// Verify the cert chain end to end.
    ///
    /// - **Root** ([`Issuer::User`]): the user's key must have signed
    ///   `(agent_pubkey || metadata_bytes)`.
    /// - **Delegated** ([`Issuer::Agent`]): the named parent pubkey must match
    ///   the embedded parent cert, that parent cert must itself verify
    ///   (rooting at a user), the parent agent's key must have signed this
    ///   cert, **and** this cert's caveats must be `⊑` the parent's
    ///   ([`MeshError::CaveatAmplification`] otherwise). Attenuation is thus
    ///   enforced structurally at every link — a forged or tampered chain that
    ///   amplifies authority is rejected even if each signature is valid.
    pub fn verify(&self) -> Result<()> {
        self.verify_inner(None)
    }

    /// Verify the cert chain against a known **current generation** (causal, not
    /// wall-clock — §9.1). In addition to signature + attenuation at every link,
    /// each link's `valid_for_generation` must include `current_generation`, else
    /// the chain is refused ([`MeshError::Generation`]). This is the authoritative
    /// revocation axis: bumping the generation invalidates every cert scoped to an
    /// earlier one, pull-based and without any wall-clock.
    pub fn verify_at(&self, current_generation: u64) -> Result<()> {
        self.verify_inner(Some(current_generation))
    }

    /// Shared chain walk. `current_generation = None` is the context-free
    /// [`CertChain::verify`]: it still enforces signatures + attenuation, but a
    /// link that declares a *bounded* `valid_for_generation` is **refused**
    /// (fail-closed) — a generation scope cannot be honoured without a current
    /// generation, and silently ignoring it would be fail-open (the §9.1 hole).
    fn verify_inner(&self, current_generation: Option<u64>) -> Result<()> {
        // Generation gate for THIS link, fail-closed.
        check_generation(
            &self.metadata.caveats.valid_for_generation,
            current_generation,
        )?;
        let to_verify = sign_payload(&self.agent_pubkey, &self.metadata);
        match &self.issuer {
            Issuer::User(user) => {
                // The user is the root authority (`⊤`); any caveats the agent
                // declares are `⊑ ⊤`, so there is nothing to attenuate-check.
                user.verify(&to_verify, &self.issuer_sig.0)
            }
            Issuer::Agent { pubkey, parent } => {
                if *pubkey != parent.agent_pubkey {
                    return Err(MeshError::InvalidCertChain(
                        "delegated cert issuer pubkey does not match its parent".into(),
                    ));
                }
                parent.verify_inner(current_generation)?;
                verify_detached(pubkey, &to_verify, &self.issuer_sig.0)?;
                if !self.metadata.caveats.leq(&parent.metadata.caveats) {
                    return Err(MeshError::CaveatAmplification);
                }
                Ok(())
            }
        }
    }

    /// Fingerprint of the agent's public key.
    #[must_use]
    pub fn agent_fingerprint(&self) -> Fingerprint {
        Fingerprint::of_bytes(&self.agent_pubkey)
    }

    /// Fingerprint of the **root user** this cert chains up to (walking through
    /// any delegations). Unchanged for root certs.
    #[must_use]
    pub fn user_fingerprint(&self) -> Fingerprint {
        match &self.issuer {
            Issuer::User(user) => user.fingerprint(),
            Issuer::Agent { parent, .. } => parent.user_fingerprint(),
        }
    }

    /// The root user's public key this cert chains up to.
    #[must_use]
    pub fn root_user_pubkey(&self) -> UserPublic {
        match &self.issuer {
            Issuer::User(user) => user.clone(),
            Issuer::Agent { parent, .. } => parent.root_user_pubkey(),
        }
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

/// The causal-generation gate (§9.1, fail-closed). An unbounded scope (`All`)
/// always passes. A *bounded* scope passes only when a `current` generation is
/// supplied **and** lies within it; with no context it is REFUSED — a scope that
/// cannot be checked must never be silently ignored (that was the fail-open hole).
fn check_generation(scope: &Scope<u64>, current: Option<u64>) -> Result<()> {
    match scope {
        Scope::All => Ok(()),
        Scope::Only(gens) => match current {
            None => Err(MeshError::Generation(
                "cert is generation-scoped; verify with a current generation via verify_at()"
                    .into(),
            )),
            Some(g) if gens.contains(&g) => Ok(()),
            Some(g) => Err(MeshError::Generation(format!(
                "cert is not valid for generation {g}"
            ))),
        },
    }
}

/// Verify an ed25519 signature from a raw 32-byte public key (a parent
/// agent's key, which — unlike a [`UserPublic`] — arrives as bare bytes).
fn verify_detached(pubkey: &[u8; 32], msg: &[u8], sig: &Signature) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| MeshError::BadSignature)?;
    vk.verify_strict(msg, sig)
        .map_err(|_| MeshError::BadSignature)
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
        assert_eq!(agent.cert().root_user_pubkey(), user.public());
        assert_eq!(agent.cert().agent_pubkey, agent.public_bytes());
    }

    #[test]
    fn verify_cert_chain_succeeds() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        agent.cert().verify().expect("fresh cert verifies");
    }

    /// §9.1: an unbounded (`All`) generation scope — the default — verifies both
    /// context-free and at any generation. No regression for today's certs.
    #[test]
    fn unbounded_generation_verifies_in_any_context() {
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, fixture_metadata("worker"));
        agent.cert().verify().expect("context-free ok");
        agent.cert().verify_at(0).expect("gen 0 ok");
        agent.cert().verify_at(9_999).expect("any gen ok");
    }

    /// §9.1 (the core fix): a generation-SCOPED cert is REFUSED by context-free
    /// `verify()` (the scope can't be checked ⇒ fail-closed, not ignored), passes
    /// `verify_at` for an in-scope generation, and is refused out of scope.
    #[test]
    fn generation_scoped_cert_is_fail_closed_context_free() {
        let mut meta = fixture_metadata("worker");
        meta.caveats = Caveats {
            valid_for_generation: crate::Scope::only([5u64]),
            ..Caveats::top()
        };
        let user = UserKey::generate();
        let agent = AgentKey::issue(&user, meta);

        // Context-free: cannot check the scope → REFUSE (was silently ignored).
        assert!(matches!(
            agent.cert().verify().unwrap_err(),
            MeshError::Generation(_)
        ));
        // With the right generation: passes.
        agent.cert().verify_at(5).expect("valid for generation 5");
        // With a different generation: refused (revoked by generation bump).
        assert!(matches!(
            agent.cert().verify_at(6).unwrap_err(),
            MeshError::Generation(_)
        ));
    }

    /// The gate applies at EVERY link: a delegated child whose chain includes a
    /// generation-scoped link is refused context-free and checked against the
    /// supplied generation across the whole chain.
    #[test]
    fn generation_gate_applies_across_the_chain() {
        let scoped = |role: &str| AgentMetadata {
            caveats: Caveats {
                valid_for_generation: crate::Scope::only([5u64]),
                ..Caveats::top()
            },
            ..fixture_metadata(role)
        };
        let user = UserKey::generate();
        let parent = AgentKey::issue(&user, scoped("lead"));
        let child = parent
            .delegate(scoped("worker"))
            .expect("attenuating delegate");

        assert!(matches!(
            child.cert().verify().unwrap_err(),
            MeshError::Generation(_)
        ));
        child
            .cert()
            .verify_at(5)
            .expect("chain valid for generation 5");
        assert!(matches!(
            child.cert().verify_at(6).unwrap_err(),
            MeshError::Generation(_)
        ));
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
        cert.issuer = Issuer::User(other.public());
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

    // ── Delegation + attenuation enforcement (#35 phase 1c) ─────────────────

    /// Metadata whose only restriction is the given exec allow-list.
    fn meta_exec(role: &str, cmds: &[&str]) -> AgentMetadata {
        AgentMetadata {
            caveats: Caveats {
                exec: crate::Scope::only(cmds.iter().map(|s| s.to_string())),
                ..Caveats::top()
            },
            ..fixture_metadata(role)
        }
    }

    #[test]
    fn delegate_accepts_attenuation_and_roots_at_user() {
        let user = UserKey::generate();
        let parent = AgentKey::issue(&user, meta_exec("parent", &["git", "cargo"]));
        // child exec {git} ⊑ parent {git, cargo}
        let child = parent
            .delegate(meta_exec("child", &["git"]))
            .expect("attenuating delegation succeeds");
        child.cert().verify().expect("delegated cert verifies");
        assert_eq!(child.cert().user_fingerprint(), user.fingerprint());
        assert_eq!(child.cert().root_user_pubkey(), user.public());
    }

    #[test]
    fn delegate_rejects_amplification() {
        let user = UserKey::generate();
        let parent = AgentKey::issue(&user, meta_exec("parent", &["git"]));
        // child wants ⊤ exec — strictly more than the parent's {git}.
        let child = AgentMetadata {
            caveats: Caveats::top(),
            ..fixture_metadata("child")
        };
        assert!(matches!(
            parent.delegate(child),
            Err(MeshError::CaveatAmplification)
        ));
    }

    #[test]
    fn multi_level_delegation_attenuates_each_link() {
        let user = UserKey::generate();
        let a = AgentKey::issue(&user, meta_exec("a", &["git", "cargo"]));
        let b = a.delegate(meta_exec("b", &["git"])).expect("B ⊑ A");
        b.cert().verify().expect("B verifies through the chain");
        assert_eq!(b.cert().user_fingerprint(), user.fingerprint());
        // B cannot grant `rm`, which it never held.
        assert!(matches!(
            b.delegate(meta_exec("c", &["git", "rm"])),
            Err(MeshError::CaveatAmplification)
        ));
    }

    #[test]
    fn delegated_cert_serde_roundtrips() {
        let user = UserKey::generate();
        let parent = AgentKey::issue(&user, meta_exec("parent", &["git"]));
        let child = parent.delegate(meta_exec("child", &["git"])).unwrap();
        let json = serde_json::to_string(child.cert()).unwrap();
        let parsed: CertChain = serde_json::from_str(&json).unwrap();
        assert_eq!(&parsed, child.cert());
        parsed
            .verify()
            .expect("roundtripped delegated cert verifies");
    }

    #[test]
    fn forged_amplifying_chain_fails_verify() {
        // A compromised parent that signs a child granting MORE than it holds
        // must still be rejected at verify time: attenuation is structural,
        // not merely a mint-time courtesy in `delegate`.
        let user = UserKey::generate();
        let parent = AgentKey::issue(&user, meta_exec("parent", &["git"]));

        // Hand-build a child with ⊤ caveats, signed correctly by the parent's
        // key — i.e. bypassing `delegate`'s refusal.
        let mut csprng = OsRng;
        let child_signing = SigningKey::generate(&mut csprng);
        let child_pubkey: [u8; 32] = *child_signing.verifying_key().as_bytes();
        let child_meta = AgentMetadata {
            caveats: Caveats::top(),
            ..fixture_metadata("child")
        };
        let to_sign = sign_payload(&child_pubkey, &child_meta);
        let sig = parent.sign(&to_sign); // a *valid* signature by the parent
        let forged = CertChain {
            agent_pubkey: child_pubkey,
            metadata: child_meta,
            issuer: Issuer::Agent {
                pubkey: parent.public_bytes(),
                parent: Box::new(parent.cert().clone()),
            },
            issuer_sig: SerdeSig(sig),
        };
        assert!(matches!(
            forged.verify(),
            Err(MeshError::CaveatAmplification)
        ));
    }

    // ── External-pubkey delegation (phone enrollment, PR #202 P1) ───────────

    /// A worker certifies an EXTERNAL pubkey (the phone's) into a cert chain it
    /// does NOT hold the secret for. The phone reconstructs its own `AgentKey`
    /// from its OWN seed + the returned cert, signs an envelope, and that
    /// envelope verifies and roots at the user — with caveats attenuated at
    /// each link (phone ⊑ worker ⊑ user).
    #[test]
    fn delegate_external_certifies_phone_and_roots_at_user() {
        use crate::envelope::{Recipient, SignedEnvelope};

        let user = UserKey::generate();
        let worker = AgentKey::issue(&user, meta_exec("worker", &["git", "cargo"]));

        // The phone holds its OWN seed; the worker only ever sees the pubkey.
        let phone_seed = [42u8; 32];
        let phone_signing = SigningKey::from_bytes(&phone_seed);
        let phone_vk = phone_signing.verifying_key();

        // Worker issues a PoP challenge; the phone proves possession by signing it.
        let challenge = worker.possession_challenge(*phone_vk.as_bytes());
        let proof = phone_signing.sign(&challenge.signing_bytes());
        // Worker vouches for the phone's pubkey, attenuating to {git}.
        let phone_cert = worker
            .delegate_external(&challenge, &proof, meta_exec("phone", &["git"]))
            .expect("external delegation attenuates");

        // The cert names the phone's pubkey (NOT a freshly minted one).
        assert_eq!(phone_cert.agent_pubkey, *phone_vk.as_bytes());
        phone_cert.verify().expect("external cert verifies");
        assert_eq!(phone_cert.root_user_pubkey(), user.public());
        assert_eq!(phone_cert.user_fingerprint(), user.fingerprint());

        // Phone reconstructs its AgentKey from its own seed + the cert.
        let phone =
            AgentKey::from_seed_and_cert(&phone_seed, phone_cert).expect("phone seed matches cert");

        // Phone signs an envelope; it verifies end-to-end.
        let env = SignedEnvelope::new(
            &phone,
            Recipient::Topic {
                name: "drake/work".into(),
            },
            1,
            b"from-the-phone".to_vec(),
        );
        env.verify().expect("phone envelope verifies");
        assert_eq!(env.sender_user_fp(), user.fingerprint());

        // Attenuation: phone {git} ⊑ worker {git,cargo} ⊑ user ⊤.
        assert!(phone
            .cert()
            .metadata
            .caveats
            .leq(&worker.cert().metadata.caveats));
    }

    /// A cert built over one external pubkey must NOT validate a DIFFERENT
    /// holder: pairing a mismatched seed with the cert is rejected, and a cert
    /// whose `agent_pubkey` is swapped fails signature verification.
    #[test]
    fn delegate_external_rejects_wrong_pubkey() {
        let user = UserKey::generate();
        let worker = AgentKey::issue(&user, meta_exec("worker", &["git"]));

        let phone_seed = [42u8; 32];
        let phone_signing = SigningKey::from_bytes(&phone_seed);
        let phone_vk = phone_signing.verifying_key();
        let challenge = worker.possession_challenge(*phone_vk.as_bytes());
        let proof = phone_signing.sign(&challenge.signing_bytes());
        let cert = worker
            .delegate_external(&challenge, &proof, meta_exec("phone", &["git"]))
            .unwrap();

        // A DIFFERENT seed cannot reconstruct an AgentKey from this cert.
        let other_seed = [99u8; 32];
        assert!(matches!(
            AgentKey::from_seed_and_cert(&other_seed, cert.clone()),
            Err(MeshError::BadSignature)
        ));

        // Swapping the certified pubkey breaks the issuer signature.
        let mut tampered = cert;
        tampered.agent_pubkey[0] ^= 0xff;
        assert!(matches!(
            tampered.verify(),
            Err(MeshError::BadSignature) | Err(MeshError::CaveatAmplification)
        ));
    }

    /// External delegation is attenuation-only: a phone that asks for MORE than
    /// the worker holds is rejected, just like `delegate`.
    #[test]
    fn delegate_external_rejects_amplification() {
        let user = UserKey::generate();
        let worker = AgentKey::issue(&user, meta_exec("worker", &["git"]));
        let phone_signing = SigningKey::from_bytes(&[42u8; 32]);
        let phone_vk = phone_signing.verifying_key();
        let challenge = worker.possession_challenge(*phone_vk.as_bytes());
        let proof = phone_signing.sign(&challenge.signing_bytes());
        // Phone requests ⊤ exec — strictly more than worker's {git}. PoP passes,
        // so the request reaches — and is refused by — the attenuation check.
        let amplifying = AgentMetadata {
            caveats: Caveats::top(),
            ..fixture_metadata("phone")
        };
        assert!(matches!(
            worker.delegate_external(&challenge, &proof, amplifying),
            Err(MeshError::CaveatAmplification)
        ));
    }

    /// §9.2: certifying a pubkey whose holder did NOT prove possession is refused.
    /// A proof from the WRONG key fails — so an agent can't certify a victim's
    /// pubkey (the proof must come from the holder of the subject's private key).
    #[test]
    fn delegate_external_requires_proof_of_possession() {
        let user = UserKey::generate();
        let worker = AgentKey::issue(&user, meta_exec("worker", &["git"]));
        let victim_vk = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let challenge = worker.possession_challenge(*victim_vk.as_bytes());
        // An attacker signs with a DIFFERENT key (they don't hold the victim's).
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let forged = attacker.sign(&challenge.signing_bytes());
        assert!(matches!(
            worker.delegate_external(&challenge, &forged, meta_exec("v", &["git"])),
            Err(MeshError::BadSignature)
        ));
    }

    /// A challenge issued by a DIFFERENT agent is refused: the proof must answer a
    /// challenge THIS certifier minted (no relay of a foreign challenge).
    #[test]
    fn delegate_external_rejects_a_foreign_challenge() {
        let user = UserKey::generate();
        let worker = AgentKey::issue(&user, meta_exec("worker", &["git"]));
        let other = AgentKey::issue(&user, meta_exec("other", &["git"]));
        let phone_signing = SigningKey::from_bytes(&[42u8; 32]);
        let phone_vk = phone_signing.verifying_key();
        // Challenge minted by `other`, presented to `worker`.
        let foreign = other.possession_challenge(*phone_vk.as_bytes());
        let proof = phone_signing.sign(&foreign.signing_bytes());
        assert!(matches!(
            worker.delegate_external(&foreign, &proof, meta_exec("phone", &["git"])),
            Err(MeshError::InvalidCertChain(_))
        ));
    }

    #[test]
    fn delegated_issuer_pubkey_must_match_parent() {
        // The issuer pubkey naming a different key than the embedded parent
        // cert is a structural inconsistency and must be rejected.
        let user = UserKey::generate();
        let parent = AgentKey::issue(&user, meta_exec("parent", &["git"]));
        let child = parent.delegate(meta_exec("child", &["git"])).unwrap();
        let mut cert = child.cert().clone();
        if let Issuer::Agent { pubkey, .. } = &mut cert.issuer {
            pubkey[0] ^= 0xff;
        }
        assert!(matches!(cert.verify(), Err(MeshError::InvalidCertChain(_))));
    }
}
