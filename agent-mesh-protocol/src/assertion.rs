//! The **Assertion** proof: a detached author signature over a [`ContentId`].
//!
//! It answers *who vouched for this object?* and lives **beside** the node,
//! never inside its hashed bytes (see [`crate::authority`], proof table). The
//! signed message is a domain tag plus the CID's own byte form — no bespoke
//! canonical encoding. The assertion does not carry the CID: the reader
//! supplies the CID they computed, so a signature cannot vouch for anything
//! but what the reader actually holds.

use content_addressable::ContentId;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::agent_key::{AgentKey, CertChain, Issuer, SerdeSig};
use crate::{MeshError, Result};

/// Domain tag: a signature minted here can't be replayed as any other signature.
const ASSERTION_DOMAIN: &[u8] = b"agent-mesh/provenance/assertion/v1\0";

/// An author's detached signature over a [`ContentId`], with the certificate
/// chain that lets any reader check who the author is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    author: CertChain,
    sig: SerdeSig,
}

fn message(cid: &ContentId) -> Vec<u8> {
    let mut m = ASSERTION_DOMAIN.to_vec();
    m.extend_from_slice(&cid.to_bytes());
    m
}

impl Assertion {
    /// `author` vouches for `cid`.
    #[must_use]
    pub fn sign(author: &AgentKey, cid: &ContentId) -> Self {
        Self {
            author: author.cert().clone(),
            sig: SerdeSig(author.sign(&message(cid))),
        }
    }

    /// The author's certificate chain.
    #[must_use]
    pub fn author(&self) -> &CertChain {
        &self.author
    }

    /// Check that the author signed `cid` and that the author's chain passes
    /// is **rooted** at `trust_root` (the flock server's agent public key) at epoch
    /// `generation`: the trust root must be the root agent, the certificate
    /// issued by the user. An intermediate or leaf key matching is refused.
    /// Two servers of one user share a user key but not an agent key.
    ///
    /// # Errors
    /// [`MeshError::BadSignature`] if the signature does not match `cid`;
    /// [`MeshError::InvalidCertChain`] / generation / amplification errors if
    /// the chain is bad or its root agent is not `trust_root`.
    pub fn verify(&self, cid: &ContentId, trust_root: &[u8; 32], generation: u64) -> Result<()> {
        self.author.verify_at(generation)?;
        if root_agent(&self.author) != trust_root {
            return Err(MeshError::InvalidCertChain(
                "author chain is not rooted at the trust root".into(),
            ));
        }
        VerifyingKey::from_bytes(&self.author.agent_pubkey)
            .and_then(|vk| vk.verify_strict(&message(cid), &self.sig.0))
            .map_err(|_| MeshError::BadSignature)
    }
}

/// The key of the chain's root agent: the certificate issued by a user.
fn root_agent(cert: &CertChain) -> &[u8; 32] {
    match &cert.issuer {
        Issuer::User(_) => &cert.agent_pubkey,
        Issuer::Agent { parent, .. } => root_agent(parent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentMetadata, Caveats, UserKey};
    use ed25519_dalek::Signature;

    fn meta(role: &str) -> AgentMetadata {
        AgentMetadata {
            role: role.into(),
            host: "h".into(),
            capabilities: vec![],
            issued_at: "2026-10-15T00:00:00Z".into(),
            expires_at: None,
            caveats: Caveats::top(),
        }
    }

    fn cid(n: u8) -> ContentId {
        ContentId::from_canonical_bytes(&[n])
    }

    /// (server, author certified by server)
    fn flock(user: &UserKey) -> (AgentKey, AgentKey) {
        let server = AgentKey::issue(user, meta("server"));
        let author = server.delegate(meta("author")).unwrap();
        (server, author)
    }

    #[test]
    fn verifies_for_any_reader_holding_the_chain() {
        let (server, author) = flock(&UserKey::generate());
        let a = Assertion::sign(&author, &cid(1));
        // a reader receives only the serialized assertion
        let wire = serde_json::to_vec(&a).unwrap();
        let got: Assertion = serde_json::from_slice(&wire).unwrap();
        got.verify(&cid(1), &server.public_bytes(), 0).unwrap();
    }

    #[test]
    fn one_changed_byte_fails() {
        let (server, author) = flock(&UserKey::generate());
        let a = Assertion::sign(&author, &cid(1));
        let root = server.public_bytes();
        assert!(a.verify(&cid(2), &root, 0).is_err(), "changed CID");
        let mut bytes = a.sig.0.to_bytes();
        bytes[0] ^= 1;
        let mut bad = a.clone();
        bad.sig = SerdeSig(Signature::from_bytes(&bytes));
        assert!(bad.verify(&cid(1), &root, 0).is_err(), "changed signature");
    }

    #[test]
    fn other_flock_server_fails_even_for_the_same_user() {
        let user = UserKey::generate();
        let (_s1, author1) = flock(&user);
        let (s2, _author2) = flock(&user);
        let a = Assertion::sign(&author1, &cid(1));
        assert!(a.verify(&cid(1), &s2.public_bytes(), 0).is_err());
    }

    #[test]
    fn domain_tag_separates_from_a_bare_cid_signature() {
        let (server, author) = flock(&UserKey::generate());
        let c = cid(1);
        let a = Assertion {
            author: author.cert().clone(),
            sig: SerdeSig(author.sign(&c.to_bytes())),
        };
        assert!(a.verify(&c, &server.public_bytes(), 0).is_err());
    }

    fn seed_of(k: &AgentKey) -> [u8; 32] {
        k.signing_key_bytes()
    }

    #[test]
    fn intermediate_match_with_other_root_agent_is_refused() {
        // user -> other -> pinned -> author: root agent is `other`.
        let user = UserKey::generate();
        let other = AgentKey::issue(&user, meta("other"));
        let pinned = AgentKey::issue(&user, meta("pinned"));
        let ch = other.possession_challenge(pinned.public_bytes());
        let proof = pinned.sign(&ch.signing_bytes());
        let cert = other
            .delegate_external(&ch, &proof, meta("pinned"))
            .unwrap();
        let pinned_via_other = AgentKey::from_seed_and_cert(&seed_of(&pinned), cert).unwrap();
        let author = pinned_via_other.delegate(meta("author")).unwrap();
        let a = Assertion::sign(&author, &cid(1));
        assert!(a.verify(&cid(1), &pinned.public_bytes(), 0).is_err());
        a.verify(&cid(1), &other.public_bytes(), 0).unwrap();
    }

    #[test]
    fn author_leaf_as_trust_root_is_refused() {
        let (_server, author) = flock(&UserKey::generate());
        let a = Assertion::sign(&author, &cid(1));
        assert!(a.verify(&cid(1), &author.public_bytes(), 0).is_err());
    }

    #[test]
    fn bounded_generation_valid_at_n_refused_at_n_plus_1() {
        let user = UserKey::generate();
        let mut m = meta("server");
        m.caveats.valid_for_generation = crate::Scope::only([5u64]);
        let server = AgentKey::issue(&user, m.clone());
        let author = server.delegate(m).unwrap();
        let a = Assertion::sign(&author, &cid(1));
        a.verify(&cid(1), &server.public_bytes(), 5).unwrap();
        assert!(a.verify(&cid(1), &server.public_bytes(), 6).is_err());
        assert!(a.verify(&cid(1), &server.public_bytes(), 4).is_err());
    }
}
