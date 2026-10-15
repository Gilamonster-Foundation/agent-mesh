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
    /// through `trust_root` (the flock server's agent public key) at epoch
    /// `generation`. Two servers of one user share a user key but not an agent
    /// key, so the chain must name *this* server, not merely the same user.
    ///
    /// # Errors
    /// [`MeshError::BadSignature`] if the signature does not match `cid`;
    /// [`MeshError::InvalidCertChain`] / generation / amplification errors if
    /// the chain is bad or does not pass through `trust_root`.
    pub fn verify(&self, cid: &ContentId, trust_root: &[u8; 32], generation: u64) -> Result<()> {
        self.author.verify_at(generation)?;
        if !chain_names(&self.author, trust_root) {
            return Err(MeshError::InvalidCertChain(
                "author chain does not pass through the trust root".into(),
            ));
        }
        VerifyingKey::from_bytes(&self.author.agent_pubkey)
            .and_then(|vk| vk.verify_strict(&message(cid), &self.sig.0))
            .map_err(|_| MeshError::BadSignature)
    }
}

/// Does `cert` or any ancestor issuer hold `pubkey`?
fn chain_names(cert: &CertChain, pubkey: &[u8; 32]) -> bool {
    cert.agent_pubkey == *pubkey
        || match &cert.issuer {
            Issuer::User(_) => false,
            Issuer::Agent { parent, .. } => chain_names(parent, pubkey),
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
}
