//! Bridge between `agent-mesh-protocol`'s [`AgentKey`] and iroh's
//! [`SecretKey`] / [`PublicKey`].
//!
//! The architectural insight Phase 2 leans on: **iroh's `EndpointId`
//! IS an ed25519 public key**. We make the agent's signing key serve
//! double-duty as its iroh identity — there is no separate "node id"
//! to manage. A peer that knows your agent fingerprint already knows
//! enough to address your iroh endpoint.

use agent_mesh_protocol::AgentKey;
use iroh::{PublicKey, SecretKey};

/// Build an iroh [`SecretKey`] from the agent's ed25519 signing seed.
///
/// This is the only path that surfaces an agent's private bytes; see
/// [`AgentKey::signing_key_bytes`] for the security caveat. The
/// returned `SecretKey` and the agent's `cert_chain.agent_pubkey` are
/// the matched halves of one ed25519 keypair, so the iroh endpoint
/// bound with this key will advertise the same pubkey the mesh
/// already trusts.
#[must_use]
pub fn to_iroh_secret(agent: &AgentKey) -> SecretKey {
    SecretKey::from_bytes(&agent.signing_key_bytes())
}

/// Convert a raw 32-byte ed25519 public key (e.g.
/// `CertChain::agent_pubkey`) into an iroh [`PublicKey`].
///
/// Returns `None` if the bytes aren't a valid ed25519 point (the
/// curve has ~1/8 invalid encodings).
#[must_use]
pub fn agent_pubkey_to_iroh(pubkey_bytes: &[u8; 32]) -> Option<PublicKey> {
    PublicKey::from_bytes(pubkey_bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_protocol::{AgentMetadata, Caveats, UserKey};

    fn fixture_agent() -> AgentKey {
        let user = UserKey::generate();
        AgentKey::issue(
            &user,
            AgentMetadata {
                role: "test".into(),
                host: "test-host".into(),
                capabilities: vec!["test".into()],
                issued_at: "2026-05-28T00:00:00Z".into(),
                expires_at: None,
                caveats: Caveats::top(),
            },
        )
    }

    #[test]
    fn to_iroh_secret_round_trips_public_bytes() {
        let agent = fixture_agent();
        let sk = to_iroh_secret(&agent);
        let pk: PublicKey = sk.public();
        // The iroh public key must equal the cert's agent pubkey
        // byte-for-byte — otherwise peers couldn't address us.
        assert_eq!(pk.as_bytes(), &agent.public_bytes());
    }

    #[test]
    fn agent_pubkey_to_iroh_accepts_valid_bytes() {
        let agent = fixture_agent();
        let pk = agent_pubkey_to_iroh(&agent.public_bytes()).expect("valid key");
        assert_eq!(pk.as_bytes(), &agent.public_bytes());
    }

    #[test]
    fn agent_pubkey_to_iroh_rejects_invalid_bytes() {
        // Not every 32-byte string is a valid ed25519 point — the
        // top three bits of the last byte encode the sign + are
        // checked against the prime. Sweep a handful of "obviously
        // wrong" patterns; if iroh ever loosens parsing such that
        // NONE of these fail, we want this test to flag the change.
        let candidates: [[u8; 32]; 5] = [
            [0xff; 32],
            {
                let mut a = [0u8; 32];
                a[31] = 0xff;
                a
            },
            {
                let mut a = [0xfe; 32];
                a[31] = 0xff;
                a
            },
            {
                let mut a = [0x7f; 32];
                a[31] = 0xff;
                a
            },
            {
                let mut a = [0u8; 32];
                a[0] = 0xff;
                a[31] = 0xff;
                a
            },
        ];
        let rejected = candidates
            .iter()
            .filter(|b| agent_pubkey_to_iroh(b).is_none())
            .count();
        assert!(
            rejected >= 1,
            "expected at least one of the sentinel byte patterns to fail \
             ed25519 decoding; if this fires, iroh's validation loosened"
        );
    }

    #[test]
    fn iroh_secret_produces_matching_signatures() {
        // The iroh SecretKey and the AgentKey share the same seed, so
        // signing the same message with each should produce the same
        // 64-byte signature.
        let agent = fixture_agent();
        let iroh_sk = to_iroh_secret(&agent);
        let msg = b"shared-seed-check";
        let iroh_sig = iroh_sk.sign(msg);
        let agent_sig = agent.sign(msg);
        assert_eq!(iroh_sig.to_bytes(), agent_sig.to_bytes());
    }
}
