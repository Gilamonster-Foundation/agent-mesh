//! Tests for the mesh-identity binding: a `SignedPrekeyBundle` must verify
//! against the agent-mesh ed25519 identity that produced it, and any
//! tampering must be rejected.

use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use agent_mesh_ratchet::{RatchetAccount, SignedPrekeyBundle};

fn metadata(role: &str) -> AgentMetadata {
    AgentMetadata {
        role: role.into(),
        host: "test-host".into(),
        capabilities: vec![],
        issued_at: "2026-06-08T00:00:00Z".into(),
        expires_at: None,
        caveats: Caveats::top(),
    }
}

fn make_bundle() -> (UserKey, SignedPrekeyBundle) {
    let user = UserKey::generate();
    let agent = AgentKey::issue(&user, metadata("worker"));
    let mut acct = RatchetAccount::new();
    acct.generate_one_time_keys(1);
    let bundle = acct.signed_prekey_bundle(&agent).unwrap();
    (user, bundle)
}

#[test]
fn signed_bundle_verifies_against_its_user_fingerprint() {
    let (user, bundle) = make_bundle();
    let (_id, _otk) = bundle
        .verify(&user.fingerprint())
        .expect("a freshly signed bundle verifies against its user");
}

#[test]
fn bundle_fails_against_a_different_user() {
    let (_user, bundle) = make_bundle();
    let stranger = UserKey::generate();
    assert!(
        bundle.verify(&stranger.fingerprint()).is_err(),
        "a bundle must not verify against a user it doesn't root at"
    );
}

#[test]
fn tampered_curve_identity_fails_verify() {
    let (user, mut bundle) = make_bundle();
    // Swap in a different Olm identity key — the agent signature no longer
    // covers it.
    let mut other = RatchetAccount::new();
    other.generate_one_time_keys(1);
    bundle.curve_identity = other.curve_identity_base64();
    assert!(
        bundle.verify(&user.fingerprint()).is_err(),
        "tampering with the Olm identity key must break the signature"
    );
}

#[test]
fn tampered_signature_fails_verify() {
    let (user, mut bundle) = make_bundle();
    let last = bundle.agent_sig.len() - 1;
    bundle.agent_sig[last] ^= 0xff;
    assert!(
        bundle.verify(&user.fingerprint()).is_err(),
        "a corrupted agent signature must fail verification"
    );
}

#[test]
fn tampered_cert_metadata_fails_verify() {
    let (user, mut bundle) = make_bundle();
    // Mutating the signed cert metadata invalidates the cert chain itself.
    bundle.cert.metadata.role = "evil".into();
    assert!(
        bundle.verify(&user.fingerprint()).is_err(),
        "tampering with the cert metadata must break the cert chain"
    );
}

#[test]
fn bundle_serde_roundtrips_and_still_verifies() {
    let (user, bundle) = make_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: SignedPrekeyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, bundle);
    parsed
        .verify(&user.fingerprint())
        .expect("a round-tripped bundle still verifies");
}

#[test]
fn signed_prekey_bundle_requires_a_one_time_key() {
    let user = UserKey::generate();
    let agent = AgentKey::issue(&user, metadata("worker"));
    let mut acct = RatchetAccount::new();
    // No one-time keys generated.
    assert!(
        acct.signed_prekey_bundle(&agent).is_err(),
        "bundling without a one-time key must error"
    );
}
