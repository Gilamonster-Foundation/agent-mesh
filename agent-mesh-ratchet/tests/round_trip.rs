//! End-to-end round-trip + ratchet-advance + replay tests for the 1:1
//! Double Ratchet session.

use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use agent_mesh_ratchet::{RatchetAccount, RatchetSession};

/// Fixed metadata — `issued_at` is a signed *claim*, not a coordination
/// primitive, so a constant string is the right choice (no wall clock).
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

/// Spin up two fully-connected sessions (Alice initiates, Bob accepts).
///
/// Returns `(alice_session, bob_session)` after the first handshake message
/// has been delivered.
fn established_pair() -> (RatchetSession, RatchetSession) {
    let alice_user = UserKey::generate();
    let bob_user = UserKey::generate();
    let alice_agent = AgentKey::issue(&alice_user, metadata("alice"));
    let bob_agent = AgentKey::issue(&bob_user, metadata("bob"));

    let mut alice_acct = RatchetAccount::new();
    alice_acct.generate_one_time_keys(1);
    let alice_bundle = alice_acct.signed_prekey_bundle(&alice_agent).unwrap();

    let mut bob_acct = RatchetAccount::new();
    bob_acct.generate_one_time_keys(1);
    let bob_bundle = bob_acct.signed_prekey_bundle(&bob_agent).unwrap();

    let mut alice_session = alice_acct
        .initiate(&bob_bundle, &bob_user.fingerprint())
        .expect("Alice opens an outbound session to Bob's verified bundle");
    let first = alice_session.encrypt(b"handshake").unwrap();
    assert!(first.is_prekey(), "first message must be a pre-key message");

    let (alice_identity, _otk) = alice_bundle
        .verify(&alice_user.fingerprint())
        .expect("Bob verifies Alice's bundle");
    let (bob_session, plaintext) = bob_acct
        .accept(alice_identity, &first)
        .expect("Bob accepts the pre-key message");
    assert_eq!(plaintext, b"handshake");

    (alice_session, bob_session)
}

#[test]
fn round_trip_both_directions() {
    let (mut alice, mut bob) = established_pair();

    // Alice -> Bob
    let m1 = alice.encrypt(b"ping from alice").unwrap();
    assert_eq!(bob.decrypt(&m1).unwrap(), b"ping from alice");

    // Bob -> Alice (triggers a DH ratchet step → PCS)
    let m2 = bob.encrypt(b"pong from bob").unwrap();
    assert_eq!(alice.decrypt(&m2).unwrap(), b"pong from bob");

    // Several more in each direction.
    for i in 0..5u8 {
        let am = alice.encrypt(format!("a{i}")).unwrap();
        assert_eq!(bob.decrypt(&am).unwrap(), format!("a{i}").as_bytes());
        let bm = bob.encrypt(format!("b{i}")).unwrap();
        assert_eq!(alice.decrypt(&bm).unwrap(), format!("b{i}").as_bytes());
    }
}

#[test]
fn ratchet_advances_per_message_keys_differ() {
    let (mut alice, mut _bob) = established_pair();

    // Encrypting identical plaintext twice yields different ciphertext: the
    // sending chain advanced between the two calls.
    let c1 = alice.encrypt(b"same plaintext").unwrap();
    let c2 = alice.encrypt(b"same plaintext").unwrap();
    assert_ne!(
        c1.ciphertext, c2.ciphertext,
        "ratchet must advance: per-message keys differ"
    );
}

#[test]
fn replay_fails_after_ratchet_advance() {
    let (mut alice, mut bob) = established_pair();

    // Two distinct messages from Alice.
    let m1 = alice.encrypt(b"first").unwrap();
    let m2 = alice.encrypt(b"second").unwrap();

    // Deliver them in order; Bob's receiving chain advances past m1's key.
    assert_eq!(bob.decrypt(&m1).unwrap(), b"first");
    assert_eq!(bob.decrypt(&m2).unwrap(), b"second");

    // Replaying m1 now must fail — the message key was consumed and the
    // chain has moved on.
    let replayed = bob.decrypt(&m1);
    assert!(
        replayed.is_err(),
        "a replayed message must fail to decrypt after the ratchet advanced"
    );
}

#[test]
fn tampered_ciphertext_fails_to_decrypt() {
    let (mut alice, mut bob) = established_pair();
    let mut m = alice.encrypt(b"authentic").unwrap();
    // Flip a byte in the ciphertext body.
    let last = m.ciphertext.len() - 1;
    m.ciphertext[last] ^= 0xff;
    assert!(
        bob.decrypt(&m).is_err(),
        "a tampered ciphertext must not decrypt"
    );
}

#[test]
fn sessions_share_a_session_id() {
    let (alice, bob) = established_pair();
    assert_eq!(
        alice.session_id(),
        bob.session_id(),
        "both peers of one session agree on its id"
    );
}
