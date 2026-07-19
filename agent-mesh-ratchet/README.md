# agent-mesh-ratchet

Signal-style **Double Ratchet** for 1:1 secure sessions on the agent-mesh.

This crate adds **message-layer** forward secrecy (FS) and post-compromise
security (PCS) on top of the agent-mesh's transport-layer guarantees
(`agent-mesh-protocol`'s signed, replay-defended `SignedEnvelope`). The mesh's
envelopes authenticate *who sent a frame*; the ratchet keeps the *contents of a
long-lived 1:1 conversation* confidential even if a session key leaks later
(FS) and lets the conversation self-heal after a compromise (PCS).

## Crypto core: vodozemac (not hand-rolled)

The ratchet itself is [`vodozemac`](https://crates.io/crates/vodozemac) —
Matrix's audited Rust implementation of Olm/Megolm. We use the **Olm** 1:1
primitives (a libsignal-style Double Ratchet: X3DH handshake + symmetric-key
ratchet + DH ratchet). This crate is a thin, documented wrapper that binds
those primitives to the agent-mesh ed25519 identity layer.

## Identity binding — the load-bearing part

Olm has its own Curve25519 identity keys, unrelated to the mesh's ed25519
identity (`AgentKey` / `UserKey`). Olm alone answers *"can we talk securely?"*
but not *"are you the agent the mesh vouches for?"*.

`SignedPrekeyBundle` closes that gap. The publisher's Olm Curve25519 identity +
a one-time prekey are **signed by their mesh `AgentKey`**, and the bundle
embeds the agent's `CertChain` (which roots at a `UserKey`). A peer calls
`bundle.verify(&trusted_user_fingerprint)`, which checks:

1. the cert chain is valid (signatures + caveat attenuation);
2. it roots at the `Fingerprint` of the user the verifier already trusts;
3. the agent named in the cert signed the published Olm keys.

Only then are the Olm keys trusted enough to open a session against.

## Usage

```rust
use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
use agent_mesh_ratchet::RatchetAccount;

fn metadata(role: &str) -> AgentMetadata {
    AgentMetadata {
        role: role.into(),
        host: "host-a".into(),
        capabilities: vec![],
        // A signed *claim*, not a coordination primitive — a fixed string.
        issued_at: "2026-06-08T00:00:00Z".into(),
        expires_at: None,
        caveats: Caveats::top(),
    }
}

// Two users, each with one agent identity.
let alice_user = UserKey::generate();
let bob_user = UserKey::generate();
let alice_agent = AgentKey::issue(&alice_user, metadata("alice"));
let bob_agent = AgentKey::issue(&bob_user, metadata("bob"));

// Both sides publish a signed prekey bundle.
let mut alice_acct = RatchetAccount::new();
alice_acct.generate_one_time_keys(1);
let alice_bundle = alice_acct.signed_prekey_bundle(&alice_agent).unwrap();

let mut bob_acct = RatchetAccount::new();
bob_acct.generate_one_time_keys(1);
let bob_bundle = bob_acct.signed_prekey_bundle(&bob_agent).unwrap();

// Alice verifies Bob's bundle, opens a session, sends the first message.
let mut alice_session = alice_acct
    .initiate(&bob_bundle, &bob_user.fingerprint())
    .unwrap();
let first = alice_session.encrypt(b"hello bob").unwrap();

// Bob verifies Alice's bundle to learn her authenticated Olm identity, then
// accepts the first (pre-key) message — recovering plaintext + a session.
let (alice_identity, _otk) = alice_bundle.verify(&alice_user.fingerprint()).unwrap();
let (mut bob_session, plaintext) = bob_acct.accept(alice_identity, &first).unwrap();
assert_eq!(plaintext, b"hello bob");

// The ratchet advances both directions.
let reply = bob_session.encrypt(b"hi alice").unwrap();
assert_eq!(alice_session.decrypt(&reply).unwrap(), b"hi alice");
```

## Public API

| Type | Role |
|------|------|
| `RatchetAccount` | Wraps `vodozemac::olm::Account`: identity + one-time prekeys; mints bundles, initiates/accepts sessions; pickles for persistence. |
| `SignedPrekeyBundle` | A peer's Olm prekey material signed by their mesh `AgentKey`; `verify(&user_fingerprint)` authenticates it. |
| `RatchetSession` | An established session; `encrypt` / `decrypt` advance the ratchet. |
| `RatchetMessage` | Serde-serializable wire form of one encrypted payload (Olm type + ciphertext). |
| `RatchetError` / `Result` | Error type for the crate. |

`vodozemac::Curve25519PublicKey` and `vodozemac::olm::AccountPickle` are
re-exported because they appear in the public API.

## Bus integration — TODO (not faked)

Wiring `RatchetMessage` into `agent-mesh-bus` (carrying ratchet ciphertext
inside a `SignedEnvelope`, routing by `RatchetSession::session_id`, publishing
bundles over discovery, and persisting pickles) is **out of scope for this
scaffold** and is left as a clearly-marked follow-up. The security-critical
identity binding (`SignedPrekeyBundle` signing + verification) is fully
implemented and tested; only the transport plumbing is deferred. See the
crate-level module docs for the exact follow-up steps.

## License

Apache-2.0.
