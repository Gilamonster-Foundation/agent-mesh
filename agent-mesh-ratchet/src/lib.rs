//! Signal-style Double Ratchet for 1:1 agent-mesh sessions.
//!
//! This crate adds **message-layer** forward secrecy (FS) and
//! post-compromise security (PCS) to the agent-mesh, on top of the
//! transport-layer guarantees that [`agent_mesh_protocol::SignedEnvelope`]
//! and the bus already provide. The mesh's signed, replay-defended envelopes
//! authenticate *who sent a frame*; the ratchet ensures that *the contents of
//! a long-lived 1:1 conversation* stay confidential even if a session key
//! leaks later (FS) and that the conversation self-heals after a compromise
//! (PCS).
//!
//! ## Crypto core
//!
//! The ratchet itself is **not** hand-rolled. It is
//! [`vodozemac`](https://crates.io/crates/vodozemac), Matrix's audited Rust
//! implementation of Olm/Megolm. We use the **Olm** 1:1 primitives — Olm is a
//! libsignal-style Double Ratchet (X3DH handshake + symmetric-key ratchet +
//! DH ratchet). This crate is a thin, documented wrapper that binds those
//! primitives to the mesh identity layer.
//!
//! ## Identity binding (this is the load-bearing part)
//!
//! Olm has its own Curve25519 identity keys, unrelated to the agent-mesh
//! ed25519 identity ([`agent_mesh_protocol::AgentKey`] /
//! [`agent_mesh_protocol::UserKey`]). Left alone, Olm answers "can we talk
//! securely?" but **not** "are you the agent the mesh vouches for?".
//!
//! [`SignedPrekeyBundle`] closes that gap: the publisher's Olm Curve25519
//! identity + a one-time prekey are signed by their mesh [`AgentKey`], and the
//! bundle embeds the agent's [`agent_mesh_protocol::CertChain`] (which roots
//! at a [`agent_mesh_protocol::UserKey`]). A peer verifies the bundle against
//! the [`agent_mesh_protocol::Fingerprint`] of the user it already trusts
//! before opening a session — so the Olm handshake is anchored to the mesh's
//! web of trust, not to whatever Curve25519 key an attacker hands over.
//!
//! ## Usage
//!
//! ```rust
//! use agent_mesh_protocol::{AgentKey, AgentMetadata, Caveats, UserKey};
//! use agent_mesh_ratchet::RatchetAccount;
//!
//! fn metadata(role: &str) -> AgentMetadata {
//!     AgentMetadata {
//!         role: role.into(),
//!         host: "host-a".into(),
//!         capabilities: vec![],
//!         // Wall-clock here is a signed *claim*, not a coordination
//!         // primitive — a fixed string is fine.
//!         issued_at: "2026-06-08T00:00:00Z".into(),
//!         expires_at: None,
//!         caveats: Caveats::top(),
//!     }
//! }
//!
//! // Two users, each with one agent identity.
//! let alice_user = UserKey::generate();
//! let bob_user = UserKey::generate();
//! let alice_agent = AgentKey::issue(&alice_user, metadata("alice"));
//! let bob_agent = AgentKey::issue(&bob_user, metadata("bob"));
//!
//! // Both sides publish a signed prekey bundle authenticated by their agent
//! // key. (Bob's is consumed by Alice's outbound handshake; Alice's lets Bob
//! // bind the inbound session to her verified Olm identity.)
//! let mut alice_acct = RatchetAccount::new();
//! alice_acct.generate_one_time_keys(1);
//! let alice_bundle = alice_acct.signed_prekey_bundle(&alice_agent).unwrap();
//!
//! let mut bob_acct = RatchetAccount::new();
//! bob_acct.generate_one_time_keys(1);
//! let bob_bundle = bob_acct.signed_prekey_bundle(&bob_agent).unwrap();
//!
//! // Alice verifies Bob's bundle against the user she trusts, opens a
//! // session, and sends the first (pre-key) message.
//! let mut alice_session = alice_acct
//!     .initiate(&bob_bundle, &bob_user.fingerprint())
//!     .unwrap();
//! let first = alice_session.encrypt(b"hello bob").unwrap();
//!
//! // Bob verifies Alice's bundle to learn her authenticated Olm identity,
//! // then accepts the first message — recovering the plaintext and an
//! // established session in one step.
//! let (alice_identity, _otk) = alice_bundle.verify(&alice_user.fingerprint()).unwrap();
//! let (mut bob_session, plaintext) = bob_acct.accept(alice_identity, &first).unwrap();
//! assert_eq!(plaintext, b"hello bob");
//!
//! // The ratchet advances both directions.
//! let reply = bob_session.encrypt(b"hi alice").unwrap();
//! assert_eq!(alice_session.decrypt(&reply).unwrap(), b"hi alice");
//! ```
//!
//! See the round-trip integration tests for the full two-party flow.
//!
//! ## Bus integration — TODO (deliberately not faked)
//!
//! Wiring [`RatchetMessage`] into `agent-mesh-bus` (placing the ratchet
//! ciphertext inside a [`agent_mesh_protocol::SignedEnvelope`], routing by
//! [`RatchetSession::session_id`], and persisting session/account pickles) is
//! **out of scope for this scaffold**. The seam is intentionally clean:
//! `RatchetMessage` is serde-serializable and self-describing, and
//! `RatchetAccount`/`RatchetSession` pickle via vodozemac. A follow-up phase
//! should:
//!
//! 1. carry a `RatchetMessage` as the payload of a `SignedEnvelope`;
//! 2. publish/fetch [`SignedPrekeyBundle`]s over the discovery/bus layer;
//! 3. persist account + session pickles alongside the mesh's other key state.
//!
//! No part of step 1–3 is stubbed here — the `SignedPrekeyBundle` signing and
//! verification *are* fully implemented and tested, because they are the
//! security-critical identity binding; only the transport plumbing is
//! deferred.

#![doc(html_root_url = "https://docs.rs/agent-mesh-ratchet")]
#![forbid(unsafe_code)]

mod account;
mod bundle;
mod error;
mod message;
mod session;

pub use account::RatchetAccount;
pub use bundle::SignedPrekeyBundle;
pub use error::{RatchetError, Result};
pub use message::RatchetMessage;
pub use session::RatchetSession;

// Re-export the vodozemac types that appear in this crate's public API, so
// downstream consumers don't have to depend on vodozemac directly or guess
// its version.
pub use vodozemac::olm::AccountPickle;
pub use vodozemac::Curve25519PublicKey;
