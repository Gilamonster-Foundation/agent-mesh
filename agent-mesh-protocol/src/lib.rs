//! Cryptographic primitives for the agent-mesh.
//!
//! This crate provides the identity layer the rest of the workspace
//! builds on:
//!
//! * [`UserKey`] — root of trust, one ed25519 keypair per user.
//! * [`AgentKey`] — short-lived per-process sub-key, certified by a
//!   `UserKey` via a [`CertChain`].
//! * [`GitHubBinding`] — cross-signature linking a `UserKey` to the
//!   ed25519 SSH key GitHub already knows about.
//! * [`SignedEnvelope`] — the wire format every mesh message is
//!   wrapped in.
//! * [`Fingerprint`] — short BLAKE3 identifier for keys and content.
//!
//! All wall-clock time in this crate is treated as a *claim* (e.g.
//! `AgentMetadata::issued_at`), never as a coordination primitive.
//! See the project `CLAUDE.md` for the rationale.

#![doc(html_root_url = "https://docs.rs/agent-mesh-protocol")]

pub mod agent_key;
pub mod caveats;
pub mod envelope;
pub mod error;
pub mod fingerprint;
pub mod github_binding;
pub mod user_key;

#[cfg(feature = "pyo3")]
pub mod pyo3_module;

pub use agent_key::{AgentKey, AgentMetadata, CertChain, Issuer, SerdeSig};
pub use caveats::{Caveats, CountBound, Scope};
pub use envelope::{Recipient, SignedEnvelope};
pub use error::{MeshError, Result};
pub use fingerprint::Fingerprint;
pub use github_binding::{ssh_pubkey_ed25519_bytes, GitHubBinding};
pub use user_key::{UserKey, UserPublic};
