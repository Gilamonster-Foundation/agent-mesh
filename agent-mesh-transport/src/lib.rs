//! Authenticated QUIC transport for agent-mesh, built on
//! [iroh](https://docs.rs/iroh).
//!
//! Phase 2 layers three things on top of QUIC's TLS handshake:
//!
//! 1. **Identity binding** — the agent's ed25519 signing key doubles
//!    as the iroh `EndpointId`, so a peer who knows your agent
//!    fingerprint already knows enough to address your iroh endpoint
//!    (see [`identity`]).
//! 2. **App-level handshake** — after ALPN negotiation, both ends
//!    exchange [`agent_mesh_core::CertChain`]s and enforce the
//!    auto-team rule: same `user_pubkey` → trust, else refuse with
//!    a clear error (see [`handshake`]).
//! 3. **Envelope framing** — once trusted, each direction is a stream
//!    of length-prefixed [`agent_mesh_core::SignedEnvelope`]s,
//!    verified on receipt (see [`stream`]).
//!
//! [`PeerResolver`] bridges Phase 1 mDNS discovery to this layer so
//! callers can dial by fingerprint without managing the browser
//! themselves.

#![doc(html_root_url = "https://docs.rs/agent-mesh-transport")]

pub mod alpn;
pub mod endpoint;
pub mod error;
pub mod handshake;
pub mod identity;

pub use alpn::ALPN;
pub use endpoint::Endpoint;
pub use error::{Result, TransportError};
pub use handshake::{do_handshake, HelloMsg, RejectMsg};
