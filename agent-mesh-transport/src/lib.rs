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
//!    exchange [`agent_mesh_protocol::CertChain`]s and enforce the
//!    auto-team rule: same `user_pubkey` → trust, else refuse with
//!    a clear error (see [`handshake`]).
//! 3. **Envelope framing** — once trusted, each direction is a stream
//!    of length-prefixed [`agent_mesh_protocol::SignedEnvelope`]s,
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
pub mod resolver;
pub mod stream;

#[cfg(feature = "pyo3")]
pub mod pyo3_module;

pub use alpn::ALPN;
pub use endpoint::Endpoint;
pub use error::{Result, TransportError};
pub use handshake::{do_handshake, HelloMsg, RejectMsg};
pub use resolver::{PeerResolver, ResolverHandle};
pub use stream::{recv_envelope, send_envelope, MAX_ENVELOPE_BYTES};

/// Re-exports from `iroh` that callers regularly need but shouldn't
/// have to add iroh as a direct dep for. Keep this list minimal — if
/// a caller starts reaching into `iroh::*` directly the right answer
/// is usually a new wrapper in this crate.
pub mod iroh_reexports {
    pub use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream};
    pub use iroh::PublicKey;
}
