//! LAN discovery for agent-mesh via mDNS.
//!
//! Service type: `_agent-mesh._udp.local.`
//!
//! Each agent advertises itself with a TXT record carrying:
//!
//! - `agent_fp` — BLAKE3 fingerprint of the agent's pubkey (hex)
//! - `user_fp`  — BLAKE3 fingerprint of the user's pubkey (hex)
//! - `caps`     — comma-separated capability list
//! - `role`     — agent role (e.g. `"inference-worker"`)
//! - `host`     — agent host hint
//!
//! mDNS TXT records are tiny (~255 bytes per key, ~9 KB aggregate); we
//! send fingerprints only, not full cert chains. A peer that wants to
//! connect uses `agent_fp` to fetch the full public key via Phase 2's
//! transport handshake.
//!
//! Phase 1 surface is intentionally narrow:
//!
//! * [`Announcer`] starts an mDNS responder for this agent and stays
//!   alive until its [`AnnouncerHandle`] is dropped.
//! * [`Browser`] starts an mDNS browser and emits resolved
//!   [`PeerInfo`] records over a tokio `mpsc` channel.
//!
//! Phase 2 will add the transport that uses these fingerprints to
//! open authenticated sessions.

#![doc(html_root_url = "https://docs.rs/agent-mesh-discovery")]

pub mod announce;
pub mod browse;
pub mod peer;

#[cfg(feature = "pyo3")]
pub mod pyo3_module;

pub use announce::{AnnounceConfig, Announcer, AnnouncerHandle};
pub use browse::{Browser, BrowserEvent, BrowserHandle};
pub use peer::PeerInfo;

/// Service type for agent-mesh discovery.
pub const SERVICE_TYPE: &str = "_agent-mesh._udp.local.";

/// Default discovery port. `0` means "discovery only, no transport
/// listening yet" — Phase 2 will set this to a real listening port.
pub const DEFAULT_PORT: u16 = 0;
