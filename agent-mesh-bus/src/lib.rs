//! High-level pub/sub + request-reply over the agent-mesh transport.
//!
//! This commit lands the application-level message dispatch surface
//! ([`Inbox`], [`BusMessage`]). The high-level [`Bus`] type that
//! drives it lands in the next commit.
//!
//! What's already in place from prior commits:
//!
//! 1. **Topic namespacing** ([`Topic`]) — every pub/sub name is
//!    scoped to the issuing user's fingerprint, so two unrelated
//!    users on the same LAN can never collide.
//! 2. **Replay defense** ([`replay::NonceCache`] +
//!    [`replay::SequenceTracker`]) — duplicate nonces and
//!    out-of-order sequence numbers from a known peer are rejected.

#![doc(html_root_url = "https://docs.rs/agent-mesh-bus")]

pub mod bus;
pub mod error;
pub mod inbox;
pub mod replay;
pub mod reply;
pub mod topic;

#[cfg(feature = "pyo3")]
pub mod pyo3_module;

pub use bus::Bus;
pub use error::{BusError, Result};
pub use inbox::{BusMessage, Inbox, OutgoingReply};
pub use reply::CorrelationId;
pub use topic::Topic;
