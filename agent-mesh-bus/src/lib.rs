//! High-level pub/sub + request-reply over the agent-mesh transport.
//!
//! This file is scaffolded incrementally across the Phase 3 commits.
//! At this checkpoint the crate provides the supporting types only
//! ([`Topic`], [`replay::NonceCache`], [`replay::SequenceTracker`],
//! [`CorrelationId`], [`BusError`]). The application surface
//! ([`Inbox`], [`Bus`]) lands in the next commits.

#![doc(html_root_url = "https://docs.rs/agent-mesh-bus")]

pub mod error;
pub mod replay;
pub mod reply;
pub mod topic;

pub use error::{BusError, Result};
pub use reply::CorrelationId;
pub use topic::Topic;
