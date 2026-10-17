//! The flock session process: holds one session key in memory (locked, no
//! core dumps, zeroized on exit) and serves the CLI over a 0600 socket.
//!
//! The socket keeps out other Unix users, not other harnesses under the same
//! account; that boundary is agent-bridle's. Unix only: elsewhere the crate
//! builds empty.
#![cfg(unix)]

mod ctl;
mod error;
mod harden;
mod locked;
mod session;

pub use ctl::{call, CtlReq, CtlResp};
pub use error::SessionError;
pub use harden::{harden, Hardening, Policy};
pub use locked::Locked;
pub use session::{run, Session};
