//! The flock server: owns one flock's signed, append-only log.
//!
//! The pure model (schema, admission table, fold) lives in `agent-mesh-flock`
//! and is reused as-is. This crate adds the I/O around it: minting the server
//! key and genesis ([`init`]), the exclusive log lock, one admission
//! transaction per [`Server::admit`], and recovery that cuts off only a torn
//! final frame and fails closed on anything else.
//!
//! Who may sign is derived from the log itself ([`Sessions`]): invites,
//! enrollment, session end, the epoch ratchet and renewal are events, so a
//! fresh reader rebuilds the same table in replay order.

mod chain;
mod entry;
mod error;
mod frame;
mod init;
mod keyfile;
mod lock;
mod log;
mod refusal;
mod server;
mod sessions;
mod state;

pub use chain::{verify_record, Chain};
pub use entry::{Enrolled, Invited};
pub use error::ServerError;
pub use frame::{cert_cid, encode, seal, AdmissionRecord, Frame, Sealed};
pub use init::{
    init, load_genesis, InitSpec, SignedGenesis, GENESIS_FILE, KEY_FILE, LOG_FILE, REFUSALS_FILE,
};
pub use keyfile::{load_server_key, store_server_key};
pub use log::CrashPlan;
pub use refusal::{Reason, RefusalEntry, RefusalRecord};
pub use server::{Receipt, Server};
pub use sessions::{session_caveats, token_digest, InviteInfo, SessionInfo, Sessions, Status};
