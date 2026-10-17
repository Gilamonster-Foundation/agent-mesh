//! The flock server: owns one flock's signed, append-only log.
//!
//! The pure model (schema, admission table, fold) lives in `agent-mesh-flock`
//! and is reused as-is. This crate adds the I/O around it: minting the server
//! key and genesis ([`init`]), the exclusive log lock, one admission
//! transaction per [`Server::admit`], and recovery that cuts off only a torn
//! final frame and fails closed on anything else.
//!
//! Sessions, invites and epoch bumps are step 4: until then the only signer
//! the default resolver knows is the server's own key; a [`SignerResolver`]
//! is the seam step 4 fills with the log-derived session table.

mod chain;
mod error;
mod frame;
mod init;
mod keyfile;
mod lock;
mod log;
mod refusal;
mod resolve;
mod server;

pub use chain::{verify_entry, Chain};
pub use error::ServerError;
pub use frame::{cert_cid, encode, seal, AdmissionRecord, Frame, Sealed};
pub use init::{
    init, load_genesis, InitSpec, SignedGenesis, GENESIS_FILE, KEY_FILE, LOG_FILE, REFUSALS_FILE,
};
pub use keyfile::{load_server_key, store_server_key};
pub use log::CrashPlan;
pub use refusal::{Reason, RefusalEntry, RefusalRecord};
pub use resolve::{ServerOnly, SignerResolver};
pub use server::{Receipt, Server};
