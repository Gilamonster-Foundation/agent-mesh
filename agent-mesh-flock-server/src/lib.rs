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

#[cfg(unix)]
mod beneath;
mod chain;
#[cfg(unix)]
mod cite;
#[cfg(feature = "serve")]
mod entry;
mod error;
#[cfg(all(unix, feature = "serve"))]
mod files;
mod follow;
mod frame;
mod init;
mod journal;
#[cfg(feature = "serve")]
mod keyfile;
#[cfg(feature = "serve")]
mod lock;
mod log;
#[cfg(unix)]
mod private;
mod read;
mod refusal;
#[cfg(all(unix, feature = "serve"))]
mod serve;
#[cfg(feature = "serve")]
mod server;
mod sessions;
mod state;
pub mod wire;

#[cfg(unix)]
pub use beneath::Beneath;
pub use chain::{verify_record, Chain};
#[cfg(unix)]
pub use cite::{file_id, MAX_CITED_BYTES};
#[cfg(feature = "serve")]
pub use entry::{Enrolled, Invited};
pub use error::ServerError;
pub use follow::{FollowError, Follower};
#[cfg(feature = "serve")]
pub use frame::seal;
pub use frame::{cert_cid, encode, AdmissionRecord, Frame, Sealed};
#[cfg(feature = "serve")]
pub use init::{init, InitSpec};
pub use init::{
    load_genesis, verify_signed_genesis, SignedGenesis, GENESIS_FILE, KEY_FILE, LOG_FILE,
    REFUSALS_FILE,
};
#[cfg(feature = "serve")]
pub use journal::{Cursor, Eligible, Journal, Published};
pub use journal::{Head, Resume};
#[cfg(feature = "serve")]
pub use keyfile::{load_server_key, store_server_key};
#[cfg(feature = "serve")]
pub use log::CrashPlan;
#[cfg(unix)]
pub use private::{bind_private, peer_ok, private_dir, uid_allowed};
pub use read::Snapshot;
pub use refusal::{Reason, RefusalEntry, RefusalRecord};
#[cfg(all(unix, feature = "serve"))]
pub use serve::{serve, serve_with_attach, Serving};
#[cfg(feature = "serve")]
pub use server::{Receipt, Server};
pub use sessions::{session_caveats, token_digest, InviteInfo, SessionInfo, Sessions, Status};
