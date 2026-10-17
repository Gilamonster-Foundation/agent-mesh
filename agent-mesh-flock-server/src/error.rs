//! One error type for the whole crate.

use agent_mesh_flock::Refusal;

/// Why a server operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// A filesystem error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Another process holds the log.
    #[error("the log is locked by another server")]
    Locked,
    /// The flock directory is already initialised.
    #[error("{0} already exists; a flock is initialised once")]
    AlreadyInitialised(String),
    /// The key file is readable by group or others.
    #[error("key file is not mode 0600")]
    KeyFileMode,
    /// The key file or genesis does not hold together.
    #[error("bad flock files: {0}")]
    BadFiles(String),
    /// Committed history is damaged or not an honest server's chain.
    #[error("log corrupt at byte {offset}: {why}")]
    Corrupt {
        /// Byte offset of the frame.
        offset: u64,
        /// What failed.
        why: String,
    },
    /// The signature did not resolve to a signer the server accepts.
    #[error("signer refused: {0}")]
    Signer(String),
    /// The admission table refused the event.
    #[error("refused: {0:?}")]
    Refused(Refusal),
    /// An earlier write failed; reopen the server to recover.
    #[error("the server stopped after a failed write; reopen to recover")]
    Poisoned,
    /// Encoding failed.
    #[error("encoding: {0}")]
    Encoding(String),
}
