//! One error type.

/// Why a session operation failed.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Socket or OS error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The server's wire or storage layer failed.
    #[error("{0}")]
    Server(#[from] agent_mesh_flock_server::ServerError),
    /// The server refused.
    #[error("refused: {0}")]
    Refused(String),
    /// The server answered something this request cannot get.
    #[error("unexpected answer from the server")]
    Unexpected,
    /// Hardening failed and the policy is to refuse.
    #[error("cannot protect the key: {0}")]
    Unprotected(String),
}
