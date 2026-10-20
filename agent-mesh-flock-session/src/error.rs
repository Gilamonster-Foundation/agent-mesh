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

/// Why reading a flock failed.
#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    /// A live process holds `reader.lock` in this state directory. A file
    /// left behind by an interrupted save is not a holder and does not cause
    /// this.
    #[error("the lock on this reader state directory is already held (reader.lock)")]
    Locked,
    /// The server's history is not an extension of the saved head: shorter,
    /// rewritten, or with an altered prefix. Never resynchronized silently.
    #[error("rollback: {0}")]
    Rollback(String),
    /// A frame, or the saved state, does not verify.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The stream was refused or ended.
    #[error("stream: {0}")]
    Stream(String),
    /// Socket or file error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A verified frame could not be saved. The reader is back at its last
    /// saved prefix: nothing that was not saved is kept or shown.
    #[error("cannot save the checkpoint: {0}")]
    Save(std::io::Error),
    /// Wire or encoding error.
    #[error("{0}")]
    Wire(#[from] agent_mesh_flock_server::ServerError),
}

#[cfg(test)]
mod tests {
    use super::ReaderError;

    #[test]
    fn the_locked_message_names_the_lock_and_the_file() {
        assert_eq!(
            ReaderError::Locked.to_string(),
            "the lock on this reader state directory is already held (reader.lock)"
        );
    }
}
