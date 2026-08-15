//! Crate-wide error type for `agent-mesh-transport-ssh`.
//!
//! OpenSSH's exit status and diagnostics are intentionally reported as
//! process evidence, not interpreted as proof that a particular SSH
//! authentication or host-key check failed.  Those diagnostics are localized
//! and are not a stable machine-readable protocol.

use thiserror::Error;

/// Errors that can arise from the SSH transport layer.
#[derive(Debug, Error)]
pub enum SshTransportError {
    /// A target or client setting was unsafe or unusable.
    #[error("invalid SSH configuration: {0}")]
    InvalidConfig(String),

    /// The mesh authentication protocol failed after the SSH process started.
    #[error("inner mesh authentication failed: {message}; ssh stderr: {stderr}")]
    InnerAuth {
        /// The inner protocol failure.
        message: String,
        /// A bounded tail of OpenSSH's diagnostic stream.
        stderr: String,
    },

    /// A bounded operation did not finish in time.
    #[error("SSH timeout during {stage}")]
    Timeout {
        /// The operation that reached its deadline.
        stage: String,
    },

    /// OpenSSH did not exit within a bounded process-supervision deadline.
    #[error("SSH process timeout during {stage}; ssh stderr: {stderr}")]
    ProcessTimeout {
        /// The process operation that reached its deadline.
        stage: String,
        /// A bounded tail of OpenSSH's diagnostic stream.
        stderr: String,
    },

    /// An SSH or mesh framing failure.
    #[error("SSH frame error: {0}")]
    Frame(String),

    /// The OpenSSH subprocess exited.
    ///
    /// `status` is `None` when the platform cannot represent the termination
    /// as an exit code (for example, termination by signal on Unix), or when
    /// waiting for the process itself failed. `stderr` is always bounded by
    /// the process layer.
    #[error("ssh process exited during {context} (status {status:?}): {stderr}")]
    ProcessExit {
        /// Portable numeric exit code, when one exists.
        status: Option<i32>,
        /// A bounded tail of OpenSSH's diagnostic stream.
        stderr: String,
        /// The operation in progress when the child exited.
        context: String,
    },

    /// The authenticated inner peer did not match the selected peer.
    #[error("SSH mesh peer mismatch: expected {expected}, got {actual}")]
    PeerMismatch {
        /// Configured peer identity.
        expected: String,
        /// Identity proven by the inner handshake.
        actual: String,
    },

    /// The byte stream closed before the current operation completed.
    #[error("SSH carrier closed")]
    Closed,

    /// Raw process or stream I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A protocol certificate, signature, or envelope operation failed.
    #[error("core error: {0}")]
    Core(#[from] agent_mesh_protocol::MeshError),
}

/// Convenience alias for the crate's `Result` type.
pub type Result<T> = std::result::Result<T, SshTransportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_exit_preserves_evidence_without_guessing_cause() {
        let error = SshTransportError::ProcessExit {
            status: Some(255),
            stderr: "localized diagnostic".into(),
            context: "inner authentication".into(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("255"));
        assert!(rendered.contains("localized diagnostic"));
        assert!(!rendered.contains("host key verification failed"));
        assert!(!rendered.contains("SSH authentication failed"));
    }

    #[test]
    fn io_error_converts_via_from() {
        let io = std::io::Error::other("eof");
        let error: SshTransportError = io.into();
        assert!(matches!(error, SshTransportError::Io(_)));
    }

    #[test]
    fn core_error_converts_via_from() {
        let core_error = agent_mesh_protocol::MeshError::BadSignature;
        let error: SshTransportError = core_error.into();
        assert!(matches!(error, SshTransportError::Core(_)));
    }
}
