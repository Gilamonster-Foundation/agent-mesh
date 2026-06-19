//! Crate-wide error type for `agent-mesh-protocol`.
//!
//! Every fallible operation in this crate returns [`Result<T>`] (an
//! alias for `Result<T, MeshError>`). The variants are deliberately
//! coarse — they cover *what* went wrong well enough that the CLI can
//! print a useful message, without forcing every caller to enumerate
//! a giant matrix of internal failure modes.

use thiserror::Error;

/// Errors that can arise from agent-mesh primitives.
#[derive(Debug, Error)]
pub enum MeshError {
    /// Underlying I/O failure (file read/write, permission, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A key blob (private or public) was malformed or rejected by
    /// the underlying crypto library.
    #[error("invalid key format: {0}")]
    InvalidKey(String),

    /// An ed25519 signature failed to verify against its claimed key
    /// and message.
    #[error("signature verification failed")]
    BadSignature,

    /// A cert chain was structurally valid but semantically wrong —
    /// e.g. the user pubkey didn't sign the embedded metadata.
    #[error("invalid cert chain: {0}")]
    InvalidCertChain(String),

    /// A delegated agent's caveats are not `⊑` its parent's — delegation is
    /// attenuation-only, so a child may never grant more authority than the
    /// parent it chains to.
    #[error(
        "caveat amplification: a delegated agent may not grant more authority than its parent"
    )]
    CaveatAmplification,

    /// A cert's causal-generation scope could not be honoured (§9.1). Either it
    /// was verified context-free (`verify()`) while declaring a *bounded*
    /// `valid_for_generation` — which cannot be checked without a current
    /// generation, so it is refused rather than ignored (fail-closed) — or its
    /// scope does not include the supplied generation. Causal generation is the
    /// authoritative revocation axis (wall-clock is not).
    #[error("generation: {0}")]
    Generation(String),

    /// A credential or envelope was rejected because it claims an
    /// expired validity window.
    #[error("expired: {0}")]
    Expired(String),

    /// A wire envelope was structurally malformed (wrong shape, wrong
    /// CID, missing fields).
    #[error("malformed envelope: {0}")]
    MalformedEnvelope(String),

    /// A duplicate nonce was observed (replay detection).
    #[error("replay detected: nonce already seen")]
    Replay,

    /// An envelope arrived with the wrong sequence number for its
    /// sender's session.
    #[error("sequence error: expected {expected}, got {actual}")]
    BadSequence { expected: u64, actual: u64 },

    /// A serialization/deserialization failure (hex, serde, etc.).
    #[error("encoding error: {0}")]
    Encoding(String),
}

/// Convenience alias for the crate's `Result` type.
pub type Result<T> = std::result::Result<T, MeshError>;
