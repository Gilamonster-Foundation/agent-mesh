//! Error type for the ratchet layer.

use thiserror::Error;

/// Errors raised by [`crate`]'s ratchet operations.
#[derive(Debug, Error)]
pub enum RatchetError {
    /// The signed prekey bundle's signature did not verify against the
    /// claimed agent-mesh identity, or the embedded cert chain is invalid.
    #[error("prekey bundle authenticity check failed: {0}")]
    BundleVerification(String),

    /// A peer's prekey bundle was missing the one-time prekey required to
    /// open an outbound session.
    #[error("prekey bundle has no one-time prekey available")]
    NoOneTimeKey,

    /// vodozemac refused to create a session from the supplied keys.
    #[error("session establishment failed: {0}")]
    SessionCreation(String),

    /// vodozemac refused to encrypt a plaintext.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// vodozemac refused to decrypt a ciphertext (wrong key, replay after
    /// ratchet advance, corruption, or a tampered message).
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// A `RatchetMessage` could not be parsed back into an Olm message
    /// (corrupted or truncated wire bytes).
    #[error("malformed ratchet message: {0}")]
    MalformedMessage(String),

    /// An inbound session was expected to open from a pre-key message but
    /// the supplied message was a normal (post-handshake) message.
    #[error("expected a pre-key message to open an inbound session")]
    NotAPreKeyMessage,

    /// A Curve25519 key in a bundle was not valid wire-format bytes.
    #[error("invalid curve25519 key in bundle: {0}")]
    InvalidCurveKey(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, RatchetError>;
