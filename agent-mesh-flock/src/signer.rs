//! Who signed an event, as the caller has already established it.

use agent_mesh_protocol::Fingerprint;

/// The class of key that signed, resolved by the caller from the certificate
/// at the current epoch and the session table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerClass {
    /// The key is genesis's server key.
    Server,
    /// A harness session of roster member `member`. `pending` sessions are
    /// replacements not yet activated by a hand-off; they sign nothing.
    Session {
        /// Roster member name the session belongs to.
        member: String,
        /// Not yet activated.
        pending: bool,
    },
    /// An operator device key certified by the same user key.
    Operator,
}

/// A verified signer: the author fingerprint and its class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// Fingerprint of the signing agent key; must equal the event's `author`.
    pub fingerprint: Fingerprint,
    /// Its class.
    pub class: SignerClass,
}
