//! Who signed an event: the seam between the log and the session table.

use agent_mesh_flock::{Board, Signer, SignerClass};
use agent_mesh_protocol::{Assertion, Fingerprint};
use content_addressable::ContentId;

/// Turns an event's detached signature into a [`Signer`], or refuses it.
///
/// Implementations verify the assertion at `epoch` (certificate chain rooted
/// at `server_pub`) and resolve the class. Step 4 supplies one backed by the
/// session table the log defines.
pub trait SignerResolver: Send {
    /// Resolve `sig` over `event` at `epoch`.
    ///
    /// # Errors
    /// A reason string when the signature or the signer is not acceptable.
    fn resolve(
        &self,
        board: &Board,
        server_pub: &[u8; 32],
        sig: &Assertion,
        event: &ContentId,
        epoch: u64,
    ) -> Result<Signer, String>;
}

/// The step-3 resolver: only the server's own key may sign.
#[derive(Debug, Default, Clone, Copy)]
pub struct ServerOnly;

impl SignerResolver for ServerOnly {
    fn resolve(
        &self,
        _board: &Board,
        server_pub: &[u8; 32],
        sig: &Assertion,
        event: &ContentId,
        epoch: u64,
    ) -> Result<Signer, String> {
        if &sig.author().agent_pubkey != server_pub {
            return Err("not the server key".into());
        }
        sig.verify(event, server_pub, epoch)
            .map_err(|e| e.to_string())?;
        Ok(Signer {
            fingerprint: Fingerprint::of_bytes(server_pub),
            class: SignerClass::Server,
        })
    }
}
