//! AgentKey-authenticated Agent Mesh sessions carried over OpenSSH.
//!
//! OpenSSH supplies an encrypted, access-controlled byte stream. A separate
//! inner protocol mutually proves live possession of each peer's certified
//! AgentKey before this crate can construct
//! [`agent_mesh_bus::AuthenticatedPeer`]. Post-authentication records are
//! cryptographically bound to the fresh transcript, direction, counter, and
//! exact envelope bytes. The bus remains responsible for independently
//! verifying the [`agent_mesh_protocol::SignedEnvelope`] and requiring its
//! signer to equal the transport-authenticated carrier.
//!
//! The SSH username, authorized SSH key, SSH host key, and AgentKey are
//! distinct identities. The system `ssh -W` interface does not expose an SSH
//! channel-binding value or the accepted client credential, so this crate does
//! not claim that those identities are cryptographically co-bound.

pub mod error;
pub mod process;
pub mod session;
pub mod transport;

pub use error::{Result, SshTransportError};
pub use process::{HostKeyPolicy, OpenSshClient, SshTarget};
pub use session::{
    AuthenticatedMeshSession, AuthenticatedSessionReader, AuthenticatedSessionWriter, SessionError,
    SessionParameters, SessionRole, SessionTimeouts, UnauthenticatedMeshSession,
    MAX_ENVELOPE_BYTES, MAX_HANDSHAKE_BYTES,
};
pub use transport::{SshTransport, SshTransportOptions};
