//! Python bindings for `agent-mesh-core`.
//!
//! Compiled only when the `pyo3` cargo feature is on; the rest of the
//! crate has no Python dependencies. The umbrella `agent-mesh-py`
//! crate is the one consumer that turns this on.
//!
//! Exposes the core identity types — keys, certs, envelopes,
//! fingerprints — as Python classes wrapped around the existing Rust
//! values. Cryptographic behavior is unchanged from the Rust API;
//! these are thin owning wrappers.

use crate::{
    agent_key::{AgentKey, AgentMetadata, CertChain},
    envelope::{Recipient, SignedEnvelope},
    fingerprint::Fingerprint,
    github_binding::{ssh_pubkey_ed25519_bytes, GitHubBinding},
    user_key::{UserKey, UserPublic},
    MeshError,
};
use ed25519_dalek::Signature;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyType};
use ssh_key::PrivateKey as SshPrivateKey;
use std::path::PathBuf;

create_exception!(_agent_mesh, PyMeshError, PyException);

/// Convert a `MeshError` into the Python-side `MeshError` exception.
fn mesh_err_to_py(e: MeshError) -> PyErr {
    PyMeshError::new_err(e.to_string())
}

// ---- Fingerprint ----

/// 32-byte BLAKE3 fingerprint of a key or content blob.
#[pyclass(
    name = "Fingerprint",
    module = "agent_mesh._agent_mesh.core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyFingerprint {
    pub(crate) inner: Fingerprint,
}

#[pymethods]
impl PyFingerprint {
    /// Build a `Fingerprint` from a 64-char hex string.
    #[classmethod]
    fn from_hex(_cls: &Bound<'_, PyType>, s: &str) -> PyResult<Self> {
        let inner: Fingerprint = s.parse().map_err(mesh_err_to_py)?;
        Ok(Self { inner })
    }

    /// Build a `Fingerprint` from raw 32 bytes.
    #[classmethod]
    fn from_bytes(_cls: &Bound<'_, PyType>, data: &[u8]) -> PyResult<Self> {
        if data.len() != 32 {
            return Err(PyMeshError::new_err(format!(
                "expected 32 bytes, got {}",
                data.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(data);
        Ok(Self {
            inner: Fingerprint(arr),
        })
    }

    /// BLAKE3-hash arbitrary bytes into a `Fingerprint`.
    #[classmethod]
    fn of_bytes(_cls: &Bound<'_, PyType>, data: &[u8]) -> Self {
        Self {
            inner: Fingerprint::of_bytes(data),
        }
    }

    /// Full 64-character hex encoding.
    fn hex(&self) -> String {
        self.inner.hex()
    }

    /// 12-character hex prefix for human display.
    fn short(&self) -> String {
        self.inner.short()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        // Truncate the first 8 bytes into a u64 — BLAKE3 output is
        // uniform, so any 64-bit slice is a fine Python hash.
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.inner.0[..8]);
        u64::from_le_bytes(buf)
    }

    fn __str__(&self) -> String {
        self.inner.short()
    }

    fn __repr__(&self) -> String {
        format!("Fingerprint('{}')", self.inner.hex())
    }
}

// ---- UserPublic ----

/// Public verifying half of a `UserKey`. Safe to share with peers.
#[pyclass(
    name = "UserPublic",
    module = "agent_mesh._agent_mesh.core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyUserPublic {
    pub(crate) inner: UserPublic,
}

#[pymethods]
impl PyUserPublic {
    /// BLAKE3 fingerprint of the public key.
    fn fingerprint(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Verify a signature was produced by this user's private key over
    /// `message`. Raises `MeshError` on bad signature.
    fn verify(&self, message: &[u8], signature: &[u8]) -> PyResult<()> {
        if signature.len() != 64 {
            return Err(PyMeshError::new_err(format!(
                "expected 64-byte signature, got {}",
                signature.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(signature);
        let sig = Signature::from_bytes(&arr);
        self.inner.verify(message, &sig).map_err(mesh_err_to_py)
    }

    /// Raw 32-byte ed25519 public key.
    fn as_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.as_bytes())
    }
}

// ---- UserKey ----

/// User-level ed25519 keypair. Root of trust for an agent mesh.
#[pyclass(name = "UserKey", module = "agent_mesh._agent_mesh.core")]
pub struct PyUserKey {
    pub(crate) inner: UserKey,
}

#[pymethods]
impl PyUserKey {
    /// Generate a fresh user key from the OS RNG.
    #[classmethod]
    fn generate(_cls: &Bound<'_, PyType>) -> Self {
        Self {
            inner: UserKey::generate(),
        }
    }

    /// Load a previously-saved key from a PKCS#8 PEM file.
    #[classmethod]
    fn load(_cls: &Bound<'_, PyType>, path: PathBuf) -> PyResult<Self> {
        let inner = UserKey::load(&path).map_err(mesh_err_to_py)?;
        Ok(Self { inner })
    }

    /// BLAKE3 fingerprint of the user's public key.
    fn fingerprint(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Public verifying half of the key.
    fn public(&self) -> PyUserPublic {
        PyUserPublic {
            inner: self.inner.public(),
        }
    }

    /// Sign an arbitrary message with the root key. Returns the
    /// 64-byte ed25519 signature.
    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> Bound<'py, PyBytes> {
        let sig = self.inner.sign(message);
        PyBytes::new(py, &sig.to_bytes())
    }

    /// Save the private key to disk in PKCS#8 PEM with `0600`
    /// permissions. Refuses to overwrite an existing file.
    fn save(&self, path: PathBuf) -> PyResult<()> {
        self.inner.save(&path).map_err(mesh_err_to_py)
    }
}

// ---- AgentMetadata ----

/// Metadata claimed by an agent at certificate-issue time.
#[pyclass(
    name = "AgentMetadata",
    module = "agent_mesh._agent_mesh.core",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct PyAgentMetadata {
    pub(crate) inner: AgentMetadata,
}

#[pymethods]
impl PyAgentMetadata {
    #[new]
    #[pyo3(signature = (role, host, capabilities, issued_at, expires_at = None))]
    fn new(
        role: String,
        host: String,
        capabilities: Vec<String>,
        issued_at: String,
        expires_at: Option<String>,
    ) -> Self {
        Self {
            inner: AgentMetadata {
                role,
                host,
                capabilities,
                issued_at,
                expires_at,
            },
        }
    }

    #[getter]
    fn role(&self) -> &str {
        &self.inner.role
    }

    #[getter]
    fn host(&self) -> &str {
        &self.inner.host
    }

    #[getter]
    fn capabilities(&self) -> Vec<String> {
        self.inner.capabilities.clone()
    }

    #[getter]
    fn issued_at(&self) -> &str {
        &self.inner.issued_at
    }

    #[getter]
    fn expires_at(&self) -> Option<String> {
        self.inner.expires_at.clone()
    }
}

// ---- CertChain ----

/// Proof an agent serves a specific user.
#[pyclass(
    name = "CertChain",
    module = "agent_mesh._agent_mesh.core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyCertChain {
    pub(crate) inner: CertChain,
}

#[pymethods]
impl PyCertChain {
    /// Verify the cert chain. Raises `MeshError` on failure.
    fn verify(&self) -> PyResult<()> {
        self.inner.verify().map_err(mesh_err_to_py)
    }

    /// Fingerprint of the agent's public key.
    fn agent_fingerprint(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.agent_fingerprint(),
        }
    }

    /// Fingerprint of the issuing user's public key.
    fn user_fingerprint(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.user_fingerprint(),
        }
    }
}

// ---- AgentKey ----

/// Short-lived per-agent ed25519 keypair, signed by a `UserKey`.
#[pyclass(name = "AgentKey", module = "agent_mesh._agent_mesh.core")]
pub struct PyAgentKey {
    pub(crate) inner: AgentKey,
}

#[pymethods]
impl PyAgentKey {
    /// Issue a fresh agent key, signed by `user`.
    #[classmethod]
    fn issue(_cls: &Bound<'_, PyType>, user: &PyUserKey, metadata: PyAgentMetadata) -> Self {
        Self {
            inner: AgentKey::issue(&user.inner, metadata.inner),
        }
    }

    /// BLAKE3 fingerprint of the agent's public key.
    fn fingerprint(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Cert chain proving this agent's authority.
    fn cert(&self) -> PyCertChain {
        PyCertChain {
            inner: self.inner.cert().clone(),
        }
    }

    /// Sign a message with the agent's sub-key. Returns 64-byte
    /// ed25519 signature.
    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> Bound<'py, PyBytes> {
        let sig = self.inner.sign(message);
        PyBytes::new(py, &sig.to_bytes())
    }

    /// Raw 32-byte ed25519 public key bytes for this agent.
    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_bytes())
    }
}

// ---- Recipient ----

/// Envelope recipient — direct peer, named topic, or anycast.
///
/// Use the `direct(fp)`, `topic(name)`, or `anycast(cap)` constructors.
#[pyclass(
    name = "Recipient",
    module = "agent_mesh._agent_mesh.core",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct PyRecipient {
    pub(crate) inner: Recipient,
}

#[pymethods]
impl PyRecipient {
    /// Address a single peer by agent-key fingerprint.
    #[classmethod]
    fn direct(_cls: &Bound<'_, PyType>, agent_fp: &PyFingerprint) -> Self {
        Self {
            inner: Recipient::Direct {
                agent_fp: agent_fp.inner,
            },
        }
    }

    /// Address a user-scoped pub/sub topic.
    #[classmethod]
    fn topic(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self {
            inner: Recipient::Topic { name },
        }
    }

    /// Address any agent claiming the named capability.
    #[classmethod]
    fn anycast(_cls: &Bound<'_, PyType>, capability: String) -> Self {
        Self {
            inner: Recipient::Anycast { capability },
        }
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            Recipient::Direct { agent_fp } => format!("Recipient.direct({})", agent_fp.short()),
            Recipient::Topic { name } => format!("Recipient.topic('{name}')"),
            Recipient::Anycast { capability } => format!("Recipient.anycast('{capability}')"),
        }
    }
}

// ---- SignedEnvelope ----

/// Wire envelope, signed by the sender's agent key.
#[pyclass(
    name = "SignedEnvelope",
    module = "agent_mesh._agent_mesh.core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PySignedEnvelope {
    pub(crate) inner: SignedEnvelope,
}

#[pymethods]
impl PySignedEnvelope {
    /// Build and sign a fresh envelope.
    #[new]
    fn new(sender: &PyAgentKey, recipient: PyRecipient, sequence: u64, payload: Vec<u8>) -> Self {
        Self {
            inner: SignedEnvelope::new(&sender.inner, recipient.inner, sequence, payload),
        }
    }

    /// Verify cert chain, payload CID, and agent signature.
    fn verify(&self) -> PyResult<()> {
        self.inner.verify().map_err(mesh_err_to_py)
    }

    /// Fingerprint of the sending agent.
    fn sender_agent_fp(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.sender_agent_fp(),
        }
    }

    /// Fingerprint of the user the sender belongs to.
    fn sender_user_fp(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.sender_user_fp(),
        }
    }

    #[getter]
    fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    /// Raw payload bytes.
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.payload.as_ref())
    }
}

// ---- GitHubBinding ----

/// Cross-signature linking a `UserKey` to a GitHub SSH ed25519 key.
#[pyclass(
    name = "GitHubBinding",
    module = "agent_mesh._agent_mesh.core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyGitHubBinding {
    pub(crate) inner: GitHubBinding,
}

#[pymethods]
impl PyGitHubBinding {
    /// Sign a `UserPublic` with an SSH ed25519 private key (OpenSSH
    /// PEM bytes).
    #[classmethod]
    #[pyo3(signature = (user_public, ssh_private_openssh, github_username = None))]
    fn sign(
        _cls: &Bound<'_, PyType>,
        user_public: &PyUserPublic,
        ssh_private_openssh: &[u8],
        github_username: Option<String>,
    ) -> PyResult<Self> {
        let ssh_key = SshPrivateKey::from_openssh(ssh_private_openssh)
            .map_err(|e| PyMeshError::new_err(format!("parse ssh key: {e}")))?;
        let inner = GitHubBinding::sign(&user_public.inner, &ssh_key, github_username)
            .map_err(mesh_err_to_py)?;
        Ok(Self { inner })
    }

    /// Verify the binding against a candidate SSH ed25519 public key
    /// (raw 32 bytes).
    fn verify(&self, candidate_ssh_pubkey: &[u8]) -> PyResult<()> {
        if candidate_ssh_pubkey.len() != 32 {
            return Err(PyMeshError::new_err(format!(
                "expected 32-byte ssh pubkey, got {}",
                candidate_ssh_pubkey.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(candidate_ssh_pubkey);
        self.inner.verify(&arr).map_err(mesh_err_to_py)
    }
}

/// Helper: extract the raw 32-byte ed25519 public key from an OpenSSH
/// `authorized_keys` line (or `<u>.keys` style content).
#[pyfunction]
fn ssh_authorized_key_to_ed25519_bytes(line: &str) -> PyResult<Vec<u8>> {
    let pub_key = ssh_key::PublicKey::from_openssh(line.trim())
        .map_err(|e| PyMeshError::new_err(format!("parse openssh pubkey: {e}")))?;
    let bytes = ssh_pubkey_ed25519_bytes(&pub_key).map_err(mesh_err_to_py)?;
    Ok(bytes.to_vec())
}

/// Register the `core` submodule on the parent `_agent_mesh` module.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "core")?;
    m.add_class::<PyFingerprint>()?;
    m.add_class::<PyUserKey>()?;
    m.add_class::<PyUserPublic>()?;
    m.add_class::<PyAgentMetadata>()?;
    m.add_class::<PyAgentKey>()?;
    m.add_class::<PyCertChain>()?;
    m.add_class::<PyRecipient>()?;
    m.add_class::<PySignedEnvelope>()?;
    m.add_class::<PyGitHubBinding>()?;
    m.add_function(wrap_pyfunction!(ssh_authorized_key_to_ed25519_bytes, &m)?)?;
    m.add("MeshError", py.get_type::<PyMeshError>())?;
    parent.add_submodule(&m)?;
    Ok(())
}
