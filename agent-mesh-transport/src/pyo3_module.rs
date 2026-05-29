//! Python bindings for `agent-mesh-transport`.
//!
//! Surface scope: enough for the native-Python `amesh` CLI to drive
//! `listen` and `send` end-to-end against Rust peers — bind an
//! [`Endpoint`], resolve a peer fingerprint via mDNS, dial it,
//! handshake, send a [`SignedEnvelope`]; or accept a single
//! envelope on the listen side. The full dial/accept/handshake/stream
//! surface is deliberately wrapped at facade granularity instead of
//! exposing iroh's Connection/Stream types directly — Python users
//! shouldn't have to manage QUIC lifetimes by hand.
//!
//! Compiled only when the `pyo3` cargo feature is on.

use crate::endpoint::Endpoint;
use crate::handshake::do_handshake;
use crate::identity::agent_pubkey_to_iroh;
use crate::resolver::{PeerResolver, ResolverHandle};
use crate::stream::{recv_envelope, send_envelope};
use agent_mesh_discovery::pyo3_module::PyPeerInfo;
use agent_mesh_protocol::pyo3_module::{PyAgentKey, PyCertChain, PyFingerprint, PySignedEnvelope};
use agent_mesh_protocol::{AgentKey, Fingerprint};
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyType};
use pyo3_async_runtimes::tokio::future_into_py;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// A bound QUIC endpoint backed by an agent's ed25519 key.
#[pyclass(
    name = "Endpoint",
    module = "agent_mesh._agent_mesh.transport",
    skip_from_py_object
)]
pub struct PyEndpoint {
    /// `Option` because `close()` consumes the endpoint by value.
    /// Holding the `Arc<Mutex<...>>` lets us pass the endpoint into
    /// the async closure and still drop it later from Python.
    inner: Arc<Mutex<Option<Endpoint>>>,
}

#[pymethods]
impl PyEndpoint {
    /// Bind a new QUIC endpoint backed by `agent`'s ed25519 key.
    /// `port = 0` lets the OS pick a free UDP port.
    ///
    /// Returns a Python awaitable resolving to the bound `Endpoint`.
    #[classmethod]
    fn bind<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        agent: &PyAgentKey,
        port: u16,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Clone the agent key seed across the await boundary. AgentKey
        // doesn't implement Clone (by design — keys are unique-bearing
        // values), but the pyo3 wrapper holds a reference. We snapshot
        // the bytes needed to rebuild a SigningKey-equivalent and
        // pair it with the existing cert chain so `Endpoint::bind`
        // can use it.
        let signing_bytes = agent.inner.signing_key_bytes();
        let cert = agent.inner.cert().clone();
        future_into_py(py, async move {
            // Rebuild a transient AgentKey from seed + cert. This
            // shares the SAME ed25519 identity (and therefore the
            // same iroh EndpointId) the Python-side AgentKey points
            // at — the bind doesn't need or want a different key.
            let agent = AgentKey::from_seed_and_cert(&signing_bytes, cert)
                .map_err(|e| PyRuntimeError::new_err(format!("agent rebuild: {e}")))?;
            let ep = Endpoint::bind(&agent, port)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("endpoint bind: {e}")))?;
            Ok(Self {
                inner: Arc::new(Mutex::new(Some(ep))),
            })
        })
    }

    /// Local UDP port the endpoint is bound on. Returns 0 if the
    /// endpoint has already been closed.
    fn local_port<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let guard = inner.lock().await;
            Ok(guard.as_ref().map(Endpoint::port).unwrap_or(0))
        })
    }

    /// Local socket addresses the endpoint is bound on. Returns an
    /// empty list if the endpoint has been closed.
    fn local_socket_addrs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let guard = inner.lock().await;
            let addrs = guard
                .as_ref()
                .map(|ep| {
                    ep.local_socket_addrs()
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Ok(addrs)
        })
    }

    /// Dial a peer (by raw 32-byte ed25519 pubkey + socket addrs),
    /// drive the cert-chain handshake, send one [`SignedEnvelope`],
    /// finish the send stream, and return the peer's verified agent
    /// fingerprint.
    ///
    /// This is the bottom half of `amesh send` — the discovery half
    /// (resolving a fingerprint to addrs + pubkey) lives in
    /// [`PyPeerResolver`]. Keeping the two halves separate lets the
    /// Python CLI structure error messages around the discovery vs
    /// transport boundary the way the Rust CLI does.
    fn send_envelope_to<'py>(
        &self,
        py: Python<'py>,
        our_cert: &PyCertChain,
        peer_pubkey: Vec<u8>,
        addrs: Vec<String>,
        envelope: &PySignedEnvelope,
    ) -> PyResult<Bound<'py, PyAny>> {
        if peer_pubkey.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "peer_pubkey must be 32 bytes, got {}",
                peer_pubkey.len()
            )));
        }
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&peer_pubkey);
        let parsed_addrs: Vec<SocketAddr> = addrs
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|e| PyValueError::new_err(format!("parse addr {s:?}: {e}")))
            })
            .collect::<PyResult<_>>()?;
        let iroh_pubkey = agent_pubkey_to_iroh(&pubkey_arr)
            .ok_or_else(|| PyValueError::new_err("peer pubkey is not a valid ed25519 point"))?;

        let inner = self.inner.clone();
        let our_cert = our_cert.inner.clone();
        let env = envelope.inner.clone();
        future_into_py(py, async move {
            let guard = inner.lock().await;
            let ep = guard
                .as_ref()
                .ok_or_else(|| PyRuntimeError::new_err("endpoint has been closed"))?;
            let conn = ep
                .dial(iroh_pubkey, parsed_addrs)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("dial: {e}")))?;
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("open bidi: {e}")))?;
            let peer_cert = do_handshake(&our_cert, &mut send, &mut recv, true)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("handshake: {e}")))?;
            send_envelope(&mut send, &env)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("send envelope: {e}")))?;
            send.finish()
                .map_err(|e| PyRuntimeError::new_err(format!("finish stream: {e}")))?;
            Ok(PyFingerprint {
                inner: peer_cert.agent_fingerprint(),
            })
        })
    }

    /// Accept one incoming connection, run the cert-chain handshake,
    /// receive one [`SignedEnvelope`], and return it along with the
    /// peer's verified agent + user fingerprints.
    ///
    /// Returns `None` if no connection arrives within `timeout_ms`,
    /// or if the endpoint has been closed. This is the per-iteration
    /// body of `amesh listen` — Python loops on it for the bounded
    /// listen window.
    fn accept_envelope<'py>(
        &self,
        py: Python<'py>,
        our_cert: &PyCertChain,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let our_cert = our_cert.inner.clone();
        future_into_py(py, async move {
            let guard = inner.lock().await;
            let ep = match guard.as_ref() {
                Some(ep) => ep,
                None => return Ok(None),
            };
            let accept_fut = ep.accept();
            let incoming =
                match tokio::time::timeout(Duration::from_millis(timeout_ms), accept_fut).await {
                    Ok(Some(inc)) => inc,
                    Ok(None) => return Ok(None),
                    Err(_) => return Ok(None),
                };
            let conn = incoming
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("await QUIC handshake: {e}")))?;
            // First (and for the CLI, only) bidi stream per
            // connection.
            let (mut send, mut recv) = conn
                .accept_bi()
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("accept bidi: {e}")))?;
            let peer_cert = match tokio::time::timeout(
                Duration::from_secs(5),
                do_handshake(&our_cert, &mut send, &mut recv, false),
            )
            .await
            {
                Ok(Ok(cert)) => cert,
                Ok(Err(e)) => {
                    return Err(PyRuntimeError::new_err(format!("handshake: {e}")));
                }
                Err(_) => {
                    return Err(PyTimeoutError::new_err("handshake timed out after 5s"));
                }
            };
            let env = recv_envelope(&mut recv)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("recv envelope: {e}")))?;
            let _ = send.finish();
            Ok(Some(AcceptedEnvelope {
                envelope: PySignedEnvelope { inner: env },
                peer_agent_fp: PyFingerprint {
                    inner: peer_cert.agent_fingerprint(),
                },
                peer_user_fp: PyFingerprint {
                    inner: peer_cert.user_fingerprint(),
                },
            }))
        })
    }

    /// Graceful shutdown — releases the UDP port. Idempotent.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(ep) = guard.take() {
                ep.close().await;
            }
            Ok(())
        })
    }
}

/// One received envelope plus the peer's verified identity.
///
/// Returned from [`PyEndpoint::accept_envelope`]; the Python CLI
/// reads `envelope` for the payload + sequence and the two `*_fp`
/// fields for the audit log it prints.
#[pyclass(
    name = "AcceptedEnvelope",
    module = "agent_mesh._agent_mesh.transport",
    frozen,
    skip_from_py_object
)]
pub struct AcceptedEnvelope {
    #[pyo3(get)]
    envelope: PySignedEnvelope,
    #[pyo3(get)]
    peer_agent_fp: PyFingerprint,
    #[pyo3(get)]
    peer_user_fp: PyFingerprint,
}

// ---- PeerResolver ----

/// Bridges mDNS discovery to transport: given a peer fingerprint,
/// returns the [`PeerInfo`](agent_mesh_discovery::PeerInfo)
/// currently advertised on the LAN (or waits up to a timeout for it
/// to appear). Wraps [`PeerResolver`].
#[pyclass(
    name = "PeerResolver",
    module = "agent_mesh._agent_mesh.transport",
    skip_from_py_object
)]
pub struct PyPeerResolver {
    inner: Arc<PeerResolver>,
    /// Keep-alive handle for the background mDNS browser task.
    /// Wrapped in `Mutex<Option<...>>` so `close()` can drop it.
    _handle: Arc<Mutex<Option<ResolverHandle>>>,
}

#[pymethods]
impl PyPeerResolver {
    /// Start the resolver — stands up a background mDNS browser and
    /// an in-process index keyed by agent fingerprint.
    #[classmethod]
    fn start(_cls: &Bound<'_, PyType>) -> PyResult<Self> {
        let (resolver, handle) = PeerResolver::start()
            .map_err(|e| PyRuntimeError::new_err(format!("resolver start: {e}")))?;
        Ok(Self {
            inner: Arc::new(resolver),
            _handle: Arc::new(Mutex::new(Some(handle))),
        })
    }

    /// Wait up to `timeout_ms` for the peer with `fp` to appear.
    /// Returns `None` on timeout, a `PeerInfo` on success.
    fn resolve<'py>(
        &self,
        py: Python<'py>,
        fp: &PyFingerprint,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let target = fp.inner;
        future_into_py(py, async move {
            let peer = inner
                .resolve(&target, Duration::from_millis(timeout_ms))
                .await;
            Ok(peer.map(|p| PyPeerInfo { inner: p }))
        })
    }

    /// Snapshot the currently-known peers.
    fn known<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let peers = inner.known().await;
            Ok(peers
                .into_iter()
                .map(|p| PyPeerInfo { inner: p })
                .collect::<Vec<_>>())
        })
    }

    /// Stop browsing immediately. Idempotent. Subsequent `resolve`
    /// calls will hang until timeout — the in-process index keeps
    /// what it already knew about.
    fn stop(&self) {
        // We can't easily call this from sync context if anyone is
        // holding the handle Arc, so use try_lock and drop on success.
        if let Ok(mut guard) = self._handle.try_lock() {
            guard.take();
        }
    }
}

/// Helper: parse `"a.b.c.d:port"` strings into Python — handy when
/// constructing the addrs list for `Endpoint.send_envelope_to`.
#[pyfunction]
fn parse_socket_addr(s: &str) -> PyResult<String> {
    let parsed: SocketAddr = s
        .parse()
        .map_err(|e| PyValueError::new_err(format!("parse {s:?}: {e}")))?;
    Ok(parsed.to_string())
}

/// Helper: build a `SocketAddr` string from an IP-like string and a
/// port. Lets Python CLIs avoid hand-formatting `[v6]:port`.
#[pyfunction]
fn make_socket_addr(ip: &str, port: u16) -> PyResult<String> {
    let ip_addr: std::net::IpAddr = ip
        .parse()
        .map_err(|e| PyValueError::new_err(format!("parse ip {ip:?}: {e}")))?;
    Ok(SocketAddr::new(ip_addr, port).to_string())
}

/// Helper: confirm a 32-byte slice is a valid ed25519 public key (the
/// shape `Endpoint.send_envelope_to` requires). Returns `True` /
/// `False`; mirrors `agent_pubkey_to_iroh` without surfacing the iroh
/// `PublicKey` type to Python.
#[pyfunction]
fn is_valid_agent_pubkey(bytes: &[u8]) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    agent_pubkey_to_iroh(&arr).is_some()
}

/// Helper: BLAKE3 fingerprint of a 32-byte ed25519 pubkey, returned
/// as a `Fingerprint`. Mirrors `Fingerprint::of_bytes` but communicates
/// intent at the call site (agent pubkey, not arbitrary content).
#[pyfunction]
fn fingerprint_from_pubkey(bytes: &[u8]) -> PyResult<PyFingerprint> {
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "expected 32-byte pubkey, got {}",
            bytes.len()
        )));
    }
    Ok(PyFingerprint {
        inner: Fingerprint::of_bytes(bytes),
    })
}

/// Register the `transport` submodule on the parent `_agent_mesh` module.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "transport")?;
    m.add_class::<PyEndpoint>()?;
    m.add_class::<AcceptedEnvelope>()?;
    m.add_class::<PyPeerResolver>()?;
    m.add_function(wrap_pyfunction!(parse_socket_addr, &m)?)?;
    m.add_function(wrap_pyfunction!(make_socket_addr, &m)?)?;
    m.add_function(wrap_pyfunction!(is_valid_agent_pubkey, &m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint_from_pubkey, &m)?)?;
    m.add("ALPN", crate::alpn::ALPN)?;
    parent.add_submodule(&m)?;
    Ok(())
}
