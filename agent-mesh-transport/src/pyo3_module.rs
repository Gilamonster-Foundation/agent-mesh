//! Python bindings for `agent-mesh-transport`.
//!
//! Surface scope (deliberately small): expose `Endpoint::bind` so
//! Python callers can stand up a QUIC endpoint, learn its bound port,
//! and close it cleanly. The full dial/accept/handshake/stream surface
//! is reserved for the higher-level `Bus` bindings — exposing iroh's
//! Connection/Stream types via PyO3 would force Python users to
//! manage the same low-level lifetime puzzles Rust callers already
//! escape via `agent_mesh_bus::Bus`.
//!
//! Compiled only when the `pyo3` cargo feature is on.

use crate::endpoint::Endpoint;
use agent_mesh_core::pyo3_module::PyAgentKey;
use agent_mesh_core::AgentKey;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyType};
use pyo3_async_runtimes::tokio::future_into_py;
use std::sync::Arc;
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
            Ok(PyEndpoint {
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

/// Register the `transport` submodule on the parent `_agent_mesh` module.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "transport")?;
    m.add_class::<PyEndpoint>()?;
    m.add("ALPN", crate::alpn::ALPN)?;
    parent.add_submodule(&m)?;
    Ok(())
}
