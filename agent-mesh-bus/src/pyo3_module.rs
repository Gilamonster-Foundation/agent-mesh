//! Python bindings for `agent-mesh-bus`.
//!
//! Exposes the high-level Bus surface to Python: bind, request,
//! handle_requests (with sync OR async Python callbacks), publish_to,
//! subscribe, close. Topic + CorrelationId come along for the ride
//! since they're the natural arguments to those methods.
//!
//! All async-returning methods produce Python awaitables via
//! `pyo3_async_runtimes::tokio`. Driving them from CPython requires
//! the asyncio runtime to be initialized — pytest-asyncio or
//! `asyncio.run(...)` are the normal entry points.

use crate::{bus::Bus, reply::CorrelationId, topic::Topic, BusError, Result as BusResult};
use agent_mesh_core::pyo3_module::{PyAgentKey, PyFingerprint, PyUserKey};
use agent_mesh_core::AgentKey;
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyType};
use pyo3::Py;

/// In pyo3 0.28 the old `PyAnyObj` type alias is gone; an unbound
/// Python object is `Py<PyAny>`. We use this alias to keep the
/// callback / future signatures readable.
type PyAnyObj = Py<PyAny>;
use pyo3_async_runtimes::tokio::future_into_py;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

// ---- Topic ----

#[pyclass(
    name = "Topic",
    module = "agent_mesh._agent_mesh.bus",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyTopic {
    pub(crate) inner: Topic,
}

#[pymethods]
impl PyTopic {
    #[new]
    fn new(user_fp: &PyFingerprint, name: String) -> Self {
        Self {
            inner: Topic::new(user_fp.inner, name),
        }
    }

    /// Wire-form representation: `"<user_fp_hex>:<name>"`.
    fn wire(&self) -> String {
        self.inner.wire()
    }

    /// Inverse of `wire()`. Returns `None` if `s` is malformed.
    #[classmethod]
    fn parse_wire(_cls: &Bound<'_, PyType>, s: &str) -> Option<Self> {
        Topic::parse_wire(s).map(|t| Self { inner: t })
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn user_fp(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.user_fp,
        }
    }

    fn __str__(&self) -> String {
        self.inner.wire()
    }

    fn __repr__(&self) -> String {
        format!("Topic('{}')", self.inner.wire())
    }
}

// ---- CorrelationId ----

#[pyclass(
    name = "CorrelationId",
    module = "agent_mesh._agent_mesh.bus",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyCorrelationId {
    pub(crate) inner: CorrelationId,
}

#[pymethods]
impl PyCorrelationId {
    /// Draw a fresh random correlation id from the OS RNG.
    #[classmethod]
    fn new_random(_cls: &Bound<'_, PyType>) -> Self {
        Self {
            inner: CorrelationId::new_random(),
        }
    }

    /// Full 32-character hex representation.
    fn hex(&self) -> String {
        self.inner.hex()
    }
}

// ---- BroadcastReceiver ----

/// Python view of a subscription. `recv()` returns an awaitable of
/// `Optional[bytes]` (None when the channel closes / lags).
#[pyclass(
    name = "BroadcastReceiver",
    module = "agent_mesh._agent_mesh.bus",
    skip_from_py_object
)]
pub struct PyBroadcastReceiver {
    inner: Arc<Mutex<tokio::sync::broadcast::Receiver<Vec<u8>>>>,
}

#[pymethods]
impl PyBroadcastReceiver {
    /// Receive the next published body. Returns `None` on lag or
    /// channel close.
    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut guard = inner.lock().await;
            match guard.recv().await {
                Ok(body) => Ok(Some(body)),
                Err(_) => Ok(None),
            }
        })
    }
}

// ---- Bus ----

#[pyclass(
    name = "Bus",
    module = "agent_mesh._agent_mesh.bus",
    skip_from_py_object
)]
pub struct PyBus {
    /// `Arc<Bus>` so concurrent Python calls (request, publish, etc.)
    /// can run in parallel — bus methods take `&self`. The outer
    /// `Mutex<Option<...>>` exists only so `close()` can take the
    /// final owned `Bus` out without forcing every other operation
    /// through a lock.
    ///
    /// Lifecycle:
    /// - `bind`     → stores `Some(Arc<Bus>)`
    /// - call paths → snapshot the Arc with a short-lived lock, drop
    ///                the lock, then operate on the Arc
    /// - `close`    → swaps the slot to `None` and unwraps the Arc
    inner: Arc<Mutex<Option<Arc<Bus>>>>,
}

impl PyBus {
    /// Snapshot the live `Arc<Bus>` if the bus hasn't been closed.
    async fn snapshot(inner: &Arc<Mutex<Option<Arc<Bus>>>>) -> PyResult<Arc<Bus>> {
        let guard = inner.lock().await;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| PyRuntimeError::new_err("bus has been closed"))
    }
}

#[pymethods]
impl PyBus {
    /// Bind a bus on `port` (use 0 for OS-picked). Returns an
    /// awaitable resolving to the `Bus`.
    #[classmethod]
    fn bind<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        user: &PyUserKey,
        agent: &PyAgentKey,
        port: u16,
    ) -> PyResult<Bound<'py, PyAny>> {
        // The `user` key is needed to derive a UserKey reference for
        // Bus::bind. UserKey doesn't impl Clone — but we only need
        // the user's fingerprint + public key, both of which are
        // exposed via &UserKey. Bus::bind consumes `agent` by value
        // but only reads `user` by &ref. We materialize a transient
        // UserKey by re-loading from the public bytes only IF the
        // signing seed isn't needed... which it is, because
        // `Bus::bind` calls `user.fingerprint()` (read-only). So a
        // pubkey-only reconstruction would suffice if we made one.
        //
        // Cleanest path: clone the user via PKCS#8 PEM roundtrip.
        // It's slow but happens once per bind, and avoids changing
        // the core API. We do this on a temp file.
        //
        // Even simpler: extract the user's signing bytes via a new
        // helper on UserKey (parallel to AgentKey::signing_key_bytes).
        // We avoid touching the core surface here and use a workaround
        // tied to the existing API.
        let user_dir =
            tempfile::tempdir().map_err(|e| PyRuntimeError::new_err(format!("temp dir: {e}")))?;
        let user_path = user_dir.path().join("user.key");
        user.inner
            .save(&user_path)
            .map_err(|e| PyRuntimeError::new_err(format!("user save: {e}")))?;

        let agent_seed = agent.inner.signing_key_bytes();
        let agent_cert = agent.inner.cert().clone();

        future_into_py(py, async move {
            let user = agent_mesh_core::UserKey::load(&user_path)
                .map_err(|e| PyRuntimeError::new_err(format!("user load: {e}")))?;
            let agent = AgentKey::from_seed_and_cert(&agent_seed, agent_cert)
                .map_err(|e| PyRuntimeError::new_err(format!("agent rebuild: {e}")))?;
            let bus = Bus::bind(&user, agent, port).await.map_err(bus_err_to_py)?;
            // Keep the tempdir alive at least until bind returned.
            drop(user_dir);
            Ok(Self {
                inner: Arc::new(Mutex::new(Some(Arc::new(bus)))),
            })
        })
    }

    /// User fingerprint this bus belongs to.
    fn user_fingerprint<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let bus = Self::snapshot(&inner).await?;
            Ok(PyFingerprint {
                inner: bus.user_fingerprint(),
            })
        })
    }

    /// Agent fingerprint this bus runs as.
    fn agent_fingerprint<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let bus = Self::snapshot(&inner).await?;
            Ok(PyFingerprint {
                inner: bus.agent_fingerprint(),
            })
        })
    }

    /// Local UDP port the bus is bound on.
    fn local_port<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let bus = Self::snapshot(&inner).await?;
            Ok(bus.local_port())
        })
    }

    /// Send a Request to `peer_fp` on `topic`. Returns an awaitable
    /// resolving to the reply bytes.
    fn request<'py>(
        &self,
        py: Python<'py>,
        peer_fp: &PyFingerprint,
        topic: &PyTopic,
        body: Vec<u8>,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let peer_fp = peer_fp.inner;
        let topic = topic.inner.clone();
        future_into_py(py, async move {
            let bus = Self::snapshot(&inner).await?;
            let bytes = bus
                .request(peer_fp, &topic, body, Duration::from_millis(timeout_ms))
                .await
                .map_err(bus_err_to_py)?;
            Python::attach(|py| Ok(PyBytes::new(py, &bytes).unbind()))
        })
    }

    /// Publish a body to `peer_fp` on `topic`. Fire-and-forget.
    fn publish_to<'py>(
        &self,
        py: Python<'py>,
        peer_fp: &PyFingerprint,
        topic: &PyTopic,
        body: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let peer_fp = peer_fp.inner;
        let topic = topic.inner.clone();
        future_into_py(py, async move {
            let bus = Self::snapshot(&inner).await?;
            bus.publish_to(peer_fp, &topic, body)
                .await
                .map_err(bus_err_to_py)?;
            Ok(())
        })
    }

    /// Subscribe to `topic`. Returns an awaitable yielding a
    /// `BroadcastReceiver`.
    fn subscribe<'py>(&self, py: Python<'py>, topic: &PyTopic) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let topic = topic.inner.clone();
        future_into_py(py, async move {
            let bus = Self::snapshot(&inner).await?;
            let rx = bus.subscribe(&topic).await;
            Ok(PyBroadcastReceiver {
                inner: Arc::new(Mutex::new(rx)),
            })
        })
    }

    /// Register a handler for `topic`. The callback gets called with
    /// the request body (bytes) and must return either bytes (sync
    /// handler) or an awaitable resolving to bytes (async handler).
    ///
    /// The handler is registered eagerly — it doesn't return an
    /// awaitable, just `None`.
    fn handle_requests(&self, topic: &PyTopic, callback: PyAnyObj) -> PyResult<()> {
        let inner = self.inner.clone();
        let topic = topic.inner.clone();
        let callback = Arc::new(callback);
        // Spawn the registration into the tokio runtime; the inbox
        // accepts handlers before the next dispatched message.
        let handle = pyo3_async_runtimes::tokio::get_runtime();
        handle.spawn(async move {
            if let Ok(bus) = Self::snapshot(&inner).await {
                bus.handle_requests(topic, move |body: Vec<u8>| {
                    let cb = callback.clone();
                    async move { invoke_py_handler(cb, body).await }
                });
            }
        });
        Ok(())
    }

    /// Graceful shutdown. The bus can no longer be used after this.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(bus_arc) = guard.take() {
                drop(guard);
                // Try to unwrap the Arc; if other tasks are still
                // mid-await, fall through and let `Drop` clean up.
                match Arc::try_unwrap(bus_arc) {
                    Ok(bus) => bus.close().await.map_err(bus_err_to_py)?,
                    Err(_) => {
                        // Another in-flight call holds an Arc clone;
                        // drop our copy and let the bus's own Drop
                        // release the endpoint once the last clone
                        // goes away.
                    }
                }
            }
            Ok(())
        })
    }
}

/// Call into a Python handler (sync or async) and return its body as
/// `Vec<u8>`. The callback may:
///
/// * Return bytes directly (sync handler).
/// * Return an awaitable / coroutine resolving to bytes (async handler).
async fn invoke_py_handler(callback: Arc<PyAnyObj>, body: Vec<u8>) -> BusResult<Vec<u8>> {
    // First, call the Python callback with the body and capture
    // whatever it returns. If it returned an awaitable, hand it to
    // pyo3_async_runtimes so we can await it from Rust. If it
    // returned plain bytes, we're already done.
    let coro_or_value: PyResult<PyAnyObj> = Python::attach(|py| {
        let args = (PyBytes::new(py, &body),);
        let result = callback.call1(py, args)?;
        Ok(result)
    });
    let value =
        coro_or_value.map_err(|e| BusError::Transport(transport_err(format!("handler: {e}"))))?;

    // Now: is it a coroutine, or is it bytes?
    let awaitable_or_bytes: PyResult<Either> = Python::attach(|py| {
        let bound = value.bind(py);
        if let Ok(coro) = pyo3_async_runtimes::tokio::into_future(bound.clone()) {
            Ok(Either::Future(Box::pin(coro)))
        } else {
            let bytes: Vec<u8> = bound
                .extract()
                .map_err(|e| PyValueError::new_err(format!("handler must return bytes: {e}")))?;
            Ok(Either::Bytes(bytes))
        }
    });

    match awaitable_or_bytes {
        Ok(Either::Bytes(b)) => Ok(b),
        Ok(Either::Future(fut)) => {
            let result = fut.await.map_err(|e| {
                BusError::Transport(transport_err(format!("handler coro raised: {e}")))
            })?;
            let bytes: Vec<u8> = Python::attach(|py| result.extract(py)).map_err(|e| {
                BusError::Transport(transport_err(format!(
                    "handler coro must resolve to bytes: {e}"
                )))
            })?;
            Ok(bytes)
        }
        Err(e) => Err(BusError::Transport(transport_err(format!(
            "handler dispatch: {e}"
        )))),
    }
}

enum Either {
    Bytes(Vec<u8>),
    Future(std::pin::Pin<Box<dyn std::future::Future<Output = PyResult<PyAnyObj>> + Send>>),
}

fn transport_err(msg: String) -> agent_mesh_transport::TransportError {
    agent_mesh_transport::TransportError::Iroh(msg)
}

fn bus_err_to_py(e: BusError) -> PyErr {
    match &e {
        BusError::Timeout(_) => PyTimeoutError::new_err(e.to_string()),
        _ => PyRuntimeError::new_err(e.to_string()),
    }
}

/// Register the `bus` submodule on the parent `_agent_mesh` module.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "bus")?;
    m.add_class::<PyTopic>()?;
    m.add_class::<PyCorrelationId>()?;
    m.add_class::<PyBus>()?;
    m.add_class::<PyBroadcastReceiver>()?;
    parent.add_submodule(&m)?;
    Ok(())
}
