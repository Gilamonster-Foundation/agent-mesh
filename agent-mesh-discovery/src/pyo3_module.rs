//! Python bindings for `agent-mesh-discovery`.
//!
//! mDNS announcer + browser surface, exposed as Python classes.
//! Compiled only when the `pyo3` cargo feature is on.
//!
//! The mDNS daemon runs in a background thread (mdns-sd's own design),
//! so Python sees these as plain sync types — no asyncio bridging
//! needed. Browsing collects events synchronously for a bounded
//! duration; that covers every Python-side use case discovery has.

use crate::{AnnounceConfig, Announcer, AnnouncerHandle, Browser, BrowserEvent, PeerInfo};
use agent_mesh_core::pyo3_module::PyFingerprint;
use agent_mesh_core::Fingerprint;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyType};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---- PeerInfo ----

/// What we know about a peer from mDNS alone (no handshake yet).
#[pyclass(
    name = "PeerInfo",
    module = "agent_mesh._agent_mesh.discovery",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyPeerInfo {
    pub inner: PeerInfo,
}

#[pymethods]
impl PyPeerInfo {
    #[getter]
    fn agent_fp(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.agent_fp,
        }
    }

    #[getter]
    fn user_fp(&self) -> PyFingerprint {
        PyFingerprint {
            inner: self.inner.user_fp,
        }
    }

    #[getter]
    fn capabilities(&self) -> Vec<String> {
        self.inner.capabilities.clone()
    }

    #[getter]
    fn role(&self) -> &str {
        &self.inner.role
    }

    #[getter]
    fn host(&self) -> &str {
        &self.inner.host
    }

    /// Resolved IP addresses for the peer, as strings.
    #[getter]
    fn addrs(&self) -> Vec<String> {
        self.inner.addrs.iter().map(|a| a.to_string()).collect()
    }

    #[getter]
    fn port(&self) -> u16 {
        self.inner.port
    }

    #[getter]
    fn instance(&self) -> &str {
        &self.inner.instance
    }

    /// Optional raw 32-byte ed25519 pubkey if the peer advertised it.
    #[getter]
    fn agent_pubkey<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .agent_pubkey
            .as_ref()
            .map(|b| PyBytes::new(py, b))
    }

    /// True if this peer shares our user fingerprint.
    fn is_same_user(&self, our_user_fp: &PyFingerprint) -> bool {
        self.inner.is_same_user(&our_user_fp.inner)
    }

    fn __repr__(&self) -> String {
        format!(
            "PeerInfo(agent_fp={}, role='{}', host='{}', port={})",
            self.inner.agent_fp.short(),
            self.inner.role,
            self.inner.host,
            self.inner.port
        )
    }
}

// ---- AnnounceConfig ----

/// Configuration for announcing this agent on the LAN.
///
/// `agent_fp` and `user_fp` may be passed as hex strings or as
/// `Fingerprint` instances. `agent_pubkey` is optional 32 raw bytes.
#[pyclass(
    name = "AnnounceConfig",
    module = "agent_mesh._agent_mesh.discovery",
    frozen,
    skip_from_py_object
)]
pub struct PyAnnounceConfig {
    pub(crate) inner: AnnounceConfig,
}

#[pymethods]
impl PyAnnounceConfig {
    #[new]
    #[pyo3(signature = (agent_fp, user_fp, capabilities, role, host, port, agent_pubkey = None))]
    fn new(
        agent_fp: &PyFingerprint,
        user_fp: &PyFingerprint,
        capabilities: Vec<String>,
        role: String,
        host: String,
        port: u16,
        agent_pubkey: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let pubkey = match agent_pubkey {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(PyValueError::new_err(format!(
                        "agent_pubkey must be 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            }
            None => None,
        };
        Ok(Self {
            inner: AnnounceConfig {
                agent_fp: agent_fp.inner,
                agent_pubkey: pubkey,
                user_fp: user_fp.inner,
                capabilities,
                role,
                host,
                port,
            },
        })
    }
}

// ---- Announcer / AnnouncerHandle ----

/// Handle to a running mDNS announcer. Call `stop()` (or let GC drop
/// it) to unregister.
#[pyclass(
    name = "AnnouncerHandle",
    module = "agent_mesh._agent_mesh.discovery",
    skip_from_py_object
)]
pub struct PyAnnouncerHandle {
    inner: Mutex<Option<AnnouncerHandle>>,
    instance_name: String,
}

#[pymethods]
impl PyAnnouncerHandle {
    /// The fully-qualified mDNS instance name we registered as.
    fn instance(&self) -> String {
        self.instance_name.clone()
    }

    /// Stop announcing immediately. Idempotent.
    fn stop(&self) {
        let mut guard = self.inner.lock().expect("announcer mutex poisoned");
        guard.take();
    }
}

/// Façade for starting the mDNS announcer.
#[pyclass(
    name = "Announcer",
    module = "agent_mesh._agent_mesh.discovery",
    frozen,
    skip_from_py_object
)]
pub struct PyAnnouncer;

#[pymethods]
impl PyAnnouncer {
    /// Start the mDNS announcer. Returns a handle that keeps the
    /// daemon alive until `.stop()` (or garbage collection).
    #[classmethod]
    fn start(_cls: &Bound<'_, PyType>, config: &PyAnnounceConfig) -> PyResult<PyAnnouncerHandle> {
        let handle = Announcer::start(config.inner.clone())
            .map_err(|e| PyRuntimeError::new_err(format!("announcer start: {e}")))?;
        let instance_name = handle.instance().to_string();
        Ok(PyAnnouncerHandle {
            inner: Mutex::new(Some(handle)),
            instance_name,
        })
    }
}

// ---- Browser / BrowserHandle ----

/// Handle to a running mDNS browser. `collect_for` drains events for
/// a bounded duration; dropping (or `.stop()`) shuts the browser down.
#[pyclass(
    name = "BrowserHandle",
    module = "agent_mesh._agent_mesh.discovery",
    skip_from_py_object
)]
pub struct PyBrowserHandle {
    state: Mutex<BrowserState>,
}

struct BrowserState {
    handle: Option<crate::BrowserHandle>,
    rx: Option<tokio::sync::mpsc::UnboundedReceiver<BrowserEvent>>,
}

#[pymethods]
impl PyBrowserHandle {
    /// Drain browser events for up to `duration_ms` milliseconds (or
    /// until `max_events` are collected, whichever comes first).
    /// Returns a list of `PeerInfo` instances for `Resolved` events;
    /// `Removed` events are silently skipped (callers that need them
    /// should keep their own state).
    ///
    /// Blocks the calling Python thread. The browser is still alive
    /// after this returns — call again to keep collecting.
    #[pyo3(signature = (duration_ms, max_events = 1024))]
    fn collect_for(&self, py: Python<'_>, duration_ms: u64, max_events: usize) -> Vec<PyPeerInfo> {
        let deadline = Instant::now() + Duration::from_millis(duration_ms);
        // Release the GIL while we block on mDNS events.
        py.detach(|| {
            let mut out = Vec::new();
            let mut guard = self.state.lock().expect("browser mutex poisoned");
            let Some(rx) = guard.rx.as_mut() else {
                return out;
            };
            while out.len() < max_events {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline - now;
                // Block synchronously on the channel with a deadline
                // using try_recv + a short sleep; the mpsc receiver
                // doesn't have a built-in blocking-with-timeout
                // method that we can call without entering a runtime.
                match rx.try_recv() {
                    Ok(BrowserEvent::Resolved(peer)) => out.push(PyPeerInfo { inner: peer }),
                    Ok(BrowserEvent::Removed { .. }) => {}
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                        // Sleep a short slice; mDNS responses arrive
                        // in hundreds of milliseconds.
                        let sleep = std::cmp::min(remaining, Duration::from_millis(50));
                        std::thread::sleep(sleep);
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
            out
        })
    }

    /// Stop the browser immediately. Idempotent.
    fn stop(&self) {
        let mut guard = self.state.lock().expect("browser mutex poisoned");
        guard.handle.take();
        guard.rx.take();
    }
}

/// Façade for starting the mDNS browser.
#[pyclass(
    name = "Browser",
    module = "agent_mesh._agent_mesh.discovery",
    frozen,
    skip_from_py_object
)]
pub struct PyBrowser;

#[pymethods]
impl PyBrowser {
    /// Start the mDNS browser. Returns a handle whose `.collect_for`
    /// drains events synchronously.
    #[classmethod]
    fn start(_cls: &Bound<'_, PyType>) -> PyResult<PyBrowserHandle> {
        let (handle, rx) =
            Browser::start().map_err(|e| PyRuntimeError::new_err(format!("browser start: {e}")))?;
        Ok(PyBrowserHandle {
            state: Mutex::new(BrowserState {
                handle: Some(handle),
                rx: Some(rx),
            }),
        })
    }
}

/// Helper: parse a hex fingerprint string back into a `Fingerprint`
/// object — convenience for Python callers building configs.
#[pyfunction]
fn fingerprint_from_hex(s: &str) -> PyResult<PyFingerprint> {
    let inner = Fingerprint::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyFingerprint { inner })
}

/// Register the `discovery` submodule on the parent `_agent_mesh` module.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "discovery")?;
    m.add_class::<PyPeerInfo>()?;
    m.add_class::<PyAnnounceConfig>()?;
    m.add_class::<PyAnnouncer>()?;
    m.add_class::<PyAnnouncerHandle>()?;
    m.add_class::<PyBrowser>()?;
    m.add_class::<PyBrowserHandle>()?;
    m.add_function(wrap_pyfunction!(fingerprint_from_hex, &m)?)?;
    m.add("SERVICE_TYPE", crate::SERVICE_TYPE)?;
    parent.add_submodule(&m)?;
    Ok(())
}
