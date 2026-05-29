//! Umbrella Python extension module for agent-mesh.
//!
//! One cdylib, four submodules (core, discovery, transport, bus).
//! Each underlying crate exposes a `pyo3_module::register` function
//! that adds its types to the parent module — this crate just stitches
//! them together.

use pyo3::prelude::*;

#[pymodule]
fn _agent_mesh(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    agent_mesh_core::pyo3_module::register(py, m)?;
    agent_mesh_discovery::pyo3_module::register(py, m)?;
    agent_mesh_transport::pyo3_module::register(py, m)?;
    agent_mesh_bus::pyo3_module::register(py, m)?;
    Ok(())
}
