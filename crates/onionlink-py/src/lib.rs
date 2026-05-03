use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass(name = "Session")]
struct PySession {
    inner: onionlink_core::Session,
}

fn map_err(err: onionlink_core::Error) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

#[pymethods]
impl PySession {
    #[new]
    #[pyo3(signature = (bootstrap = "128.31.0.39:9131", consensus_file = "", timeout_ms = 30000, verbose = false))]
    fn new(
        py: Python<'_>,
        bootstrap: &str,
        consensus_file: &str,
        timeout_ms: i32,
        verbose: bool,
    ) -> PyResult<Self> {
        let inner = py
            .detach(|| onionlink_core::Session::new(bootstrap, consensus_file, timeout_ms, verbose))
            .map_err(map_err)?;
        Ok(Self { inner })
    }

    #[pyo3(signature = (onion, port, payload = Vec::<u8>::new(), response_limit = 4 * 1024 * 1024))]
    fn request<'py>(
        &self,
        py: Python<'py>,
        onion: &str,
        port: u16,
        payload: Vec<u8>,
        response_limit: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inbound = py
            .detach(|| self.inner.request(onion, port, &payload, response_limit))
            .map_err(map_err)?;
        Ok(PyBytes::new(py, &inbound))
    }

    #[pyo3(signature = (onion, port = 80, path = "/", response_limit = 4 * 1024 * 1024))]
    fn http_get<'py>(
        &self,
        py: Python<'py>,
        onion: &str,
        port: u16,
        path: &str,
        response_limit: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inbound = py
            .detach(|| self.inner.http_get(onion, port, path, response_limit))
            .map_err(map_err)?;
        Ok(PyBytes::new(py, &inbound))
    }
}

#[pymodule(gil_used = false)]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__doc__", "Native Rust bindings for onionlink")?;
    m.add_class::<PySession>()?;
    Ok(())
}
