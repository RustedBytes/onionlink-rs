use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};

#[pyclass(name = "Session", frozen)]
struct PySession {
    inner: Arc<onionlink_core::Session>,
}

fn map_err(err: onionlink_core::Error) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

fn map_join_err(err: tokio::task::JoinError) -> PyErr {
    PyRuntimeError::new_err(format!("async runtime task failed: {err}"))
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
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[staticmethod]
    #[pyo3(signature = (bootstrap = "128.31.0.39:9131", consensus_file = "", timeout_ms = 30000, verbose = false))]
    fn create_async<'py>(
        py: Python<'py>,
        bootstrap: &str,
        consensus_file: &str,
        timeout_ms: i32,
        verbose: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let bootstrap = bootstrap.to_owned();
        let consensus_file = consensus_file.to_owned();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inner = tokio::task::spawn_blocking(move || {
                onionlink_core::Session::new(&bootstrap, &consensus_file, timeout_ms, verbose)
            })
            .await
            .map_err(map_join_err)?
            .map_err(map_err)?;

            Python::attach(|py| {
                Py::new(
                    py,
                    PySession {
                        inner: Arc::new(inner),
                    },
                )
            })
        })
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
        let inner = Arc::clone(&self.inner);
        let onion = onion.to_owned();
        let inbound = py
            .detach(move || inner.request(&onion, port, &payload, response_limit))
            .map_err(map_err)?;
        Ok(PyBytes::new(py, &inbound))
    }

    #[pyo3(signature = (onion, port, payload = Vec::<u8>::new(), response_limit = 4 * 1024 * 1024))]
    fn request_async<'py>(
        &self,
        py: Python<'py>,
        onion: &str,
        port: u16,
        payload: Vec<u8>,
        response_limit: usize,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        let onion = onion.to_owned();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inbound = tokio::task::spawn_blocking(move || {
                inner.request(&onion, port, &payload, response_limit)
            })
            .await
            .map_err(map_join_err)?
            .map_err(map_err)?;

            Python::attach(|py| Ok(PyBytes::new(py, &inbound).unbind()))
        })
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
        let inner = Arc::clone(&self.inner);
        let onion = onion.to_owned();
        let path = path.to_owned();
        let inbound = py
            .detach(move || inner.http_get(&onion, port, &path, response_limit))
            .map_err(map_err)?;
        Ok(PyBytes::new(py, &inbound))
    }

    #[pyo3(signature = (onion, port = 80, path = "/", response_limit = 4 * 1024 * 1024))]
    fn http_get_async<'py>(
        &self,
        py: Python<'py>,
        onion: &str,
        port: u16,
        path: &str,
        response_limit: usize,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        let onion = onion.to_owned();
        let path = path.to_owned();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inbound = tokio::task::spawn_blocking(move || {
                inner.http_get(&onion, port, &path, response_limit)
            })
            .await
            .map_err(map_join_err)?
            .map_err(map_err)?;

            Python::attach(|py| Ok(PyBytes::new(py, &inbound).unbind()))
        })
    }
}

#[pymodule(gil_used = false)]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__doc__", "Native Rust bindings for onionlink")?;
    m.add_class::<PySession>()?;
    Ok(())
}
