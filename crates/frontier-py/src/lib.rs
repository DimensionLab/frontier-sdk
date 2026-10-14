// SPDX-License-Identifier: Apache-2.0

use frontier_connectors::ConnectorRegistry;
use frontier_core::RunId;
use frontier_telemetry::{JsonlSink, RunLogger};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

mod prep;

fn registry() -> ConnectorRegistry {
    let mut r = ConnectorRegistry::new();
    r.register(Box::new(
        frontier_connector_openfoam::OpenFoamConnector::default(),
    ));
    r.register(Box::new(frontier_connector_vtk::VtkConnector::default()));
    r
}

/// Native run logger writing JSONL metrics (offline-first).
#[pyclass(name = "RunLogger")]
struct PyRunLogger {
    inner: RunLogger,
    run_id: String,
}

#[pymethods]
impl PyRunLogger {
    #[new]
    #[pyo3(signature = (dir, run_id=None))]
    fn new(dir: PathBuf, run_id: Option<String>) -> PyResult<Self> {
        let run = match run_id {
            Some(s) => s
                .parse::<RunId>()
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
            None => RunId::new(),
        };
        let sink = JsonlSink::open(&dir, run).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            inner: RunLogger::new(run, Box::new(sink)),
            run_id: run.to_string(),
        })
    }

    #[getter]
    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn log(&self, step: u64, values: BTreeMap<String, f64>) -> PyResult<()> {
        self.inner
            .log_scalars(step, values)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn flush(&self) -> PyResult<()> {
        self.inner
            .flush()
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

/// Detect which connectors can read `path`; returns `[(connector_id, confidence), ...]`.
#[pyfunction]
fn detect(path: PathBuf) -> Vec<(String, f32)> {
    registry()
        .detect(&path)
        .into_iter()
        .map(|d| (d.connector_id, d.confidence))
        .collect()
}

/// Open a sample and return its metadata as a JSON string.
#[pyfunction]
fn describe(path: PathBuf) -> PyResult<String> {
    let reader = registry()
        .open(&path)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(reader.metadata()).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn connector_ids() -> Vec<String> {
    registry().ids().into_iter().map(str::to_owned).collect()
}

#[pymodule]
fn frontier_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("DATA_MODEL_VERSION", frontier_core::DATA_MODEL_VERSION)?;
    m.add_class::<PyRunLogger>()?;
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(describe, m)?)?;
    m.add_function(wrap_pyfunction!(connector_ids, m)?)?;
    // `frontier_native.prep`: the data-preparation kernels. Registered in `sys.modules` so
    // `import frontier_native.prep` works for a submodule of an extension module.
    let py = m.py();
    let prep = prep::module(py)?;
    m.add_submodule(&prep)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("frontier_native.prep", &prep)?;
    Ok(())
}
