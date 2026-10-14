// SPDX-License-Identifier: Apache-2.0
//! Telemetry ingestion for training runs.
//!
//! The Python SDK (and, later, the worker's GPU sampler) emit [`Metric`] records.
//! A [`MetricSink`] receives them. The default sink appends newline-delimited JSON to
//! a per-run file, which is enough for offline / air-gapped usage and is trivially
//! replayable into the server or converted to Arrow with `frontier-data`.

use chrono::Utc;
use frontier_core::{Metric, MetricValue, Result, RunId, Step};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub trait MetricSink: Send + Sync {
    fn log(&self, metric: &Metric) -> Result<()>;
    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

/// Appends metrics as JSON lines to `<dir>/<run_id>.metrics.jsonl`.
pub struct JsonlSink {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl JsonlSink {
    pub fn open(dir: &Path, run: RunId) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{run}.metrics.jsonl"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl MetricSink for JsonlSink {
    fn log(&self, metric: &Metric) -> Result<()> {
        let line = serde_json::to_string(metric)?;
        let mut f = self.file.lock().expect("sink poisoned");
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.file.lock().expect("sink poisoned").flush()?;
        Ok(())
    }
}

/// Convenience handle used by SDK bindings.
pub struct RunLogger {
    run: RunId,
    sink: Box<dyn MetricSink>,
}

impl RunLogger {
    pub fn new(run: RunId, sink: Box<dyn MetricSink>) -> Self {
        Self { run, sink }
    }

    pub fn log_scalars(&self, step: Step, values: BTreeMap<String, f64>) -> Result<()> {
        let metric = Metric {
            run: self.run,
            step,
            timestamp: Utc::now(),
            values: values
                .into_iter()
                .map(|(k, v)| (k, MetricValue::Float(v)))
                .collect(),
        };
        self.sink.log(&metric)
    }

    pub fn flush(&self) -> Result<()> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_jsonl_lines() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunId::new();
        let sink = JsonlSink::open(dir.path(), run).unwrap();
        let logger = RunLogger::new(run, Box::new(sink));
        for step in 0..3 {
            logger
                .log_scalars(
                    step,
                    BTreeMap::from([("loss".into(), 1.0 / (step as f64 + 1.0))]),
                )
                .unwrap();
        }
        logger.flush().unwrap();
        let content =
            std::fs::read_to_string(dir.path().join(format!("{run}.metrics.jsonl"))).unwrap();
        assert_eq!(content.lines().count(), 3);
    }
}
