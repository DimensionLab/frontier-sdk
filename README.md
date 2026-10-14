# frontier-sdk

Frontier Python SDK: offline-first experiment tracking for physics ML, the native Rust core, and the NVIDIA PhysicsNeMo bridge.

```python
import frontier

run = frontier.init(project="drivaer-surrogates", name="transolver-baseline", config={"lr": 1e-3})
for step in range(1000):
    run.log({"train/loss": 0.1, "cfd/cd_rel_err": 0.02}, step=step)
run.log_artifact("runs/best.pt", name="best.pt")
run.finish()
```

Offline first: with no server configured every run is written to local files you own
(`.frontier/<project>/<run>.metrics.jsonl`), so training on an air-gapped cluster needs
nothing but the package. Point `FRONTIER_SERVER` at a Frontier server and the same calls
stream there; a server that goes away never fails a training job.

Metric keys are namespaced for physics (`cfd/cd_rel_err`, `field/p/l2`), not just
`loss`.

## What is in this repository

- `crates/frontier-config/`: Rust crate `frontier-config`
- `crates/frontier-py/`: Rust crate `frontier-py`
- `crates/frontier-telemetry/`: Rust crate `frontier-telemetry`
- `packages/frontier/`: Python package `frontier`

`frontier-physicsnemo` hooks the SDK into NVIDIA PhysicsNeMo training recipes (PhysicsNeMo
itself is an optional dependency). `frontier-py` builds the optional `frontier-native` wheel
that moves local logging and connector detection into Rust.

## Extending

- **Metric sinks** implement `frontier_telemetry::MetricSink` (Rust) to forward metrics
  elsewhere (MLflow, W&B, your own store).
- **Integrations** for other training frameworks live in their own package and depend on
  `frontier` only; `frontier-physicsnemo` is the template.

The wire format (run JSON, metrics JSONL, REST calls) is documented in the package README
and versioned with the data model, so other tools can read and write it.

## Ecosystem

| Repository | What it is |
|---|---|
| [frontier-format](https://github.com/DimensionLab/frontier-format) | Frontier data model and dataset format: the frontier-dataset specification, the plugin contract, and reference readers/writers in Rust and Python. |
| [frontier-connectors](https://github.com/DimensionLab/frontier-connectors) | Connector plugins that turn CFD/CAE solver output (OpenFOAM, VTK, Fluent, STAR-CCM+, CGNS, LS-DYNA, ...) into Frontier datasets. Write your own in an afternoon. |
| **frontier-sdk** (this repository) | Frontier Python SDK: offline-first experiment tracking for physics ML, the native Rust core, and the NVIDIA PhysicsNeMo bridge. |
| [frontier-physicsnemo](https://github.com/DimensionLab/frontier-physicsnemo) | NVIDIA PhysicsNeMo plugin for Frontier: logging, model registry, checkpoint compatibility and dataset adapters. Installable independently of the platform. |
| [frontier-hub](https://github.com/DimensionLab/frontier-hub) | Curated hub of public physics-AI datasets and benchmarks: catalog, fetchers and converters to the Frontier dataset format. |
| [frontier-editor](https://github.com/DimensionLab/frontier-editor) | Editor core and GPU text view for physics-ML configs, recipes and logs: rope document, undo tree, hunks with per-hunk approval, tree-sitter syntax, JSON-Schema diagnostics, provenance events, and a wgpu renderer that draws into the host's render pass. |
| [frontier-viz](https://github.com/DimensionLab/frontier-viz) | GPU-accelerated (wgpu) rendering core for meshes, fields and neural-network topology: native, browser (WebGPU) and headless. |
| [foldstate](https://github.com/DimensionLab/foldstate) | Statecharts as data with an event log: a pure, deterministic kernel (state, event) -> (state, effects), replay, fork, restore and explanations. no_std + alloc, runs natively and in WebAssembly. Not specific to Frontier. |
| [frontier-zed](https://github.com/DimensionLab/frontier-zed) | Frontier for Zed: JSON schemas, snippets and the Frontier MCP context server for physics-ML training configs, RunSpecs, data-prep recipes, pipelines, hub entries and plugin manifests. A Zed extension (extension.toml plus a small wasm32-wasip2 crate), installable as a dev extension today and submitted to the Zed extension registry later. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under [Apache-2.0](LICENSE).
