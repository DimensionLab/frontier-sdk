# SPDX-License-Identifier: Apache-2.0
"""Type stub of the native module (crates/frontier-py). maturin ships this file with the
wheel; keep it in step with `#[pymodule] fn frontier_native` in src/lib.rs."""

from os import PathLike
from typing import Any

__version__: str
DATA_MODEL_VERSION: int

class RunLogger:
    """Appends scalar metrics of one run to `<dir>/<run id>/metrics.jsonl`."""

    def __init__(self, dir: str | PathLike[str], run_id: str | None = None) -> None: ...
    @property
    def run_id(self) -> str: ...
    def log(self, step: int, values: dict[str, float]) -> None: ...
    def flush(self) -> None: ...

def detect(path: str | PathLike[str]) -> list[tuple[str, float]]:
    """Connectors that can read `path`: `[(connector_id, confidence), ...]`."""

def describe(path: str | PathLike[str]) -> str:
    """Metadata of the sample at `path`, as a JSON string."""

def connector_ids() -> list[str]: ...

# `frontier_native.prep`: the data-preparation kernels (src/prep.rs). Their signatures take
# and return NumPy arrays; they are documented in docs/spec/data-prep.md, section 11, and
# typed loosely here.
prep: Any
