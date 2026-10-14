# SPDX-License-Identifier: Apache-2.0
"""Run tracking: the `frontier.init()` / `run.log()` API.

The SDK is deliberately tiny and dependency-light so it can be imported inside any
training loop (PhysicsNeMo, raw PyTorch, JAX, ...). It writes newline-delimited JSON
locally and optionally streams to a Frontier server (`server=` or setting `client.server_url`).
If the Rust extension `frontier_native` is importable, the native logger is used instead of
the pure-Python one.

Offline layout under `directory/<project>/`:

```
<run_id>.run.json            # RunConfig + state + summary
<run_id>.metrics.jsonl       # one {"run","step","timestamp","values"} record per line
<run_id>/artifacts/<name>    # copies of files passed to run.log_artifact()
```
"""

from __future__ import annotations

import json
import logging
import math
import os
import shutil
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from frontier import config as _config
from frontier._server import MetricStreamer, ServerClient, ServerError

log = logging.getLogger("frontier")
# httpx logs every request at INFO; that is noise inside a training loop.
logging.getLogger("httpx").setLevel(logging.WARNING)

DEFAULT_DIR = Path(".frontier")


def default_dir() -> Path:
    """Where offline run records go: setting `client.offline_dir` (env `FRONTIER_DIR`)."""
    return _config.get_config().path("client.offline_dir") or DEFAULT_DIR


class RunConfig(BaseModel):
    project: str
    name: str
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    config: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class _JsonlLogger:
    def __init__(self, directory: Path, run_id: str) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / f"{run_id}.metrics.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")
        self.run_id = run_id

    def log(self, step: int, values: Mapping[str, float]) -> None:
        record = {
            "run": self.run_id,
            "step": step,
            "timestamp": datetime.now(UTC).isoformat(),
            "values": dict(values),
        }
        self._fh.write(json.dumps(record) + "\n")

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def _make_logger(directory: Path, run_id: str):
    try:
        import frontier_native  # type: ignore[import-not-found]
    except ImportError:
        return _JsonlLogger(directory, run_id)
    # The native logger uses UUIDv7 run ids; keep the id it generated. (Looked up by name:
    # an installed build from before the type stub shipped has no typed attributes.)
    native: Any = frontier_native
    return native.RunLogger(str(directory))


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, float):
        # JSON has no NaN/Infinity; strict encoders (httpx, the server) reject them.
        return value if math.isfinite(value) else None
    if isinstance(value, str | int | bool) or value is None:
        return value
    if hasattr(value, "item"):  # numpy / torch scalars
        try:
            return _json_safe(value.item())
        except Exception:  # pragma: no cover - defensive
            pass
    return str(value)


class Run:
    """A handle to an active run."""

    def __init__(
        self,
        cfg: RunConfig,
        directory: Path = DEFAULT_DIR,
        server: str | None = None,
    ) -> None:
        self.cfg = cfg
        self.directory = directory
        self._logger = _make_logger(directory / cfg.project, cfg.run_id)
        self.id = getattr(self._logger, "run_id", cfg.run_id)
        self._step = 0
        self._started = time.monotonic()
        self.state = "running"
        #: free-form final results (best metrics, dataset hash, ...); saved into run.json.
        self.summary: dict[str, Any] = {}
        self._meta_path = directory / cfg.project / f"{self.id}.run.json"
        self._artifact_dir = directory / cfg.project / self.id / "artifacts"

        self.server_url: str | None = server
        self.server_run_id: str | None = None
        self._client: ServerClient | None = None
        self._streamer: MetricStreamer | None = None
        if server:
            self._connect(server)
        self._write_meta()

    # -- server --------------------------------------------------------------------------

    def _connect(self, server: str) -> None:
        client = ServerClient(server)
        try:
            existing = os.environ.get("FRONTIER_RUN_ID")
            if existing:
                remote = client.get_run(existing)
            else:
                project_id = client.resolve_project(self.cfg.project)
                remote = client.create_run(
                    project_id, self.cfg.name, self.cfg.config, self.cfg.tags
                )
            self.server_run_id = str(remote["id"])
            if remote.get("state") != "running":
                try:
                    client.patch_run(self.server_run_id, state="running")
                except Exception as exc:  # noqa: BLE001 - never block training on the server
                    log.warning("frontier: could not mark run running (%s)", exc)
        except (ServerError, KeyError, TypeError, ValueError) as exc:
            log.warning("frontier: server %s unreachable (%s); logging offline only", server, exc)
            client.close()
            return
        self._client = client
        self._streamer = MetricStreamer(client, self.server_run_id)

    def _write_meta(self) -> None:
        meta = self.cfg.model_dump(mode="json")
        meta.update(
            {
                "id": self.id,
                "state": self.state,
                "summary": _json_safe(self.summary),
                "server": self.server_url,
                "server_run_id": self.server_run_id,
            }
        )
        self._meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # -- logging -------------------------------------------------------------------------

    def log(self, values: Mapping[str, float], step: int | None = None) -> None:
        """Log scalar metrics. Keys may be namespaced, e.g. ``cfd/cd_rel_err``."""
        if step is None:
            step = self._step
            self._step += 1
        else:
            self._step = step + 1
        clean = {k: float(v) for k, v in values.items()}
        self._logger.log(step, clean)
        # Non-finite values stay in the local JSONL (they are diagnostic) but are not
        # streamed: the wire format is strict JSON.
        clean = {k: v for k, v in clean.items() if math.isfinite(v)}
        if self._streamer is not None:
            self._streamer.log(
                {"step": step, "timestamp": datetime.now(UTC).isoformat(), "values": clean}
            )

    def log_artifact(self, path: str | os.PathLike[str], name: str | None = None) -> Path:
        """Store a file as a run artifact (offline copy + server upload when connected).

        Returns the path of the offline copy.
        """
        src = Path(path)
        if not src.is_file():
            raise FileNotFoundError(src)
        name = name or src.name
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        dst = self._artifact_dir / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.resolve() != dst.resolve():
            shutil.copyfile(src, dst)
        if self._client is not None and self.server_run_id is not None:
            try:
                self._client.upload_artifact(self.server_run_id, dst, name)
            except ServerError as exc:
                log.warning("frontier: artifact upload of %s failed (%s)", name, exc)
        return dst

    @property
    def artifact_dir(self) -> Path:
        return self._artifact_dir

    # -- lifecycle -----------------------------------------------------------------------

    def finish(self, state: str = "finished") -> None:
        if self.state not in ("running",):
            return
        self.state = state
        self._logger.flush()
        close = getattr(self._logger, "close", None)
        if close is not None:
            close()
        if self._streamer is not None:
            self._streamer.close()
        if self._client is not None and self.server_run_id is not None:
            try:
                self._client.patch_run(
                    self.server_run_id, state=state, summary=_json_safe(self.summary)
                )
            except Exception as exc:  # noqa: BLE001 - finishing must never crash training
                log.warning("frontier: could not mark run %s (%s)", state, exc)
            self._client.close()
        self._write_meta()

    def __enter__(self) -> Run:
        return self

    def __exit__(self, exc_type: object, *exc: object) -> None:
        self.finish("failed" if exc_type is not None else "finished")


def init(
    project: str,
    name: str,
    config: Mapping[str, Any] | None = None,
    tags: list[str] | None = None,
    directory: str | os.PathLike[str] | None = None,
    server: str | None = None,
) -> Run:
    """Start a run. Mirrors the ergonomics people know from W&B / MLflow.

    `server` defaults to the setting `client.server_url` (config files, or the environment
    variable `FRONTIER_SERVER`) and `directory` to `client.offline_dir` (`FRONTIER_DIR`).
    With a server, the run is registered there and metrics are streamed in batches from a
    background thread; the offline JSONL is always written.
    """
    cfg = RunConfig(
        project=project,
        name=name,
        config=_json_safe(dict(config or {})),
        tags=list(tags or []),
    )
    if server is None:
        server = _config.get_config().opt_str("client.server_url")
    return Run(cfg, Path(directory) if directory else default_dir(), server=server)
