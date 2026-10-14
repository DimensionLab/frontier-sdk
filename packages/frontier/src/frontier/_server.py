# SPDX-License-Identifier: Apache-2.0
"""HTTP client for a Frontier server (`frontier-server`, REST API from docs/spec/api.md).

Everything here is best-effort: a training loop must never die because the tracking server
is down. Errors are logged once as a warning and the run falls back to offline JSONL.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx

from frontier import auth as _auth
from frontier import config as _config

log = logging.getLogger("frontier")

DEFAULT_FLUSH_INTERVAL_S = 1.0
DEFAULT_FLUSH_RECORDS = 100
MAX_BUFFERED_RECORDS = 50_000


class ServerError(RuntimeError):
    """Raised by :class:`ServerClient` when the server rejects or cannot be reached."""


class ServerAuthError(ServerError):
    """The server refused the caller: not signed in (401) or not allowed (403).

    `status` is the HTTP status, `auth_mode` the server's `auth.mode` when it said so
    (`token`, `oidc`), `permission` the permission a 403 names.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        auth_mode: str | None = None,
        permission: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.auth_mode = auth_mode
        self.permission = permission


class ServerOfflineError(ServerError, _config.OfflineError):
    """A request to a server that is not on this machine while ``network.offline`` is set.
    Nothing was sent. It is both a :class:`ServerError` (a run falls back to its offline
    record) and a :class:`frontier.config.OfflineError`."""


def _stored_token(base_url: str | None = None) -> str | None:
    """The `frontier` credential, else the local token of a single-user server at
    `base_url`, or `None`. Never raises: tracking is best-effort."""
    return _auth.server_token(base_url)


def _auth_error(method: str, path: str, resp: httpx.Response) -> ServerAuthError:
    """A refusal as something a person can act on."""
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    detail = str(body.get("error") or resp.text[:200])
    if resp.status_code == 401:
        info = body.get("auth")
        mode = info.get("mode") if isinstance(info, dict) else None
        hint = (
            "sign in with `frontier login` (or set FRONTIER_TOKEN to an API token of this server)"
        )
        return ServerAuthError(
            f"{method} {path}: HTTP 401 {detail}; {hint}", status=401, auth_mode=mode
        )
    permission = body.get("permission")
    return ServerAuthError(
        f"{method} {path}: HTTP 403 {detail}",
        status=403,
        permission=permission if isinstance(permission, str) else None,
    )


class ServerClient:
    """Thin synchronous wrapper over the `frontier-server` REST API.

    The bearer token is `token`, else the `frontier` credential (`frontier login`, or
    `FRONTIER_TOKEN` in the environment). A server in single-user mode (`auth.mode =
    "none"`) ignores it. `project` (an id or a name) is sent as `X-Frontier-Project`: the
    project that datasets and jobs created through this client belong to. `timeout`
    defaults to the setting `client.request_timeout_secs`.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float | None = None,
        token: str | None = None,
        project: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        headers = {}
        if not token:
            token = _stored_token(self.base_url)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if project:
            headers["X-Frontier-Project"] = project
        if timeout is None:
            timeout = float(_config.get_config().int("client.request_timeout_secs") or 30)
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, headers=headers)

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            _config.require_online(f"reaching the server {self.base_url}", url=self.base_url)
        except _config.OfflineError as exc:
            raise ServerOfflineError(f"{method} {path}: {exc}") from exc
        try:
            resp = self._http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise ServerError(f"{method} {path}: {exc}") from exc
        if resp.status_code in (401, 403):
            raise _auth_error(method, path, resp)
        if resp.status_code >= 400:
            raise ServerError(f"{method} {path}: HTTP {resp.status_code} {resp.text[:200]}")
        return resp

    def close(self) -> None:
        self._http.close()

    # -- identity ------------------------------------------------------------------------

    def auth_config(self) -> dict[str, Any]:
        """How this server authenticates callers (`mode`: `none`, `token` or `oidc`)."""
        return self._request("GET", "/api/v1/auth/config").json()

    def whoami(self) -> dict[str, Any]:
        """The identity, role and permissions this client acts with."""
        return self._request("GET", "/api/v1/auth/whoami").json()

    # -- projects / runs -----------------------------------------------------------------

    def resolve_project(self, name: str) -> str:
        """Return the id of project `name`, creating it when missing."""
        for proj in self._request("GET", "/api/v1/projects").json():
            if proj.get("name") == name:
                return str(proj["id"])
        created = self._request("POST", "/api/v1/projects", json={"name": name}).json()
        return str(created["id"])

    def create_run(
        self,
        project_id: str,
        name: str,
        config: Mapping[str, Any],
        tags: list[str],
    ) -> dict[str, Any]:
        body = {"project": project_id, "name": name, "config": dict(config), "tags": list(tags)}
        return self._request("POST", "/api/v1/runs", json=body).json()

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/runs/{run_id}").json()

    def patch_run(self, run_id: str, **fields: Any) -> dict[str, Any]:
        return self._request("PATCH", f"/api/v1/runs/{run_id}", json=fields).json()

    def post_metrics(self, run_id: str, records: list[dict[str, Any]]) -> None:
        self._request("POST", f"/api/v1/runs/{run_id}/metrics", json=records)

    def upload_artifact(self, run_id: str, path: Path, name: str) -> dict[str, Any]:
        with path.open("rb") as fh:
            files = {"file": (name, fh, "application/octet-stream")}
            resp = self._request(
                "POST", f"/api/v1/runs/{run_id}/artifacts", files=files, data={"name": name}
            )
        return resp.json() if resp.content else {"name": name, "size": path.stat().st_size}


class MetricStreamer:
    """Buffers metric records and flushes them to the server from a background thread.

    Flushes whenever `flush_records` are buffered or `flush_interval` seconds elapsed.
    Transport failures are reported once; records that fail to send are dropped (the
    offline JSONL on disk remains the source of truth).
    """

    def __init__(
        self,
        client: ServerClient,
        run_id: str,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL_S,
        flush_records: int = DEFAULT_FLUSH_RECORDS,
    ) -> None:
        self._client = client
        self._run_id = run_id
        self._interval = flush_interval
        self._batch_size = flush_records
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(MAX_BUFFERED_RECORDS)
        self._stop = threading.Event()
        self._warned = False
        self.dropped = 0
        self.sent = 0
        self._thread = threading.Thread(target=self._loop, name="frontier-metrics", daemon=True)
        self._thread.start()

    def log(self, record: Mapping[str, Any]) -> None:
        try:
            self._queue.put_nowait(dict(record))
        except queue.Full:
            self.dropped += 1

    def _warn_once(self, exc: Exception) -> None:
        if not self._warned:
            self._warned = True
            log.warning("frontier: metric streaming to server failed (%s); continuing offline", exc)

    def _send(self, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        try:
            self._client.post_metrics(self._run_id, batch)
            self.sent += len(batch)
        except ServerError as exc:
            self.dropped += len(batch)
            self._warn_once(exc)

    def _loop(self) -> None:
        batch: list[dict[str, Any]] = []
        deadline = time.monotonic() + self._interval
        while True:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                item = ...
            if item is None:  # sentinel: flush and exit
                self._send(batch)
                return
            if item is not ...:
                batch.append(item)  # type: ignore[arg-type]
            if len(batch) >= self._batch_size or time.monotonic() >= deadline:
                self._send(batch)
                batch = []
                deadline = time.monotonic() + self._interval

    def close(self, timeout: float = 10.0) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self._queue.put(None)
        self._thread.join(timeout)
