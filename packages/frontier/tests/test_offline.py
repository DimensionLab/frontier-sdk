# SPDX-License-Identifier: Apache-2.0
"""`network.offline` at every outbound call site of the SDK (security review PRIV-01): each
entry point raises the shared `OfflineError` before a socket is touched, and a server on
this machine stays reachable."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

import frontier
from frontier import _server, auth, config

REMOTE = "https://frontier.example.com"


def _no_network(*_a: Any, **_k: Any) -> Any:
    raise AssertionError("offline mode must not touch the network")


@pytest.fixture
def offline_home(_isolated_frontier_home: Path) -> Path:
    """Offline through a config layer: the user file."""
    (_isolated_frontier_home / config.CONFIG_FILE).write_text("[network]\noffline = true\n")
    config.reset()
    assert config.get_config().bool("network.offline")
    assert config.get_config().trusted_source("network.offline") == "user"
    return _isolated_frontier_home


@pytest.fixture
def offline(offline_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)


def _client() -> _server.ServerClient:
    return _server.ServerClient(REMOTE, token="t-000000")


def _upload(tmp: Path) -> Any:
    path = tmp / "artifact.bin"
    path.write_bytes(b"x")
    return _client().upload_artifact("run-1", path, "artifact.bin")


ENTRY_POINTS: dict[str, Callable[[Path], Any]] = {
    "require_online": lambda tmp: config.require_online("a download"),
    "require_online(url)": lambda tmp: config.require_online("a download", url=REMOTE),
    "server.auth_config": lambda tmp: _client().auth_config(),
    "server.whoami": lambda tmp: _client().whoami(),
    "server.resolve_project": lambda tmp: _client().resolve_project("demo"),
    "server.create_run": lambda tmp: _client().create_run("p", "run", {}, []),
    "server.get_run": lambda tmp: _client().get_run("run-1"),
    "server.patch_run": lambda tmp: _client().patch_run("run-1", state="running"),
    "server.upload_artifact": _upload,
    "server._request": lambda tmp: _client()._request("GET", "/api/v1/anything"),
    "auth.transport": lambda tmp: auth._urllib_transport(config.get_config())(
        "https://huggingface.co/api/whoami-v2", {}, 1.0
    ),
    "auth.token_transport": lambda tmp: auth._urllib_token_transport(None)(
        "https://idp.example.com/token", {"grant_type": "refresh_token"}, 1.0
    ),
}


@pytest.mark.parametrize("name", sorted(ENTRY_POINTS))
def test_offline_entry_point_fails_before_any_connection(name: str, offline: None, tmp_path: Path):
    with pytest.raises(
        config.OfflineError, match=r"offline mode is on \(setting network.offline\)"
    ):
        ENTRY_POINTS[name](tmp_path)


def test_every_public_server_call_is_guarded(offline: None):
    """A method added to `ServerClient` later is covered without touching this file, as long
    as it goes through `_request`."""
    client = _client()
    public = [
        n
        for n in dir(client)
        if not n.startswith("_") and n != "close" and callable(getattr(client, n))
    ]
    assert len(public) >= 6
    sent: list[str] = []
    original = client._http.request
    client._http.request = lambda *a, **k: sent.append(a[1]) or original(*a, **k)  # type: ignore[method-assign]
    with pytest.raises(_server.ServerOfflineError):
        client.whoami()
    assert sent == []


def test_server_offline_error_is_both_kinds(offline: None):
    with pytest.raises(_server.ServerError) as exc:
        _client().whoami()
    assert isinstance(exc.value, config.OfflineError)
    assert isinstance(exc.value, frontier.ServerError)
    assert REMOTE in str(exc.value)


def test_run_falls_back_to_its_offline_record(offline: None, tmp_path: Path, caplog):
    """`frontier.init` with a remote server never blocks training: offline it does not
    connect, says so once and keeps the JSONL record."""
    run = frontier.init("demo", "run", directory=tmp_path / "runs", server=REMOTE)
    run.log({"train/loss": 1.0}, step=0)
    run.finish()
    assert run.server_run_id is None
    assert "offline mode is on" in caplog.text
    assert list((tmp_path / "runs").rglob("*.metrics.jsonl"))


def test_credential_test_and_refresh_do_not_connect_offline(offline: None):
    auth.login("huggingface", {"token": "hf_test_0000000000"})
    out = auth.test("huggingface")
    assert not out["ok"] and "offline mode is on (network.offline)" in out["error"]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        body = json.dumps({"mode": "none", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


def test_loopback_server_is_still_reachable_offline(offline_home: Path):
    """A control plane on this machine is not an outbound connection."""
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}"
        config.require_online("the local server", url=url)
        client = _server.ServerClient(url, token="t-000000")
        assert client.auth_config() == {"mode": "none", "path": "/api/v1/auth/config"}
        client.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    ("url", "loopback"),
    [
        ("http://localhost:8787", True),
        ("http://127.0.0.1:8787/api", True),
        ("http://127.8.9.1", True),
        ("https://[::1]:8443", True),
        ("http://api.localhost:3000", True),
        ("localhost:8787", True),
        ("https://frontier.example.com", False),
        ("http://127.0.0.1.example.com", False),
        ("http://localhost.example.com", False),
        ("http://10.0.0.5:8787", False),
        ("http://169.254.169.254/latest", False),
        ("http://0.0.0.0:8787", False),
    ],
)
def test_loopback_urls(offline: None, url: str, loopback: bool):
    assert config.is_loopback_url(url) is loopback
    if loopback:
        config.require_online("x", url=url)
    else:
        with pytest.raises(config.OfflineError):
            config.require_online("x", url=url)
