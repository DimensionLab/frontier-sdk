# SPDX-License-Identifier: Apache-2.0
"""The SDK presents a token to the control plane and explains refusals."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from frontier import auth
from frontier import config as _config
from frontier._server import ServerAuthError, ServerClient, ServerError


@pytest.fixture
def guarded_server():
    """A server that wants `Bearer good-token`, answers like frontier-server otherwise."""
    seen: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def _json(self, code: int, body: object, headers: dict[str, str] | None = None) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            seen.append({k.lower(): v for k, v in self.headers.items()})
            token = self.headers.get("Authorization", "")
            if self.path == "/api/v1/auth/config":
                self._json(200, {"mode": "token"})
            elif token == "Bearer viewer-token" and self.path == "/api/v1/settings":
                self._json(
                    403,
                    {
                        "error": "forbidden: `settings.write` needs the role admin",
                        "status": "forbidden",
                        "permission": "settings.write",
                    },
                )
            elif token in ("Bearer good-token", "Bearer viewer-token"):
                self._json(200, {"user": {"name": "ada"}, "role": "member", "mode": "token"})
            else:
                self._json(
                    401,
                    {
                        "error": "authentication required",
                        "status": "unauthenticated",
                        "auth": {"mode": "token", "config_url": "/api/v1/auth/config"},
                    },
                    {"WWW-Authenticate": 'Bearer realm="frontier", auth_mode="token"'},
                )

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}", seen
    finally:
        srv.shutdown()
        srv.server_close()


def _reload_config() -> None:
    reset = getattr(_config, "reset_config", None) or getattr(_config, "_reset", None)
    if reset:
        reset()


def test_token_from_the_environment_is_sent_as_bearer(guarded_server, monkeypatch):
    url, seen = guarded_server
    monkeypatch.setenv("FRONTIER_TOKEN", "good-token")
    _reload_config()
    client = ServerClient(url, project="aero")
    assert client.whoami()["user"]["name"] == "ada"
    assert seen[-1]["authorization"] == "Bearer good-token"
    assert seen[-1]["x-frontier-project"] == "aero"
    assert client.auth_config()["mode"] == "token"


def test_an_explicit_token_wins(guarded_server, monkeypatch):
    url, seen = guarded_server
    monkeypatch.setenv("FRONTIER_TOKEN", "stale")
    _reload_config()
    assert ServerClient(url, token="good-token").whoami()["role"] == "member"
    assert seen[-1]["authorization"] == "Bearer good-token"


def test_401_says_how_to_sign_in(guarded_server):
    url, seen = guarded_server
    with pytest.raises(ServerAuthError) as err:
        ServerClient(url).whoami()
    assert "authorization" not in seen[-1]
    assert err.value.status == 401
    assert err.value.auth_mode == "token"
    assert "frontier login" in str(err.value) and "FRONTIER_TOKEN" in str(err.value)
    assert isinstance(err.value, ServerError)  # callers that fall back offline still do


def test_403_names_the_permission(guarded_server):
    url, _ = guarded_server
    with pytest.raises(ServerAuthError) as err:
        ServerClient(url, token="viewer-token")._request("GET", "/api/v1/settings")
    assert err.value.status == 403
    assert err.value.permission == "settings.write"
    assert "frontier login" not in str(err.value)


def test_local_token_of_a_single_user_server_is_found_by_port(guarded_server):
    url, seen = guarded_server
    port = url.rsplit(":", 1)[1]
    servers = Path(os.environ["FRONTIER_HOME"]) / "servers"
    servers.mkdir(parents=True, exist_ok=True)
    (servers / f"{port}.token").write_text("good-token\n", encoding="utf-8")
    assert auth.local_server_token(url) == "good-token"
    assert auth.server_token(url) == "good-token"
    assert auth.server_headers(url) == {"Authorization": "Bearer good-token"}
    assert ServerClient(url).whoami()["user"]["name"] == "ada"
    assert seen[-1]["authorization"] == "Bearer good-token"
    # never for a server that is not this machine, whatever the port
    assert auth.local_server_token(f"https://frontier.example.com:{port}") is None
    assert auth.local_server_token(f"http://127.0.0.1.evil.example:{port}") is None
    assert auth.local_server_token("http://127.0.0.1:1") is None
    assert auth.server_token() is None


def test_a_token_kept_for_one_server_is_used_for_that_server_only(guarded_server, monkeypatch):
    url, seen = guarded_server
    monkeypatch.setenv("FRONTIER_TOKEN", "stale-global-token")
    _reload_config()
    key = auth.server_key(url)
    assert key is not None and key == url.removeprefix("http://").replace(":", "_")
    auth.resolver().store.set(auth.SERVER_TOKENS, key, "good-token")
    assert auth.server_token(url) == "good-token"
    assert ServerClient(url).whoami()["user"]["name"] == "ada"
    assert seen[-1]["authorization"] == "Bearer good-token"
    # another server gets the global credential, never this one's token
    assert auth.server_token("https://abc-8787.proxy.example.net") == "stale-global-token"
    key = auth.server_key("https://ABC-8787.proxy.example.net/api/v1")
    assert key == "abc-8787.proxy.example.net"
    for bad in ("ftp://x", "https://../etc", "https://user@host", "not a url"):
        assert auth.server_key(bad) is None


def test_remote_secret_stores_are_read_through_the_command_line(tmp_path, monkeypatch):
    """`secrets.backend = vault|aws|azure|gcp`: the SDK asks `frontier secrets helper`."""
    calls = tmp_path / "calls.log"
    stored = tmp_path / "stored"
    stored.mkdir()
    fake = tmp_path / "frontier"
    # a stand-in for the command line with the helper's contract: value on stdout, exit 3
    # for a missing entry, the value to store on stdin, an error on stderr
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{calls}"\n'
        '[ "$1 $2" = "secrets helper" ] || exit 64\n'
        '[ "$4" = "broken" ] && { echo "Error: Vault refused (HTTP 403)" >&2; exit 1; }\n'
        f'f="{stored}/$4.$5"\n'
        'case "$3" in\n'
        '  get) [ -f "$f" ] || exit 3; cat "$f" ;;\n'
        '  set) cat > "$f" ;;\n'
        '  delete) [ -f "$f" ] || exit 3; rm "$f" ;;\n'
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("FRONTIER_CLI", str(fake))
    monkeypatch.setenv("FRONTIER_SECRETS__BACKEND", "vault")
    _reload_config()
    store = auth.resolver().store
    assert store.name == "vault"
    assert store.get("huggingface", "token") is None
    store.set("huggingface", "token", "hf_in_vault")
    assert store.get("huggingface", "token") == "hf_in_vault"
    found = auth.resolve("huggingface")
    assert found is not None and found.value == "hf_in_vault"
    assert store.delete("huggingface", "token") is True
    assert store.delete("huggingface", "token") is False
    # the value never travels on the command line
    assert "hf_in_vault" not in calls.read_text(encoding="utf-8")
    with pytest.raises(auth.AuthError, match="HTTP 403"):
        store.get("broken", "token")
    # without the command line the reason is said, not a silent "not configured"
    monkeypatch.setenv("FRONTIER_CLI", "")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    _reload_config()
    with pytest.raises(auth.AuthError, match="FRONTIER_CLI"):
        auth.resolver().store.get("huggingface", "token")
