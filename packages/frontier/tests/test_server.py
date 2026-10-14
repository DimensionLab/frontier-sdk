# SPDX-License-Identifier: Apache-2.0
"""Server streaming tests against a tiny in-process HTTP server."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import frontier
from frontier._server import MetricStreamer, ServerClient


class _State:
    def __init__(self) -> None:
        self.projects: list[dict] = []
        self.runs: dict[str, dict] = {}
        self.metrics: dict[str, list[dict]] = {}
        self.artifacts: dict[str, list[tuple[str, int]]] = {}
        self.lock = threading.Lock()


def _make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # silence
            pass

        def _json(self, code: int, body=None) -> None:
            data = b"" if body is None else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(n)

        def do_GET(self):
            if self.path == "/api/v1/projects":
                self._json(200, state.projects)
            elif self.path.startswith("/api/v1/runs/"):
                rid = self.path.split("/")[4]
                run = state.runs.get(rid)
                self._json(200, run) if run else self._json(404, {"error": "no run"})
            else:
                self._json(404, {})

        def do_POST(self):
            parts = self.path.split("/")
            if self.path == "/api/v1/projects":
                body = json.loads(self._body())
                proj = {"id": f"p{len(state.projects) + 1}", "name": body["name"]}
                state.projects.append(proj)
                self._json(201, proj)
            elif self.path == "/api/v1/runs":
                body = json.loads(self._body())
                run = {"id": f"r{len(state.runs) + 1}", "state": "running", **body}
                state.runs[run["id"]] = run
                self._json(201, run)
            elif len(parts) == 6 and parts[5] == "metrics":
                body = json.loads(self._body())
                with state.lock:
                    state.metrics.setdefault(parts[4], []).extend(body)
                self._json(204)
            elif len(parts) == 6 and parts[5] == "artifacts":
                raw = self._body()
                # crude multipart parse: find the file part
                with state.lock:
                    state.artifacts.setdefault(parts[4], []).append(("file", len(raw)))
                self._json(200, {"name": "x", "size": len(raw), "url": "/x"})
            else:
                self._json(404, {})

        def do_PATCH(self):
            rid = self.path.split("/")[4]
            body = json.loads(self._body())
            state.runs[rid].update(body)
            self._json(200, state.runs[rid])

    return Handler


@pytest.fixture
def fake_server():
    state = _State()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{srv.server_port}"
    try:
        yield url, state
    finally:
        srv.shutdown()
        srv.server_close()


def test_streams_metrics_and_marks_finished(fake_server, tmp_path):
    url, state = fake_server
    with frontier.init(project="p", name="n", directory=tmp_path, server=url) as run:
        for i in range(250):
            run.log({"loss": 1.0 / (i + 1)}, step=i)
        run.summary["best"] = 0.1
        run.log_artifact(_write(tmp_path / "a.txt"), name="a.txt")

    assert run.server_run_id == "r1"
    assert state.projects[0]["name"] == "p"
    records = state.metrics["r1"]
    assert len(records) == 250
    assert [r["step"] for r in records] == list(range(250))
    assert state.runs["r1"]["state"] == "finished"
    assert state.runs["r1"]["summary"] == {"best": 0.1}
    assert state.artifacts["r1"]
    # offline copies are still written
    assert (tmp_path / "p" / f"{run.id}.metrics.jsonl").exists()
    assert (tmp_path / "p" / run.id / "artifacts" / "a.txt").read_text() == "hi"
    meta = json.loads((tmp_path / "p" / f"{run.id}.run.json").read_text())
    assert meta["state"] == "finished" and meta["summary"] == {"best": 0.1}


def test_reuses_existing_project(fake_server, tmp_path):
    url, state = fake_server
    state.projects.append({"id": "p42", "name": "p"})
    with frontier.init(project="p", name="n", directory=tmp_path, server=url) as run:
        run.log({"x": 1})
    assert state.runs["r1"]["project"] == "p42"


def test_env_run_id_attaches_to_existing_run(fake_server, tmp_path, monkeypatch):
    url, state = fake_server
    state.runs["r9"] = {"id": "r9", "state": "running"}
    monkeypatch.setenv("FRONTIER_SERVER", url)
    monkeypatch.setenv("FRONTIER_RUN_ID", "r9")
    with frontier.init(project="p", name="n", directory=tmp_path) as run:
        run.log({"x": 1})
    assert run.server_run_id == "r9"
    assert state.metrics["r9"][0]["values"] == {"x": 1.0}


def test_unreachable_server_falls_back_offline(tmp_path, caplog):
    with frontier.init(
        project="p", name="n", directory=tmp_path, server="http://127.0.0.1:9"
    ) as run:
        run.log({"loss": 1.0})
        run.log_artifact(_write(tmp_path / "a.txt"))
    assert run.server_run_id is None
    assert "unreachable" in caplog.text
    assert (tmp_path / "p" / f"{run.id}.metrics.jsonl").exists()


def test_failure_marks_run_failed(fake_server, tmp_path):
    url, state = fake_server
    with pytest.raises(RuntimeError):
        with frontier.init(project="p", name="n", directory=tmp_path, server=url):
            raise RuntimeError("boom")
    assert state.runs["r1"]["state"] == "failed"


def test_streamer_flushes_on_interval(fake_server):
    url, state = fake_server
    client = ServerClient(url)
    state.runs["r1"] = {"id": "r1"}
    streamer = MetricStreamer(client, "r1", flush_interval=0.05, flush_records=1000)
    streamer.log({"step": 0, "timestamp": "t", "values": {"a": 1.0}})
    deadline = time.time() + 2
    while time.time() < deadline and not state.metrics.get("r1"):
        time.sleep(0.01)
    assert state.metrics["r1"][0]["values"] == {"a": 1.0}
    streamer.close()
    client.close()


def _write(path):
    path.write_text("hi")
    return path
