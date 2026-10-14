# SPDX-License-Identifier: Apache-2.0
"""Unit tests configuration module."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_frontier_home(tmp_path_factory, monkeypatch):
    """No test reads the developer's own configuration, credentials or `.env`."""
    home = tmp_path_factory.mktemp("frontier-home")
    monkeypatch.setenv("FRONTIER_HOME", str(home))
    monkeypatch.setenv("FRONTIER_DEV", "0")
    monkeypatch.setenv("FRONTIER_SECRETS__BACKEND", "file")
    for var in ("FRONTIER_TOKEN", "FRONTIER_SERVER", "FRONTIER_DIR", "FRONTIER_CREDENTIALS_BOUND"):
        monkeypatch.delenv(var, raising=False)
    from frontier import config

    config.reset()
    yield home
    config.reset()
