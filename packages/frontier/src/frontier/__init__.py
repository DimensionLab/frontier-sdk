# SPDX-License-Identifier: Apache-2.0
"""DimensionLab Frontier Python SDK.

The run-tracking API (``init``, ``Run``, ``ServerClient`` ...) is imported on first use, so
``import frontier.config`` and ``import frontier.auth`` stay light (standard library only).
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from frontier._version import __version__

if TYPE_CHECKING:
    from frontier._run import Run, RunConfig, init
    from frontier._server import ServerClient, ServerError

__all__ = ["Run", "RunConfig", "ServerClient", "ServerError", "init", "__version__"]

_LAZY = {
    "Run": "frontier._run",
    "RunConfig": "frontier._run",
    "init": "frontier._run",
    "ServerClient": "frontier._server",
    "ServerError": "frontier._server",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY})
