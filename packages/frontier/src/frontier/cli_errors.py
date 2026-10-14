# SPDX-License-Identifier: Apache-2.0
"""One line for a failure the user can act on, a traceback for everything else.

A command line ends with ``error: <what happened>`` and a non-zero status when the failure is
an expected one: a file or directory that is missing or not writable, an invalid config, or an
error class defined by a Frontier package (those describe a refused request, not a defect).
Any other exception keeps its traceback. ``FRONTIER_TRACEBACK=1`` shows the traceback always.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import Any, NoReturn

PATH_ERRORS = (FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError)


def is_expected(exc: BaseException) -> bool:
    if isinstance(exc, PATH_ERRORS):
        return True
    module = type(exc).__module__ or ""
    if module.split(".")[0].startswith("frontier"):
        return True
    return module.startswith("pydantic") and type(exc).__name__ == "ValidationError"


def message(exc: BaseException) -> str:
    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])  # str(KeyError) adds quotes
    if isinstance(exc, PATH_ERRORS) and exc.filename is not None and exc.strerror:
        return f"{exc.strerror}: {exc.filename}"
    return str(exc) or type(exc).__name__


def run(entry: Callable[[], Any], *, code: int = 2) -> NoReturn:
    """Call ``entry`` (a Typer app or a ``main`` returning a status) and exit with its status;
    an expected failure prints one line on stderr and exits with ``code``."""
    try:
        status = entry()
    except Exception as exc:
        if os.environ.get("FRONTIER_TRACEBACK") or not is_expected(exc):
            raise
        print(f"error: {message(exc)}", file=sys.stderr)
        sys.exit(code)
    sys.exit(status if isinstance(status, int) else 0)
