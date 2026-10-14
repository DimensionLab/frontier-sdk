# SPDX-License-Identifier: Apache-2.0
"""Owner-only files and directories (standard library only).

Everything Frontier keeps for one user (credentials, token caches, key files, session
records, judgment caches) is created ``0700`` / ``0600`` and tightened again on every write.
Nothing here ever widens a mode. On Windows the modes are a no-op: the profile directory's
ACL is what protects the files there.

    from frontier._private import private_dir, write_private, open_private_append

    d = private_dir(home / "agent")                  # 0700, existing directory tightened
    write_private(d / "state.json", "{}")            # atomic, 0600
    with open_private_append(d / "session.jsonl") as fh:   # 0600, text, append
        fh.write(line)
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import IO

DIR_MODE = 0o700
FILE_MODE = 0o600

_POSIX = os.name == "posix"


def _tighten(path: str | os.PathLike[str], limit: int) -> None:
    """Remove every permission bit outside ``limit``; never add one."""
    if not _POSIX:
        return
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & ~limit:
            os.chmod(path, mode & limit)
    except OSError:
        pass  # not ours to change (another owner, a read-only mount): the caller still works


def private_dir(path: str | os.PathLike[str]) -> Path:
    """Create ``path`` as a directory only its owner can enter (``0700``) and return it. A
    directory that already exists loses its group and other bits. Missing parents are
    created with the process umask: only the leaf is private."""
    p = Path(path)
    try:
        p.mkdir(mode=DIR_MODE)
    except FileExistsError:
        pass
    except FileNotFoundError:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.mkdir(mode=DIR_MODE, exist_ok=True)
    _tighten(p, DIR_MODE)
    return p


def write_private(path: str | os.PathLike[str], data: str | bytes) -> Path:
    """Write ``data`` to ``path`` atomically (temporary file in the same directory, then a
    rename) with mode ``0600``. Text is encoded as UTF-8. The parent directory is created
    with the process umask when missing; use :func:`private_dir` first to make it private."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    tmp = p.with_name(f"{p.name}.tmp{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(tmp, flags, FILE_MODE)
    except FileExistsError:  # a crashed writer with our pid: start over
        os.unlink(tmp)
        fd = os.open(tmp, flags, FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        _tighten(tmp, FILE_MODE)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


def open_private_append(path: str | os.PathLike[str], *, encoding: str = "utf-8") -> IO[str]:
    """Open ``path`` for appending text, creating it ``0600`` and tightening a file that
    already exists. The parent directory is created with the process umask when missing."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, FILE_MODE)
    _tighten(p, FILE_MODE)
    return os.fdopen(fd, "a", encoding=encoding)


def ensure_private(path: str | os.PathLike[str]) -> None:
    """Tighten an existing file (to ``0600``) or directory (to ``0700``); nothing is created
    and a missing path is not an error."""
    p = Path(path)
    if p.is_dir():
        _tighten(p, DIR_MODE)
    elif p.exists():
        _tighten(p, FILE_MODE)


__all__ = [
    "DIR_MODE",
    "FILE_MODE",
    "ensure_private",
    "open_private_append",
    "private_dir",
    "write_private",
]
