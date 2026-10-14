# SPDX-License-Identifier: Apache-2.0
"""Owner-only files (security review SEC-01): what `frontier.auth` writes under the Frontier
home is 0600 in a 0700 directory, and the shared helper never widens a mode."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from frontier import _private, auth, config
from frontier._private import ensure_private, open_private_append, private_dir, write_private

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture(autouse=True)
def permissive_umask():
    """The modes must not depend on the umask of whoever runs the process."""
    old = os.umask(0o000)
    yield
    os.umask(old)


def test_private_dir_creates_0700_and_tightens_an_existing_one(tmp_path: Path):
    d = private_dir(tmp_path / "a" / "b" / "secrets")
    assert d.is_dir() and mode(d) == 0o700
    wide = tmp_path / "wide"
    wide.mkdir(mode=0o755)
    assert mode(wide) == 0o755
    assert private_dir(wide) == wide and mode(wide) == 0o700
    # never widened: a stricter directory keeps its mode
    strict = tmp_path / "strict"
    strict.mkdir(mode=0o500)
    private_dir(strict)
    assert mode(strict) == 0o500
    strict.chmod(0o700)


def test_write_private_is_atomic_0600_and_tightens_on_rewrite(tmp_path: Path):
    path = tmp_path / "state" / "token.json"
    assert write_private(path, '{"a": 1}') == path
    assert path.read_text() == '{"a": 1}' and mode(path) == 0o600
    path.chmod(0o644)
    write_private(path, b"\x00\x01")
    assert path.read_bytes() == b"\x00\x01" and mode(path) == 0o600
    assert [p.name for p in path.parent.iterdir()] == ["token.json"]  # no temporary left
    # a stale temporary of a crashed writer (same pid) does not get in the way, and a
    # symlink planted at the temporary name is not written through
    victim = tmp_path / "victim"
    victim.write_text("keep")
    tmp = path.with_name(f"{path.name}.tmp{os.getpid()}")
    os.symlink(victim, tmp)
    write_private(path, "new")
    assert path.read_text() == "new" and victim.read_text() == "keep"
    assert not path.is_symlink()


def test_open_private_append_creates_0600_and_tightens(tmp_path: Path):
    path = tmp_path / "sessions" / "s1.jsonl"
    with open_private_append(path) as fh:
        fh.write("one\n")
    assert mode(path) == 0o600
    path.chmod(0o664)
    with open_private_append(path) as fh:
        fh.write("two\n")
    assert path.read_text() == "one\ntwo\n" and mode(path) == 0o600
    strict = tmp_path / "strict.log"
    strict.touch(mode=0o400)
    strict.chmod(0o400)
    ensure_private(strict)
    assert mode(strict) == 0o400  # never widened


def test_ensure_private_tightens_files_and_directories(tmp_path: Path):
    f, d = tmp_path / "f", tmp_path / "d"
    f.write_text("x")
    f.chmod(0o666)
    d.mkdir(mode=0o777)
    ensure_private(f)
    ensure_private(d)
    ensure_private(tmp_path / "missing")
    assert (mode(f), mode(d)) == (0o600, 0o700)
    assert not (tmp_path / "missing").exists()
    assert (_private.FILE_MODE, _private.DIR_MODE) == (0o600, 0o700)


def test_credentials_file_and_home_are_private(_isolated_frontier_home: Path):
    home = _isolated_frontier_home
    home.chmod(0o755)
    auth.login("huggingface", {"token": "hf_test_0000000000"})
    creds = home / auth.CREDENTIALS_FILE
    assert mode(creds) == 0o600
    assert mode(home) == 0o700
    # a file somebody widened is tightened by the next write
    creds.chmod(0o640)
    home.chmod(0o750)
    # a widened file is not read at all: the store is reported unavailable and the
    # credential does not resolve (the environment fallback is the only other source)
    assert auth.resolve("huggingface") is None
    with pytest.raises(auth.AuthError, match="readable by other users"):
        auth.resolver().store.get("huggingface", "token")
    creds.chmod(0o600)
    auth.login("runpod", {"api_key": "rp_test_0000000000"})
    assert mode(creds) == 0o600 and mode(home) == 0o700


def test_frontier_home_is_created_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "fresh" / "frontier-home"
    monkeypatch.setenv("FRONTIER_HOME", str(home))
    config.reset()
    auth.login("huggingface", {"token": "hf_test_0000000000"})
    assert mode(home) == 0o700 and mode(home / auth.CREDENTIALS_FILE) == 0o600


def test_test_state_and_every_other_file_under_home_is_private(_isolated_frontier_home: Path):
    home = _isolated_frontier_home
    auth.login("huggingface", {"token": "hf_test_0000000000"})
    auth.resolver().record_test("huggingface", True, "ok")
    state = home / auth.STATE_FILE
    assert state.is_file() and mode(state) == 0o600
    for path in home.rglob("*"):
        limit = 0o700 if path.is_dir() else 0o600
        assert mode(path) & ~limit == 0, f"{path} is {mode(path):o}"


def test_atomic_write_never_widens(tmp_path: Path):
    path = tmp_path / "new-dir" / "x.toml"
    auth.atomic_write(path, "a = 1\n", 0o644)  # a wider mode is not honoured
    assert mode(path) == 0o600 and mode(path.parent) == 0o700
    auth.atomic_write(path, "a = 2\n", 0o400)  # a stricter one is
    assert mode(path) == 0o400
    path.chmod(0o600)
    # an existing directory that is not the Frontier home is left alone
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    auth.atomic_write(shared / "y.toml", "b = 1\n")
    assert mode(shared) == 0o755 and mode(shared / "y.toml") == 0o600
