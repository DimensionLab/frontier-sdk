# SPDX-License-Identifier: Apache-2.0
"""Layered configuration (standard library only; safe to import anywhere).

The same files, keys, precedence and messages as the ``frontier`` command line. Precedence,
lowest to highest:

1. built-in defaults (the settings registry, ``config_schema.json``)
2. system file ``/etc/frontier/config.toml`` (an administrator may **lock** keys there)
3. server layer: the policy file named by ``FRONTIER_SERVER_CONFIG`` (written by the control
   plane for the jobs it launches; see :func:`server_path`)
4. user file ``~/.frontier/config.toml`` (``FRONTIER_HOME`` moves it)
5. project file: the nearest ``frontier.toml`` walking up from the working directory
6. developer ``.env`` (only with ``FRONTIER_DEV=1``)
7. environment: ``FRONTIER_<SECTION>__<KEY>`` (and the legacy names listed per setting)
8. explicit overrides passed by the caller (command-line flags)

Precedence is not trust. Not every layer may set every key (see :func:`restriction`):

* ``admin`` keys (organisation policy: ``policy.*`` keys the registry marks as server or
  system scope or admin-edited, and every server-scope key) are accepted only from the
  system file and the server layer.
* ``trusted`` keys (code execution and the network: ``compute.python``, ``network.*``,
  ``client.server_url``, ``hub.extra_catalogs``, ``plugins.index_url``,
  ``policy.ai.local_endpoint``, and every other system-scope or admin-edited key) are never
  accepted from a project ``frontier.toml`` or a ``.env``: a cloned repository must not
  configure what runs or where credentials are sent.
* Any layer may *tighten* a restricted key (:func:`tightens`): ``network.offline = true``,
  ``policy.ai.data_leaves_site = false``, a shorter allow-list, a lower cap.

A refused value is recorded on the entry (:class:`Shadowed`, ``why`` starts with
``restricted``) and as a warning in :attr:`Config.problems`, so ``explain`` says why it had
no effect. Loading never raises because of a bad file or value: the offending value is
skipped and reported in :attr:`Config.problems`.

    from frontier import config

    cfg = config.get_config()
    cfg.path("storage.datasets_dir")
    print(cfg.explain("hub.max_bytes"))
    config.policy().check_target("runpod")       # raises PolicyViolation when refused

A ``.env`` file is a developer convenience, not product configuration: it is read only when
``FRONTIER_DEV=1`` is set in the real process environment, it never overrides a variable
that is really set, and it can set neither a restricted key nor the variables that locate
the trusted layers (see :func:`read_dotenv`).
"""

from __future__ import annotations

import builtins
import json
import os
import stat
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

CONFIG_FILE = "config.toml"
PROJECT_FILE = "frontier.toml"
SYSTEM_FILE_UNIX = "/etc/frontier/config.toml"

SOURCES = ("default", "system", "server", "user", "project", "dotenv", "env", "cli")

#: names the server policy file (the ``server`` layer); only read from the real environment
SERVER_CONFIG_ENV = "FRONTIER_SERVER_CONFIG"

#: ``Shadowed.why`` of a value for an ``admin`` key from a layer that may not set it
RESTRICTED_WHY = "restricted: only the system file or the server may set this"
#: ``Shadowed.why`` of a value for a ``trusted`` key from a project file or a ``.env``
UNTRUSTED_WHY = (
    "restricted: a project file or .env may not set this "
    "(use the user file, the system file or the real environment)"
)

ALLOW_CLOUD_TARGETS = "policy.allow_cloud_targets"
ALLOW_PUBLIC_HUB = "policy.allow_public_hub"
ALLOWED_DATASET_LICENCES = "policy.allowed_dataset_licences"
MAX_COST_PER_RUN = "policy.max_cost_per_run"
PLUGIN_SOURCES = "policy.plugin_sources"
ALLOW_PLUGIN_CHANGES = "policy.allow_plugin_changes"

_PLUGIN_SOURCE_KINDS = ("bundled", "pypi", "wheel_dir", "index")


# -- registry -------------------------------------------------------------------------------

_SCHEMA: dict[str, Any] | None = None
_DEFS: dict[str, dict[str, Any]] | None = None


def schema() -> dict[str, Any]:
    """The settings registry: ``{"version", "sections": [...], "settings": [...]}``."""
    global _SCHEMA
    if _SCHEMA is None:
        text = resources.files("frontier").joinpath("config_schema.json").read_text("utf-8")
        _SCHEMA = json.loads(text)
    assert _SCHEMA is not None
    return _SCHEMA


def _defs() -> dict[str, dict[str, Any]]:
    global _DEFS
    if _DEFS is None:
        _DEFS = {d["key"]: d for d in schema()["settings"]}
    return _DEFS


def find(key: str) -> dict[str, Any] | None:
    """The definition of one setting (``key``, ``type``, ``default``, ``enum``, ...)."""
    return _defs().get(key)


def _distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] * (len(b) + 1)
        for j in range(1, len(b) + 1):
            cost = int(a[i - 1] != b[j - 1])
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[len(b)]


def suggest(key: str) -> list[str]:
    """Keys closest to ``key`` (for "did you mean")."""
    name = key.rsplit(".", 1)[-1]
    scored: list[tuple[int, str]] = []
    for k in _defs():
        score = min(_distance(key, k), _distance(name, k.split(".", 1)[-1]) + 1)
        if score <= 3 or k.startswith(key):
            scored.append((score, k))
    scored.sort()
    return [k for _, k in scored[:3]]


# -- trust ----------------------------------------------------------------------------------

#: Keys that configure code execution or where data and credentials are sent, whatever the
#: registry says about their scope. A project file or a ``.env`` never sets them.
EXEC_NETWORK_KEYS = frozenset(
    {
        "compute.python",
        "client.server_url",
        "hub.extra_catalogs",
        "plugins.index_url",
        "plugins.wheel_dir",
        "policy.ai.local_endpoint",
        "policy.ai.local_endpoints",
    }
)
EXEC_NETWORK_PREFIXES = ("network.",)

#: layers that may set an ``admin`` key / a ``trusted`` key
_ACCEPTED_FROM = {
    "admin": frozenset({"system", "server"}),
    "trusted": frozenset({"system", "server", "user", "env", "cli"}),
}


def restriction(key: str) -> str | None:
    """Which layers may set ``key``, decided from the registry:

    * ``"admin"``: only the system file and the server layer. Every server-scope setting,
      and every ``policy.*`` setting whose scope is ``server`` or ``system`` or that is
      edited by an administrator.
    * ``"trusted"``: not a project ``frontier.toml`` and not a ``.env``. The keys in
      :data:`EXEC_NETWORK_KEYS` and under :data:`EXEC_NETWORK_PREFIXES`, and every other
      system-scope or admin-edited setting.
    * ``None``: any layer (and any key that is not a registered setting).

    A layer that may not set a key may still tighten it (:func:`tightens`)."""
    d = find(key)
    if d is None:
        return None
    if key in EXEC_NETWORK_KEYS or key.startswith(EXEC_NETWORK_PREFIXES):
        return "trusted"
    admin = d.get("scope") in ("server", "system") or d.get("editable_by") == "admin"
    if d.get("scope") == "server" or (admin and key.startswith("policy.")):
        return "admin"
    return "trusted" if admin else None


def may_set(key: str, source: str) -> bool:
    """Whether the layer ``source`` (one of :data:`SOURCES`) may set ``key`` to any value."""
    kind = restriction(key)
    return kind is None or source in _ACCEPTED_FROM[kind]


#: In which direction a restricted setting gets stricter.
_TIGHTER: dict[str, str] = {
    "network.offline": "true",
    "policy.ai.data_leaves_site": "false",
    "policy.allow_public_hub": "false",
    "policy.allow_plugin_changes": "false",
    "policy.allow_cloud_targets": "subset",
    "policy.allowed_dataset_licences": "subset",
    "policy.plugin_sources": "subset",
    "policy.compute_allowed_pools": "subset",
    "policy.ai.allowed_providers": "subset",
    "policy.ai.autonomous_op_classes": "subset",
    "policy.max_cost_per_run": "cap",
    "policy.compute_max_gpus_per_run": "cap",
}
_WILDCARDS = frozenset({"any", "*", "all"})


def tightens(defn: Mapping[str, Any], current: Any, proposed: Any) -> bool:
    """Whether changing the setting ``defn`` from ``current`` to ``proposed`` can only make
    things stricter, so that a layer without the right to set the key may still apply it.

    * a boolean switch moves in its strict direction (``network.offline`` on,
      ``policy.ai.data_leaves_site``, ``policy.allow_public_hub`` and
      ``policy.allow_plugin_changes`` off);
    * an allow-list becomes a subset of the current one (entries compared exactly, ignoring
      case; a wildcard ``any``/``*``/``all`` in the current list allows any list, a wildcard
      in the proposed list is never a subset of a list without one);
    * a cap where 0 means "no ceiling" becomes a positive number not above the current one.

    Anything this function does not know to be stricter is treated as loosening."""
    key = str(defn.get("key") or "")
    how = _TIGHTER.get(key)
    if how is None and defn.get("type") == "list":
        name = key.rsplit(".", 1)[-1]
        if name.startswith(("allow_", "allowed_")):
            how = "subset"
    if how in ("true", "false"):
        want = how == "true"
        return isinstance(proposed, bool) and isinstance(current, bool) and proposed is want
    if how == "subset":
        if not isinstance(current, list) or not isinstance(proposed, list):
            return False
        if not all(isinstance(i, str) for i in (*current, *proposed)):
            return False
        cur = {i.lower() for i in current}
        new = {i.lower() for i in proposed}
        if cur & _WILDCARDS:
            return True
        return not (new & _WILDCARDS) and new <= cur
    if how == "cap":
        nums = (current, proposed)
        if any(isinstance(n, bool) or not isinstance(n, int | float) for n in nums):
            return False
        if proposed <= 0:
            return current <= 0  # "no ceiling" tightens nothing unless it already is that
        return current <= 0 or proposed <= current
    return False


# -- values ---------------------------------------------------------------------------------

_UNITS = {
    "": 1,
    "b": 1,
    "k": 1000,
    "kb": 1000,
    "kib": 1 << 10,
    "m": 1000**2,
    "mb": 1000**2,
    "mib": 1 << 20,
    "g": 1000**3,
    "gb": 1000**3,
    "gib": 1 << 30,
    "t": 1000**4,
    "tb": 1000**4,
    "tib": 1 << 40,
}


def parse_bytes(text: str) -> int | None:
    """``"2GiB"``, ``"500MB"``, ``"1024"`` -> bytes (kB/MB/GB are decimal, KiB/MiB/GiB binary,
    like the hub's ``--max-bytes``)."""
    t = text.strip()
    split = len(t)
    for i, c in enumerate(t):
        if not (c.isascii() and c.isdigit() or c in "._"):
            split = i
            break
    num, unit = t[:split].replace("_", ""), t[split:].strip().lower()
    if unit not in _UNITS or not num or num.strip(".") == "":
        return None
    try:
        n = float(num)
    except ValueError:
        return None
    return int(n * _UNITS[unit]) if n >= 0 else None


def _quote(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def _num(n: float) -> str:
    f = float(n)
    return str(int(f)) if f.is_integer() and abs(f) < 1e16 else repr(f)


def _type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "a boolean"
    if isinstance(v, int | float):
        return "a number"
    if isinstance(v, str):
        return "a string"
    if isinstance(v, list | tuple):
        return "a list"
    return "a table"


_EXPECTED = {
    "string": "a string",
    "path": "a path",
    "url": "a URL starting with http:// or https://",
    "int": "an integer",
    "float": "a number",
    "bool": "true or false",
    "list": "a list of strings",
    "bytes": 'a byte count such as 2147483648 or "2GiB"',
}


def _expected(d: Mapping[str, Any]) -> str:
    base = _EXPECTED.get(d["type"]) or str(d["type"])
    choices = d.get("enum")
    if choices and d["type"] == "list":
        return f"{base}, each one of: {', '.join(choices)}"
    if choices:
        return f"one of: {', '.join(choices)}"
    return base


def from_text(d: Mapping[str, Any], text: str) -> Any:
    """Convert an environment (or command-line) string into a value for the setting ``d``.
    Raises ``ValueError`` naming what was expected."""
    t = text.strip()
    ty = d["type"]
    bad = ValueError(f"expected {_expected(d)}, got {_quote(t)}")
    raw: Any
    if ty in ("string", "path", "url"):
        raw = t
    elif ty == "int":
        try:
            raw = int(t, 10)
        except ValueError:
            raise bad from None
    elif ty == "float":
        try:
            raw = float(t)
        except ValueError:
            raise bad from None
    elif ty == "bool":
        low = t.lower()
        if low in ("1", "true", "yes", "on"):
            raw = True
        elif low in ("0", "false", "no", "off", ""):
            raw = False
        else:
            raise bad
    elif ty == "list":
        if t.startswith("["):
            try:
                raw = json.loads(t)
            except ValueError as e:
                raise ValueError(f"expected {_expected(d)}: {e}") from None
        else:
            raw = [s.strip() for s in t.split(",") if s.strip()]
    elif ty == "bytes":
        raw = parse_bytes(t)
        if raw is None:
            raise bad
    else:
        raw = t
    return coerce(d, raw)


def coerce(d: Mapping[str, Any], value: Any) -> Any:
    """Validate ``value`` for the setting ``d`` and return its normalised form (bytes as
    integers, URLs without a trailing slash). Raises ``ValueError``."""
    ty = d["type"]
    wrong = ValueError(f"expected {_expected(d)}, got {_type_name(value)}")
    is_num = isinstance(value, int | float) and not isinstance(value, bool)
    out: Any
    if ty in ("string", "path") and isinstance(value, str):
        out = value
    elif ty == "url" and isinstance(value, str):
        if value and not value.startswith(("http://", "https://")):
            raise ValueError(f"expected {_expected(d)}, got {_quote(value)}")
        out = value.rstrip("/")
    elif ty == "int" and is_num:
        if not isinstance(value, int):
            raise wrong
        out = value
    elif ty == "float" and is_num:
        out = float(value)
    elif ty == "bool" and isinstance(value, bool):
        out = value
    elif ty == "list" and isinstance(value, list | tuple):
        if not all(isinstance(i, str) for i in value):
            raise wrong
        out = list(value)
    elif ty == "bytes" and is_num:
        if not isinstance(value, int) or value < 0:
            raise wrong
        out = value
    elif ty == "bytes" and isinstance(value, str):
        out = parse_bytes(value)
        if out is None:
            raise ValueError(f"expected {_expected(d)}, got {_quote(value)}")
    elif ty == "table" and isinstance(value, dict):
        # a nested table level (`[policy.ai]`): its keys are settings of their own
        out = dict(value)
    else:
        raise wrong
    choices = d.get("enum")
    if choices:
        items = [out] if isinstance(out, str) else out if isinstance(out, list) else []
        for s in items:
            if s not in choices:
                raise ValueError(f"{_quote(s)} is not allowed; expected {_expected(d)}")
    if isinstance(out, int | float) and not isinstance(out, bool):
        lo, hi = d.get("min"), d.get("max")
        if lo is not None and out < lo:
            raise ValueError(f"{_num(out)} is below the minimum {_num(lo)}")
        if hi is not None and out > hi:
            raise ValueError(f"{_num(out)} is above the maximum {_num(hi)}")
    return out


def expand_path(text: str) -> Path:
    """Expand a leading ``~`` to the home directory."""
    if text == "~":
        return Path.home()
    if text.startswith(("~/", "~\\")):
        return Path.home() / text[2:]
    return Path(text)


# -- developer .env -------------------------------------------------------------------------


def parse_dotenv(text: str) -> list[tuple[str, str]]:
    """``KEY=VALUE`` lines (``export`` prefix, ``#`` comments, single or double quotes; no
    interpolation)."""
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ")
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not all(c.isascii() and (c.isalnum() or c == "_") for c in key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        out.append((key, value))
    return out


def source_checkout(start: Path) -> Path | None:
    """The root of a Frontier source checkout containing ``start``, if any."""
    for d in (start, *start.parents):
        if (
            (d / "Cargo.toml").is_file()
            and (d / "crates" / "frontier-config").is_dir()
            and (d / "packages" / "frontier").is_dir()
        ):
            return d
    return None


def _dev_mode(env: Mapping[str, str]) -> bool:
    return env.get("FRONTIER_DEV", "").strip().lower() in ("1", "true", "yes")


def dotenv_path(cwd: Path, env: Mapping[str, str]) -> Path | None:
    """The ``.env`` that applies in developer mode, which is on only when ``FRONTIER_DEV=1``
    is set in ``env`` (the real environment): the source checkout root's, else the nearest
    one walking up from ``cwd``. ``None`` otherwise: merely standing in a directory that
    looks like a checkout loads nothing."""
    if not _dev_mode(env):
        return None
    root = source_checkout(cwd)
    if root is not None:
        p = root / ".env"
        return p if p.is_file() else None
    for d in (cwd, *cwd.parents):
        if (d / ".env").is_file():
            return d / ".env"
    return None


#: variables that locate the trusted layers or switch developer mode: never from a ``.env``
_DOTENV_NEVER = frozenset(
    {
        "FRONTIER_DEV",
        "FRONTIER_HOME",
        "FRONTIER_SYSTEM_CONFIG",
        SERVER_CONFIG_ENV,
        "PROGRAMDATA",
        "HOME",
        "USERPROFILE",
    }
)


@dataclass(frozen=True)
class Dotenv:
    """What a developer ``.env`` contributed."""

    #: the file, ``None`` when none applies
    path: Path | None
    #: the environment with the harmless ``.env`` variables folded in
    env: dict[str, str]
    #: ``.env`` variables naming a restricted setting: kept out of ``env`` and handed to
    #: :func:`load` as the ``dotenv`` layer, which refuses them unless they tighten
    held: dict[str, str]
    #: ``.env`` variables dropped outright (they locate the trusted layers)
    dropped: tuple[str, ...]


def _restricted_env_names() -> dict[str, str]:
    return {name: k for k, d in _defs().items() if restriction(k) for name in d["env"]}


def read_dotenv(env: Mapping[str, str], cwd: Path) -> Dotenv:
    """Fold the developer ``.env`` into ``env``. A variable that is really set always wins;
    variables that name a restricted setting or locate the trusted layers are not merged."""
    out = dict(env)
    path = dotenv_path(cwd, out)
    if path is None:
        return Dotenv(None, out, {}, ())
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Dotenv(None, out, {}, ())
    restricted = _restricted_env_names()
    held: dict[str, str] = {}
    dropped: list[str] = []
    for k, v in parse_dotenv(text):
        if k in env:
            continue
        if k in _DOTENV_NEVER:
            dropped.append(k)
        elif k in restricted:
            held.setdefault(k, v)
        else:
            out.setdefault(k, v)
    return Dotenv(path, out, held, tuple(dropped))


def with_dotenv(env: Mapping[str, str], cwd: Path) -> dict[str, str]:
    """``env`` plus the developer ``.env`` (which never overrides a variable already set and
    never contributes a restricted setting; see :func:`read_dotenv`)."""
    return read_dotenv(env, cwd).env


def _cwd() -> Path:
    try:
        return Path.cwd()
    except OSError:
        return Path(".")


def _stamp(path: Path | None) -> tuple[int, int] | None:
    if path is None:
        return None
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


_ENV_CACHE: tuple[Any, Dotenv] | None = None


def process_dotenv() -> Dotenv:
    """The process environment and what the developer ``.env`` added to it. Cached; refreshed
    when the environment, the working directory or the ``.env`` file changes."""
    global _ENV_CACHE
    base = dict(os.environ)
    cwd = _cwd()
    path = dotenv_path(cwd, base)
    key = (hash(frozenset(base.items())), str(cwd), str(path), _stamp(path))
    if _ENV_CACHE is None or _ENV_CACHE[0] != key:
        _ENV_CACHE = (key, read_dotenv(base, cwd))
    return _ENV_CACHE[1]


def process_env() -> dict[str, str]:
    """The process environment with the developer ``.env`` folded in (see
    :func:`read_dotenv` for what a ``.env`` cannot set)."""
    return dict(process_dotenv().env)


# -- loader ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Shadowed:
    """A value a layer provided that did not become the effective one."""

    source: str
    origin: str
    value: Any
    #: ``"overridden"`` (a higher layer won), ``"locked"`` (the system file forbids it) or a
    #: sentence starting with ``"restricted"`` (this layer may not set the key)
    why: str


@dataclass
class Entry:
    """The effective value of one key and how it came about."""

    value: Any
    source: str = "default"
    #: file path or environment variable that set the value (empty for defaults)
    origin: str = ""
    locked: bool = False
    reason: str | None = None
    shadowed: list[Shadowed] = field(default_factory=list)


@dataclass(frozen=True)
class Problem:
    """Something wrong in a layer; the offending value was skipped."""

    severity: str
    source: str
    origin: str
    key: str | None
    message: str

    def __str__(self) -> str:
        if self.key is not None:
            return f"{self.origin}: {self.key}: {self.message}"
        return f"{self.origin}: {self.message}"


@dataclass(frozen=True)
class Paths:
    """Where the layers live on this machine."""

    home: Path
    system: Path
    user: Path
    project: Path | None
    #: the server policy file (``FRONTIER_SERVER_CONFIG``), ``None`` when there is none
    server: Path | None = None


def frontier_home(env: Mapping[str, str] | None = None) -> Path:
    """``$FRONTIER_HOME`` or ``~/.frontier``."""
    env = process_env() if env is None else env
    h = env.get("FRONTIER_HOME")
    return Path(h) if h else Path.home() / ".frontier"


def system_path(env: Mapping[str, str] | None = None) -> Path:
    """The system config path. The installed file always wins when it exists; only when it does
    not is ``FRONTIER_SYSTEM_CONFIG`` honoured, so a user cannot point an installed lock file
    elsewhere."""
    env = process_env() if env is None else env
    if sys.platform == "win32":
        default = Path(env.get("PROGRAMDATA") or r"C:\ProgramData") / "Frontier" / CONFIG_FILE
    else:
        default = Path(SYSTEM_FILE_UNIX)
    if default.is_file():
        return default
    p = env.get("FRONTIER_SYSTEM_CONFIG")
    return Path(p) if p else default


def server_path(env: Mapping[str, str] | None = None) -> Path | None:
    """The server policy file: ``$FRONTIER_SERVER_CONFIG``. The control plane writes it for the
    jobs it launches so a worker evaluates the server's policy, not its own files. A ``.env``
    cannot set the variable."""
    env = process_env() if env is None else env
    p = env.get(SERVER_CONFIG_ENV)
    return Path(p) if p else None


def _read_trusted_file(path: Path) -> tuple[str | None, str | None]:
    """``(text, refusal)`` of a file that carries the server's trust. It must be a regular
    file, owned by the current user or root and not writable by group or others; anything
    else could have been written by somebody the server never authorised."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        return None, f"cannot be read ({e.strerror or e}); the server layer is ignored"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "is not a regular file; the server layer is ignored"
        if os.name == "posix":
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o022:
                return None, (
                    f"is writable by group or others (mode {mode:o}); the server layer is "
                    f"ignored (run `chmod go-w {path}`)"
                )
            if st.st_uid not in (0, os.geteuid()):
                return None, (
                    f"is owned by another user (uid {st.st_uid}); the server layer is ignored"
                )
        with os.fdopen(os.dup(fd), "rb") as fh:
            data = fh.read()
    finally:
        os.close(fd)
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "is not UTF-8 text; the server layer is ignored"


def find_project_file(start: Path) -> Path | None:
    """Nearest ``frontier.toml`` walking up from ``start``."""
    for d in (start, *start.parents):
        if (d / PROJECT_FILE).is_file():
            return d / PROJECT_FILE
    return None


def _jsonable(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    if isinstance(v, str | int | float | bool):
        return v
    return str(v)  # dates and times


@dataclass
class _FileLayer:
    values: list[tuple[str, Any]] = field(default_factory=list)
    locks: list[tuple[str, str | None]] = field(default_factory=list)
    problems: list[tuple[str | None, str, str]] = field(default_factory=list)


def _parse_locks(body: Any, layer: _FileLayer) -> None:
    if not isinstance(body, dict):
        layer.problems.append(
            ("lock", "error", '`[lock]` must be a table of `"section.key" = "reason"`')
        )
        return

    def add(pattern: str, v: Any) -> None:
        if isinstance(v, str):
            layer.locks.append((pattern, v))
        elif v is True:
            layer.locks.append((pattern, None))
        elif v is False:
            pass
        else:
            layer.problems.append(
                (f"lock.{pattern}", "error", "a lock is `true` or a string with the reason")
            )

    for k, v in body.items():
        if isinstance(v, dict):  # [lock.policy] allow_public_hub = "reason"
            for name, inner in v.items():
                add(f"{k}.{name}", inner)
        else:  # [lock] "policy.allow_public_hub" = "reason"
            add(k, v)


def _parse_file(text: str, allow_locks: bool, *, as_json: bool = False) -> _FileLayer:
    layer = _FileLayer()
    table: Any
    if as_json:
        try:
            table = json.loads(text)
        except ValueError as e:
            layer.problems.append(
                (None, "error", f"not valid JSON, the whole file is ignored: {e}")
            )
            return layer
        if not isinstance(table, dict):
            layer.problems.append((None, "error", "expected a JSON object of sections"))
            return layer
    else:
        try:
            table = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            layer.problems.append(
                (None, "error", f"not valid TOML, the whole file is ignored: {e}")
            )
            return layer
    for section, body in table.items():
        if "." in section and not isinstance(body, dict):
            # a flat dotted key (`"policy.ai.data_leaves_site": false`), as the server's
            # settings table stores them
            layer.values.append((section, _jsonable(body)))
            continue
        if section == "lock":
            if not allow_locks:
                layer.problems.append(
                    (
                        "lock",
                        "warning",
                        "locks are only honoured in the system file; ignored here",
                    )
                )
                continue
            _parse_locks(body, layer)
            continue
        if not isinstance(body, dict):
            layer.problems.append(
                (
                    section,
                    "error",
                    "settings live in sections, for example `[storage]` then "
                    '`datasets_dir = "..."`',
                )
            )
            continue
        for name, v in body.items():
            key = f"{section}.{name}"
            d = find(key)
            if isinstance(v, dict) and (d is None or d.get("type") == "table"):
                # one nested table level: `[policy.ai]` holds `policy.ai.<name>` keys
                for sub, sv in v.items():
                    layer.values.append((f"{key}.{sub}", _jsonable(sv)))
                continue
            layer.values.append((key, _jsonable(v)))
    return layer


def _lock_matches(pattern: str, key: str) -> bool:
    if pattern.endswith(".*"):
        return key.split(".", 1)[0] == pattern[:-2]
    return pattern in (key, "*")


def _describe_value(v: Any) -> str:
    if isinstance(v, str) and not v:
        return "(empty)"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


class Config:
    """The effective configuration. Build one with :func:`load` or :func:`get_config`."""

    def __init__(
        self,
        entries: dict[str, Entry],
        problems: list[Problem],
        paths: Paths,
        env: dict[str, str],
    ) -> None:
        self._entries = entries
        self.problems = problems
        self.paths = paths
        self._env = env

    def __repr__(self) -> str:
        n = sum(1 for e in self._entries.values() if e.source != "default")
        return f"<frontier Config: {n} setting(s) set, {len(self.problems)} problem(s)>"

    def entry(self, key: str) -> Entry | None:
        """The effective entry of ``key`` (value, source, origin, locked, reason, shadowed)."""
        return self._entries.get(key)

    def entries(self) -> dict[str, Entry]:
        """All entries, by key."""
        return dict(self._entries)

    def trusted_source(self, key: str) -> builtins.str:
        """The layer whose value is in effect for ``key`` (one of :data:`SOURCES`). For a
        restricted key this is ``default``, ``system`` or ``server`` unless a lower layer
        tightened it. Raises ``KeyError`` for a key that is not a registered setting."""
        try:
            return self._entries[key].source
        except KeyError:
            raise KeyError(f"{key} is not a registered setting") from None

    def ignored(self, key: str) -> builtins.list[Shadowed]:
        """Values for ``key`` that a layer provided and that were refused (locked by the
        system file, or from a layer that may not set the key), lowest layer first."""
        e = self._entries.get(key)
        return [s for s in e.shadowed if s.why != "overridden"] if e else []

    @property
    def env(self) -> dict[str, str]:
        """The environment the configuration was loaded with (process environment plus the
        developer ``.env``). Credential fallbacks read from the same mapping."""
        return self._env

    def get(self, key: str) -> Any:
        """The effective value. Raises ``KeyError`` for a key that is not a registered setting
        (a programming error)."""
        try:
            return self._entries[key].value
        except KeyError:
            raise KeyError(f"{key} is not a registered setting") from None

    def is_set(self, key: str) -> bool:
        """Whether any layer above the defaults set ``key``."""
        e = self._entries.get(key)
        return e is not None and e.source != "default"

    def opt_str(self, key: str) -> builtins.str | None:
        """String value, ``None`` when empty."""
        v = self.get(key)
        return v if isinstance(v, str) and v else None

    def path(self, key: str) -> Path | None:
        """Path value with ``~`` expanded, ``None`` when empty."""
        v = self.opt_str(key)
        return expand_path(v) if v else None

    def explain(self, key: str) -> builtins.str | None:
        """Multi-line explanation of one key: effective value, the layer that set it, the lock
        and every value that had no effect."""
        d = find(key)
        e = self._entries.get(key)
        if d is None or e is None:
            return None
        out = [f"{d['key']} ({d['title']})", f"  {d['description']}"]
        out.append(f"  type: {d['type']}   scope: {d['scope']}   edited by: {d['editable_by']}")
        out.append(f"  effective value: {_describe_value(e.value)}")
        out.append(f"  set by: {_describe_source(e)}")
        if e.locked:
            reason = f": {e.reason}" if e.reason else ""
            out.append(f"  locked by the system file {self.paths.system}{reason}")
        kind = restriction(key)
        if kind == "admin":
            out.append(
                "  restricted: only the system file or the server may set this; "
                "other layers may only tighten it"
            )
        elif kind == "trusted":
            out.append(
                "  restricted: a project file or .env may not set this; they may only tighten it"
            )
        for s in reversed(e.shadowed):
            line = f"{_describe_value(s.value)} from {s.source} ({s.origin})"
            if s.why == "overridden":
                out.append(f"  overridden: {line}")
            elif s.why == "locked":
                out.append(f"  ignored: {line}: locked by the system file")
            else:
                out.append(f"  ignored: {line}: {s.why}")
        if e.source != "default":
            out.append(f"  default: {_describe_value(d['default'])}")
        out.append(f"  environment: {', '.join(d['env'])}")
        return "\n".join(out) + "\n"

    def network_env(self) -> dict[builtins.str, builtins.str]:
        """Environment variables child processes need so tools that know nothing about
        Frontier (pip, curl, vendor SDKs, huggingface_hub) honour the network settings."""
        out: dict[str, str] = {}

        def put(names: tuple[str, ...], v: str) -> None:
            if v:
                for n in names:
                    out[n] = v

        put(("HTTPS_PROXY", "https_proxy"), self.str("network.https_proxy"))
        put(("HTTP_PROXY", "http_proxy"), self.str("network.http_proxy"))
        put(("NO_PROXY", "no_proxy"), ",".join(self.list("network.no_proxy")))
        ca = self.path("network.ca_bundle")
        if ca is not None:
            put(("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"), str(ca))
        if self.bool("network.offline"):
            # pip and uv children must not reach an index either (a wheel directory given
            # with --find-links keeps working)
            put(("HF_HUB_OFFLINE", "FRONTIER_OFFLINE", "PIP_NO_INDEX", "UV_OFFLINE"), "1")
        put(("HF_ENDPOINT",), self.str("hub.huggingface_endpoint"))
        return out

    # The typed getters are named after the types they return, as in the command-line
    # implementation; they come last so the built-in names stay usable above.

    def str(self, key: builtins.str) -> builtins.str:
        v = self.get(key)
        return v if isinstance(v, builtins.str) else ""

    def int(self, key: builtins.str) -> builtins.int:
        v = self.get(key)
        return v if isinstance(v, builtins.int) and not isinstance(v, builtins.bool) else 0

    def float(self, key: builtins.str) -> builtins.float:
        v = self.get(key)
        if isinstance(v, builtins.bool) or not isinstance(v, builtins.int | builtins.float):
            return 0.0
        return builtins.float(v)

    def bool(self, key: builtins.str) -> builtins.bool:
        return self.get(key) is True

    def list(self, key: builtins.str) -> builtins.list[builtins.str]:
        v = self.get(key)
        if not isinstance(v, builtins.list):
            return []
        return [i for i in v if isinstance(i, builtins.str)]


def _describe_source(e: Entry) -> str:
    return {
        "default": "built-in default",
        "system": f"system file {e.origin}",
        "server": f"server policy file {e.origin}",
        "dotenv": f"developer .env ({e.origin})",
        "user": f"user file {e.origin}",
        "project": f"project file {e.origin}",
        "env": f"environment variable {e.origin}",
        "cli": "command-line flag",
    }.get(e.source, e.source)


def load(
    *,
    system_file: str | os.PathLike[str] | None = None,
    home: str | os.PathLike[str] | None = None,
    project_file: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
    server_file: str | os.PathLike[str] | None = None,
    dotenv: Mapping[str, str] | None = None,
    dotenv_file: str | os.PathLike[str] | None = None,
) -> Config:
    """Load exactly the given layers (nothing is read from the process: tests and tools build
    a configuration by hand). ``home`` defaults to the current directory, as a place that
    holds no ``config.toml``; use :func:`load_process` for the standard locations.

    ``server_file`` is the server policy file (TOML, or JSON when it ends in ``.json``; the
    same sections as the other files, or flat dotted keys). ``dotenv`` holds the variables
    a developer ``.env`` (``dotenv_file``) supplied for restricted settings
    (:attr:`Dotenv.held`); ``env`` is trusted as the real environment."""
    home_path = Path(home) if home is not None else Path(".")
    user_file = home_path / CONFIG_FILE
    env_map = dict(env or {})
    paths = Paths(
        home=home_path,
        system=Path(system_file) if system_file is not None else Path(SYSTEM_FILE_UNIX),
        user=user_file,
        project=Path(project_file) if project_file is not None else None,
        server=Path(server_file) if server_file is not None else None,
    )
    defs = _defs()
    problems: list[Problem] = []
    entries = {k: Entry(value=_copy(d["default"])) for k, d in sorted(defs.items())}

    def apply(source: str, origin: str, key: str, raw: Any, text: bool = False) -> None:
        d = defs.get(key)
        if d is None:
            hint = suggest(key)
            message = "unknown setting"
            if hint:
                message += f" (did you mean {', '.join(hint)}?)"
            problems.append(Problem("warning", source, origin, key, message))
            return
        try:
            value = from_text(d, raw) if text else coerce(d, raw)
        except ValueError as e:
            problems.append(Problem("error", source, origin, key, f"{e}; the value is ignored"))
            return
        entry = entries[key]
        if entry.locked and source != "system":
            entry.shadowed.append(Shadowed(source, origin, value, "locked"))
            return
        kind = restriction(key)
        if kind is not None and source not in _ACCEPTED_FROM[kind]:
            if value == entry.value:
                return  # nothing would change
            if not tightens(d, entry.value, value):
                why = RESTRICTED_WHY if kind == "admin" else UNTRUSTED_WHY
                entry.shadowed.append(Shadowed(source, origin, value, why))
                problems.append(
                    Problem("warning", source, origin, key, f"{why}; the value is ignored")
                )
                return
        if entry.source != "default":
            entry.shadowed.append(Shadowed(entry.source, entry.origin, entry.value, "overridden"))
        entry.value, entry.source, entry.origin = value, source, origin

    def file_layer(source: str, path: Path) -> None:
        origin = str(path)
        if source == "server":
            text, refusal = _read_trusted_file(path)
            if text is None:
                problems.append(Problem("warning", source, origin, None, f"{refusal}"))
                return
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return
        as_json = source == "server" and path.suffix.lower() == ".json"
        layer = _parse_file(text, source == "system", as_json=as_json)
        for key, severity, message in layer.problems:
            problems.append(Problem(severity, source, origin, key, message))
        for key, v in layer.values:
            apply(source, origin, key, v)
        for pattern, reason in layer.locks:
            hit = False
            for key, entry in entries.items():
                if _lock_matches(pattern, key):
                    entry.locked, entry.reason, hit = True, reason, True
            if not hit:
                problems.append(
                    Problem("warning", source, origin, f"lock.{pattern}", "locks no known setting")
                )

    if system_file is not None:
        file_layer("system", paths.system)
    if paths.server is not None:
        file_layer("server", paths.server)
    file_layer("user", user_file)
    if paths.project is not None:
        file_layer("project", paths.project)
    # developer .env, then the environment: legacy names first, the canonical name last so
    # it wins
    where = f" in {dotenv_file}" if dotenv_file is not None else " in .env"
    for source, variables in (("dotenv", dict(dotenv or {})), ("env", env_map)):
        for key, d in defs.items():
            for name in reversed(d["env"]):
                text = variables.get(name)
                if text is None or (text == "" and d["type"] != "string"):
                    continue
                origin = name + where if source == "dotenv" else name
                apply(source, origin, key, text, text=True)
    canonical = {d["env"][0] for d in defs.values()}
    for name in sorted(env_map):
        if name.startswith("FRONTIER_") and "__" in name[9:] and name not in canonical:
            problems.append(
                Problem(
                    "warning",
                    "env",
                    name,
                    None,
                    "matches no setting (expected FRONTIER_<SECTION>__<KEY>)",
                )
            )
    for key, v in (overrides or {}).items():
        apply("cli", "command line", key, v, text=isinstance(v, str) and key in defs)
    return Config(entries, problems, paths, env_map)


def _copy(v: Any) -> Any:
    return list(v) if isinstance(v, list) else v


def load_process(overrides: Mapping[str, Any] | None = None) -> Config:
    """Load from the standard locations and the process environment (plus the developer
    ``.env``), without caching."""
    state = process_dotenv()
    env = dict(state.env)
    return load(
        system_file=system_path(env),
        home=frontier_home(env),
        project_file=find_project_file(_cwd()),
        env=env,
        overrides=overrides,
        server_file=server_path(env),
        dotenv=state.held,
        dotenv_file=state.path,
    )


_CONFIG_CACHE: tuple[Any, Config] | None = None


def get_config() -> Config:
    """The process-wide configuration. Cached; it is reloaded when the environment, the
    working directory or one of the config files changed since the last call."""
    global _CONFIG_CACHE
    state = process_dotenv()
    env = dict(state.env)
    cwd = _cwd()
    system, home, project = system_path(env), frontier_home(env), find_project_file(cwd)
    server = server_path(env)
    key = (
        str(server),
        _stamp(server),
        tuple(sorted(state.held.items())),
        hash(frozenset(env.items())),
        str(system),
        _stamp(system),
        str(home),
        _stamp(home / CONFIG_FILE),
        str(project),
        _stamp(project),
    )
    if _CONFIG_CACHE is None or _CONFIG_CACHE[0] != key:
        cfg = load(
            system_file=system,
            home=home,
            project_file=project,
            env=env,
            server_file=server,
            dotenv=state.held,
            dotenv_file=state.path,
        )
        _CONFIG_CACHE = (key, cfg)
    return _CONFIG_CACHE[1]


def reset() -> None:
    """Forget the cached configuration and environment (tests)."""
    global _CONFIG_CACHE, _ENV_CACHE
    _CONFIG_CACHE = None
    _ENV_CACHE = None


# -- policy ---------------------------------------------------------------------------------


class OfflineError(RuntimeError):
    """An outbound connection was attempted while ``network.offline`` is set."""


def is_loopback_url(url: str) -> bool:
    """True when ``url`` names this machine (localhost, 127.0.0.0/8, ::1, a unix socket)."""
    import ipaddress
    from urllib.parse import urlsplit

    host = (urlsplit(url if "://" in url else f"//{url}").hostname or "").strip("[]").lower()
    if host in ("localhost", ""):
        return host == "localhost" or url.startswith(("unix:", "/"))
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.endswith(".localhost")


def require_online(what: str, config: Config | None = None, *, url: str | None = None) -> None:
    """The one guard every outbound call site uses: raise :class:`OfflineError` before any
    connection when ``network.offline`` is set. A ``url`` on this machine (loopback) is not
    an outbound connection and passes."""
    cfg = config or get_config()
    if not cfg.bool("network.offline"):
        return
    if url is not None and is_loopback_url(url):
        return
    raise OfflineError(f"offline mode is on (setting network.offline), so {what} is not possible")


class PolicyViolation(Exception):  # noqa: N818 - the name is part of the public API
    """A refused action: which policy, a message for the user and where the policy was set."""

    def __init__(
        self, policy: str, message: str, origin: str, locked: bool, reason: str | None
    ) -> None:
        super().__init__(f"{message} (policy {policy}, {origin})")
        self.policy = policy
        self.message = message
        self.origin = origin
        self.locked = locked
        self.reason = reason

    def to_json(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "message": self.message,
            "origin": self.origin,
            "locked": self.locked,
            "reason": self.reason,
        }


class Policy:
    """The organisation policy in effect. Every enforcement point calls one ``check_*``."""

    def __init__(self, config: Config) -> None:
        self.allow_cloud_targets = config.list(ALLOW_CLOUD_TARGETS)
        self.allow_public_hub = config.bool(ALLOW_PUBLIC_HUB)
        self.allowed_dataset_licences = config.list(ALLOWED_DATASET_LICENCES)
        #: 0 = no organisation-wide ceiling
        self.max_cost_per_run = config.float(MAX_COST_PER_RUN)
        self.plugin_sources = config.list(PLUGIN_SOURCES)
        #: may plugins be installed, removed, enabled, disabled or have exporters deployed?
        self.allow_plugin_changes = config.bool(ALLOW_PLUGIN_CHANGES)
        self._origins: dict[str, tuple[str, bool, str | None]] = {}
        for key in (
            ALLOW_CLOUD_TARGETS,
            ALLOW_PUBLIC_HUB,
            ALLOWED_DATASET_LICENCES,
            MAX_COST_PER_RUN,
            PLUGIN_SOURCES,
            ALLOW_PLUGIN_CHANGES,
        ):
            e = config.entry(key)
            if e is None or e.source == "default":
                text = "built-in default"
            elif e.source == "system":
                text = f"set by your administrator in {e.origin}"
            elif e.source == "server":
                text = f"set by your administrator on the server ({e.origin})"
            else:
                text = f"set in {e.source} {e.origin}"
            self._origins[key] = (text, bool(e and e.locked), e.reason if e else None)

    def _violation(self, key: str, message: str) -> PolicyViolation:
        text, locked, reason = self._origins[key]
        if reason:
            text += f": {reason}"
        return PolicyViolation(key, message, text, locked, reason)

    def check_target(self, target: str) -> None:
        """May a run or job be sent to ``target`` (``local``, ``ssh``, ``slurm``, ``k8s``,
        ``runpod``, ``anyscale``)?"""
        if target in self.allow_cloud_targets:
            return
        allowed = ", ".join(self.allow_cloud_targets) or "none"
        raise self._violation(
            ALLOW_CLOUD_TARGETS,
            f"target `{target}` is not allowed here; allowed targets: {allowed}",
        )

    def check_hub_pull(
        self, *, id: str, spdx: str = "", commercial_use: bool = False, public: bool = True
    ) -> None:
        """May this dataset be pulled? ``public`` says whether the files come from a public
        host (anything but a local path)."""
        if public and not self.allow_public_hub:
            raise self._violation(
                ALLOW_PUBLIC_HUB,
                f"downloading `{id}` from a public host is not allowed here",
            )
        for allowed in self.allowed_dataset_licences:
            a = allowed.lower()
            if a in ("any", "*") or (a == "commercial" and commercial_use) or a == spdx.lower():
                return
        raise self._violation(
            ALLOWED_DATASET_LICENCES,
            f"dataset `{id}` is licensed {spdx or 'under unknown terms'}"
            f"{'' if commercial_use else ' (no commercial use)'}, which is not among the "
            f"allowed licences ({', '.join(self.allowed_dataset_licences)})",
        )

    def check_cost(self, requested: float) -> None:
        """May a cloud run use ``requested`` (USD) as its cost ceiling? 0 means "no ceiling"."""
        if self.max_cost_per_run <= 0.0:
            return
        if requested <= 0.0:
            raise self._violation(
                MAX_COST_PER_RUN,
                "a run without a cost ceiling is not allowed here; the ceiling is "
                f"${self.max_cost_per_run:.2f} per run",
            )
        if requested > self.max_cost_per_run + 1e-9:
            raise self._violation(
                MAX_COST_PER_RUN,
                f"a cost ceiling of ${requested:.2f} exceeds the allowed "
                f"${self.max_cost_per_run:.2f} per run",
            )

    def check_plugin_change(self, action: str, plugin: str) -> None:
        """May the set of plugins change at all? ``action`` (``install``, ``uninstall``,
        ``enable``, ``disable``, ``install-exporter``, ...) and ``plugin`` shape the message."""
        if self.allow_plugin_changes:
            return
        raise self._violation(
            ALLOW_PLUGIN_CHANGES,
            f"plugins are managed by your administrator; `{action} {plugin}` is not allowed here",
        )

    def check_plugin_source(self, source: str) -> None:
        """May a plugin be installed from ``source``: ``bundled`` (shipped with the product),
        ``pypi``, ``wheel_dir`` (the configured wheel directory), ``index`` (the configured
        index), or an explicit path or URL?"""
        for allowed in self.plugin_sources:
            if allowed in ("any", "*"):
                return
            if allowed in _PLUGIN_SOURCE_KINDS:
                if source == allowed:
                    return
            elif source not in _PLUGIN_SOURCE_KINDS and source.startswith(allowed):
                return
        allowed = ", ".join(self.plugin_sources) or "none"
        raise self._violation(
            PLUGIN_SOURCES,
            f"installing plugins from `{source}` is not allowed here; allowed sources: {allowed}",
        )

    def summary(self) -> dict[str, Any]:
        """A machine-readable summary (no secrets, safe to show anywhere)."""
        return {
            "allow_cloud_targets": self.allow_cloud_targets,
            "allow_public_hub": self.allow_public_hub,
            "allowed_dataset_licences": self.allowed_dataset_licences,
            "max_cost_per_run": self.max_cost_per_run,
            "plugin_sources": self.plugin_sources,
            "allow_plugin_changes": self.allow_plugin_changes,
        }


def policy(config: Config | None = None) -> Policy:
    """The policy of ``config`` (default: the process-wide configuration)."""
    return Policy(config if config is not None else get_config())


__all__ = [
    "ALLOWED_DATASET_LICENCES",
    "ALLOW_CLOUD_TARGETS",
    "ALLOW_PUBLIC_HUB",
    "MAX_COST_PER_RUN",
    "PLUGIN_SOURCES",
    "EXEC_NETWORK_KEYS",
    "RESTRICTED_WHY",
    "SERVER_CONFIG_ENV",
    "SOURCES",
    "UNTRUSTED_WHY",
    "Config",
    "Dotenv",
    "Entry",
    "OfflineError",
    "Paths",
    "Policy",
    "PolicyViolation",
    "Problem",
    "Shadowed",
    "coerce",
    "expand_path",
    "find",
    "find_project_file",
    "from_text",
    "frontier_home",
    "get_config",
    "load",
    "is_loopback_url",
    "load_process",
    "may_set",
    "parse_bytes",
    "parse_dotenv",
    "policy",
    "process_dotenv",
    "process_env",
    "read_dotenv",
    "require_online",
    "reset",
    "restriction",
    "server_path",
    "schema",
    "source_checkout",
    "suggest",
    "system_path",
    "tightens",
    "with_dotenv",
]
