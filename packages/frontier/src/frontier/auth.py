# SPDX-License-Identifier: Apache-2.0
"""Credentials (standard library only; safe to import anywhere).

A **credential provider** declares what it needs (``auth_providers.json`` for the built-in
ones, ``[[auth]]`` in a plugin's ``plugin.toml`` for the rest); nothing else reads a raw token
from the environment. The same files, stores and messages as ``frontier auth`` on the command
line.

Where secrets are kept is chosen by the setting ``secrets.backend``:

* ``keychain``: the OS keychain through the optional ``keyring`` package (service
  ``org.dimensionlab.frontier``, account ``<provider>/<field>``);
* ``file``: ``$FRONTIER_HOME/credentials.toml``, mode 0600 (headless nodes);
* ``env``: the process environment, read-only;
* ``auto`` (default): the keychain when one is usable, else the file.

Resolution order per field: a **job binding** (the launcher put the value into this process's
environment and listed the provider in ``FRONTIER_CREDENTIALS_BOUND``), then the local store,
then the provider's environment fallbacks (``HF_TOKEN`` ...).

    from frontier import auth

    token = auth.require("huggingface")          # raises MissingCredentialError with guidance
    found = auth.resolve("runpod")               # Resolved(value=***, source='env:RUNPOD_API_KEY')
    auth.statuses()                              # never contains a secret value

Values never appear in ``repr``, logs, status dictionaries or error messages.
"""

from __future__ import annotations

import base64
import importlib
import json
import logging
import os
import ssl
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from dataclasses import field as _dc_field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from frontier import _private
from frontier import config as _config

log = logging.getLogger("frontier.auth")

#: service name of every keychain entry; the account is ``<provider>/<field>``
KEYCHAIN_SERVICE = "org.dimensionlab.frontier"
#: service name the connector framework used before credentials moved here (account = the
#: environment variable name); still read as a last fallback
LEGACY_KEYRING_SERVICE = "frontier-connectors"
CREDENTIALS_FILE = "credentials.toml"
#: where the plugin manager records the ``[[auth]]`` declarations of installed plugins
PLUGIN_PROVIDERS_FILE = "auth-providers.json"
#: result of the last test per provider (no secrets), shared with the command line
STATE_FILE = "auth-state.json"
#: variable listing the provider ids whose values were injected into the environment
BOUND_ENV = "FRONTIER_CREDENTIALS_BOUND"
MASK = "***"
KINDS = ("token", "api_key", "basic", "oauth_device", "oauth_pkce", "file", "none")
OAUTH_KINDS = ("oauth_device", "oauth_pkce")
#: an access token is renewed this long before it expires
OAUTH_SKEW_SECS = 60.0
TEST_TIMEOUT_SECS = 20.0

_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


class AuthError(Exception):
    """A credential operation failed (unusable store, unknown field, invalid login)."""


class UnknownProviderError(AuthError):
    def __init__(self, id: str, known: list[str]) -> None:
        super().__init__(f"unknown credential provider `{id}` (known: {', '.join(known)})")
        self.id = id
        self.known = known


class MissingCredentialError(AuthError):
    """A credential is needed and absent. The message tells the user how to provide it."""

    def __init__(self, id: str, title: str, env: list[str], help_url: str | None) -> None:
        hint = f" (or set {' / '.join(env)} in the environment)" if env else ""
        where = f". Get a credential at {help_url}" if help_url else ""
        super().__init__(f"{title} is not signed in: run `frontier auth login {id}`{hint}{where}")
        self.id = id
        self.title = title
        self.env = env
        self.help_url = help_url


class ExpiredCredentialError(MissingCredentialError):
    """An OAuth sign-in has expired and could not be renewed here (no refresh token, offline
    mode, or the identity provider refused). The user has to sign in again."""

    def __init__(self, id: str, title: str, why: str) -> None:
        AuthError.__init__(
            self,
            f"{title}: the sign-in has expired and could not be renewed ({why}): "
            f"run `frontier auth login {id}`",
        )
        self.id = id
        self.title = title
        self.env = []
        self.help_url = None
        self.why = why


# -- providers ------------------------------------------------------------------------------


@dataclass
class Field:
    """One value a provider needs. Non-secret fields (a user name, a region, a file path) are
    kept in the secret store too, so one login is one unit."""

    name: str
    title: str = ""
    secret: bool = True
    required: bool = True
    env: list[str] = _dc_field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "env": list(self.env),
            "name": self.name,
            "required": self.required,
            "secret": self.secret,
            "title": self.title,
        }


@dataclass
class Provider:
    """A credential provider, as declared by ``[[auth]]``."""

    id: str
    title: str
    category: str = ""
    kind: str = "token"
    fields: list[Field] = _dc_field(default_factory=list)
    env: list[str] = _dc_field(default_factory=list)
    help_url: str | None = None
    test: str | None = None
    scopes_hint: str | None = None
    test_http: dict[str, Any] | None = None
    #: ``[auth.oauth]`` of an OAuth provider (authorize_url, token_url, device_code_url,
    #: client_id, scopes, redirect_port, audience), as declared
    oauth: dict[str, Any] | None = None
    declared_by: list[str] = _dc_field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Provider:
        """Parse and normalise a declaration: default field, titles, provider-level ``env``
        moved onto the first secret field. Raises ``ValueError`` on a malformed one."""
        pid = d.get("id")
        if not isinstance(pid, str) or not valid_id(pid):
            raise ValueError(f"auth id {pid!r}: use lower-case letters, digits, `-` and `_`")
        title = d.get("title")
        if not isinstance(title, str) or not title:
            raise ValueError(f"auth `{pid}`: `title` is required")
        kind = d.get("kind", "token")
        if kind not in KINDS:
            raise ValueError(f"auth `{pid}`: kind {kind!r} is not one of {', '.join(KINDS)}")
        fields: list[Field] = []
        raw_fields = d.get("fields") or []
        if not isinstance(raw_fields, list):
            raise ValueError(f"auth `{pid}`: `fields` must be a list of tables")
        for f in raw_fields:
            if not isinstance(f, Mapping) or not isinstance(f.get("name"), str) or not f["name"]:
                raise ValueError(f"auth `{pid}`: every field needs a `name`")
            fields.append(
                Field(
                    name=f["name"],
                    title=str(f.get("title") or ""),
                    secret=bool(f.get("secret", True)),
                    required=bool(f.get("required", True)),
                    env=_str_list(f.get("env"), f"auth `{pid}` field `{f['name']}`: env"),
                )
            )
        env = _str_list(d.get("env"), f"auth `{pid}`: env")
        if not fields and kind in OAUTH_KINDS:
            # the stored token set of an OAuth sign-in
            fields = [
                Field("access_token", "Access token"),
                Field("refresh_token", "Refresh token", required=False),
                Field("expires_at", "Expires at", secret=False, required=False),
            ]
        elif not fields and kind != "none":
            fields.append(Field(name="api_key" if kind == "api_key" else "token"))
        primary = next((i for i, f in enumerate(fields) if f.secret), 0)
        for i, f in enumerate(fields):
            if not f.title:
                f.title = f.name.replace("_", " ")
            if i == primary:
                f.env.extend(e for e in env if e not in f.env)
        test_http = d.get("test_http")
        oauth = d.get("oauth")
        return cls(
            id=pid,
            title=title,
            category=str(d.get("category") or ""),
            kind=kind,
            fields=fields,
            env=env,
            help_url=_opt_str(d.get("help_url")),
            test=_opt_str(d.get("test")),
            scopes_hint=_opt_str(d.get("scopes_hint")),
            test_http=dict(test_http) if isinstance(test_http, Mapping) else None,
            oauth=dict(oauth) if isinstance(oauth, Mapping) else None,
            declared_by=_str_list(d.get("declared_by"), f"auth `{pid}`: declared_by"),
        )

    def field(self, name: str) -> Field | None:
        return next((f for f in self.fields if f.name == name), None)

    def primary(self) -> Field | None:
        """The first secret field (the token of single-token providers)."""
        return next((f for f in self.fields if f.secret), self.fields[0] if self.fields else None)

    def to_dict(self) -> dict[str, Any]:
        """The declaration as JSON (the shape of ``auth_providers.json``)."""
        out: dict[str, Any] = {
            "category": self.category,
            "env": list(self.env),
            "fields": [f.to_dict() for f in self.fields],
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
        }
        for key in ("help_url", "test", "scopes_hint", "test_http", "oauth"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.declared_by:
            out["declared_by"] = list(self.declared_by)
        return dict(sorted(out.items()))


def _opt_str(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def _str_list(v: Any, what: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
        raise ValueError(f"{what} must be a list of strings")
    return list(v)


def valid_id(id: str) -> bool:
    """Whether ``id`` is usable in file names, keychain accounts and URLs."""
    return bool(id) and len(id) <= 64 and all(c in _ID_CHARS for c in id)


_BUILTIN: list[dict[str, Any]] | None = None


def builtin_declarations() -> list[dict[str, Any]]:
    """The providers that ship with Frontier, as declared."""
    global _BUILTIN
    if _BUILTIN is None:
        text = resources.files("frontier").joinpath("auth_providers.json").read_text("utf-8")
        _BUILTIN = json.loads(text)
    assert _BUILTIN is not None
    return _BUILTIN


class Registry:
    """The provider registry: built-in providers plus plugin declarations, merged by id."""

    def __init__(self) -> None:
        self._providers: dict[str, Provider] = {}

    @classmethod
    def builtin(cls) -> Registry:
        r = cls()
        for d in builtin_declarations():
            r.add(Provider.from_dict(d))
        return r

    @classmethod
    def load(cls, home: Path) -> Registry:
        """Built-in providers plus the ones recorded in ``<home>/auth-providers.json``."""
        r = cls.builtin()
        path = home / PLUGIN_PROVIDERS_FILE
        try:
            items = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return r
        except (OSError, ValueError) as e:
            log.warning("ignoring unreadable plugin auth declarations %s: %s", path, e)
            return r
        if not isinstance(items, list):
            log.warning("ignoring %s: expected a list of provider declarations", path)
            return r
        for d in items:
            try:
                r.add(Provider.from_dict(d))
            except (ValueError, TypeError, AttributeError):
                continue
        return r

    def add(self, p: Provider) -> None:
        """Add a declaration. A provider that already exists keeps its definition and gains
        the new declarer, extra environment names and any field it did not have."""
        existing = self._providers.get(p.id)
        if existing is None:
            self._providers[p.id] = p
            return
        existing.declared_by.extend(d for d in p.declared_by if d not in existing.declared_by)
        for f in p.fields:
            mine = existing.field(f.name)
            if mine is None:
                existing.fields.append(f)
            else:
                mine.env.extend(v for v in f.env if v not in mine.env)
        if existing.test_http is None:
            existing.test_http = p.test_http
        if existing.help_url is None:
            existing.help_url = p.help_url
        if existing.oauth is None:
            existing.oauth = p.oauth

    def get(self, id: str) -> Provider | None:
        return self._providers.get(id)

    def __iter__(self) -> Iterator[Provider]:
        return iter(self._providers.values())

    def ids(self) -> list[str]:
        return list(self._providers)

    def by_env(self, var: str) -> tuple[Provider, Field] | None:
        """The provider that accepts ``var`` as a fallback, with the field it fills."""
        for p in self:
            for f in p.fields:
                if var in f.env:
                    return p, f
        return None


# -- stores ---------------------------------------------------------------------------------


def atomic_write(
    path: Path, text: str, mode: int | None = None, *, private_parent: bool = False
) -> None:
    """Write ``text`` to ``path`` through a temporary file and a rename. Everything this
    module writes is for its owner only: the file is ``0600`` whatever ``mode`` says (a
    stricter ``mode`` is applied, a wider one is not), a parent directory that has to be
    created is ``0700``, and an existing parent is tightened to ``0700`` when
    ``private_parent`` is set (the Frontier home)."""
    if private_parent or not path.parent.exists():
        _private.private_dir(path.parent)
    _private.write_private(path, text)
    if mode is not None and os.name == "posix" and mode & _private.FILE_MODE != _private.FILE_MODE:
        os.chmod(path, mode & _private.FILE_MODE)


_BARE_KEY = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_TOML_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _toml_string(s: str) -> str:
    out = []
    for c in s:
        if c in _TOML_ESCAPES:
            out.append(_TOML_ESCAPES[c])
        elif ord(c) < 0x20 or ord(c) == 0x7F:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def _toml_key(k: str) -> str:
    return k if k and all(c in _BARE_KEY for c in k) else _toml_string(k)


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return repr(v)
    return _toml_string(v if isinstance(v, str) else str(v))


_FILE_HEADER = "# Frontier credentials. Written by `frontier auth login`; do not commit or share.\n"


def dump_tables(doc: Mapping[str, Mapping[str, Any]]) -> str:
    """A TOML document of flat tables (``[provider]`` then ``field = "value"``)."""
    parts = [_FILE_HEADER]
    for name, table in doc.items():
        if not table:
            continue
        parts.append(f"\n[{_toml_key(name)}]\n")
        parts.extend(f"{_toml_key(k)} = {_toml_value(v)}\n" for k, v in table.items())
    return "".join(parts)


class FileStore:
    """``credentials.toml``, readable by the owner only."""

    name = "file"
    writable = True

    def __init__(self, path: Path, *, private_parent: bool = False) -> None:
        self.path = path
        #: tighten the directory to 0700 on write (set for the Frontier home)
        self.private_parent = private_parent

    @classmethod
    def in_home(cls, home: Path) -> FileStore:
        return cls(home / CREDENTIALS_FILE, private_parent=True)

    def describe(self) -> str:
        return f"file {self.path} (owner-only)"

    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as e:
            raise AuthError(f"{self.path}: {e.strerror or e}") from None
        if text and os.name == "posix":
            mode = self.path.stat().st_mode & 0o777
            if mode & 0o077:
                raise AuthError(
                    f"{self.path} is readable by other users (mode {mode:o}); "
                    f"run `chmod 600 {self.path}`"
                )
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            # the parser's message names a position, never file content
            raise AuthError(f"{self.path}: not valid TOML: {e}") from None
        return {k: dict(v) for k, v in doc.items() if isinstance(v, dict)}

    def _write(self, doc: Mapping[str, Mapping[str, Any]]) -> None:
        try:
            atomic_write(self.path, dump_tables(doc), 0o600, private_parent=self.private_parent)
        except OSError as e:
            raise AuthError(f"{self.path}: {e.strerror or e}") from None

    def get(self, provider: str, field: str) -> str | None:
        value = self._read().get(provider, {}).get(field)
        return value if isinstance(value, str) else None

    def set(self, provider: str, field: str, value: str) -> None:
        doc = self._read()
        doc.setdefault(provider, {})[field] = value
        self._write(doc)

    def delete(self, provider: str, field: str) -> bool:
        if not self.path.is_file():
            return False
        doc = self._read()
        table = doc.get(provider)
        if table is None or field not in table:
            return False
        del table[field]
        if not table:
            del doc[provider]
        self._write(doc)
        return True


class EnvStore:
    """Read-only: a field's value is the first of its fallback variables that is set."""

    name = "env"
    writable = False

    def __init__(self, env: Mapping[str, str], registry: Registry) -> None:
        self._env = env
        self._registry = registry

    def describe(self) -> str:
        return "environment variables (read-only)"

    def variable(self, provider: str, field: str) -> tuple[str, str] | None:
        """``(variable, value)`` providing ``provider/field``, if one is set."""
        p = self._registry.get(provider)
        f = p.field(field) if p else None
        return _env_value(self._env, f) if f else None

    def get(self, provider: str, field: str) -> str | None:
        found = self.variable(provider, field)
        return found[1] if found else None

    def set(self, provider: str, field: str, value: str) -> None:
        raise AuthError(
            'the secret store is the environment (secrets.backend = "env"), which is '
            f"read-only; set the variable for `{provider}` in the environment, or choose "
            "`keychain` or `file`"
        )

    def delete(self, provider: str, field: str) -> bool:
        return False


class MemoryStore:
    """This process only (tests)."""

    name = "memory"
    writable = True

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], str] = {}

    def describe(self) -> str:
        return "memory (this process only)"

    def get(self, provider: str, field: str) -> str | None:
        return self._values.get((provider, field))

    def set(self, provider: str, field: str, value: str) -> None:
        self._values[(provider, field)] = value

    def delete(self, provider: str, field: str) -> bool:
        return self._values.pop((provider, field), None) is not None


def _keyring(env: Mapping[str, str] | None = None, *, legacy: bool = False) -> Any | None:
    """The ``keyring`` module when it is installed and has a backend that can be used from
    this session without failing or waiting for a desktop that is not there; else ``None``.
    ``legacy`` also accepts a module that only offers ``get_password`` (enough to read the
    entries the connector framework wrote before credentials moved here)."""
    try:
        kr: Any = importlib.import_module("keyring")
    except Exception:  # noqa: BLE001 - a missing or broken keyring is "no keychain"
        return None
    if not hasattr(kr, "get_keyring"):
        return kr if legacy and hasattr(kr, "get_password") else None
    try:
        backend = kr.get_keyring()
    except Exception:  # noqa: BLE001
        return None
    module = type(backend).__module__ or ""
    if module.startswith(("keyring.backends.fail", "keyring.backends.null")):
        return None
    try:
        if float(getattr(backend, "priority", 1)) <= 0:
            return None
    except Exception:  # noqa: BLE001 - a backend that cannot say is treated as unusable
        return None
    desktop = sys.platform in ("darwin", "win32")
    env = os.environ if env is None else env
    if module.startswith("keyring.backends") and not desktop:
        # Secret Service / KWallet need a session bus; without one the call fails or waits
        if not env.get("DBUS_SESSION_BUS_ADDRESS"):
            return None
    return kr


class KeychainStore:
    """The OS keychain, through the optional ``keyring`` package."""

    name = "keychain"
    writable = True

    def __init__(self, module: Any) -> None:
        self._kr = module

    def describe(self) -> str:
        what = {"darwin": "macOS Keychain", "win32": "Windows Credential Manager"}.get(
            sys.platform, "Secret Service keyring"
        )
        return f"{what} (service {KEYCHAIN_SERVICE})"

    def _call(self, fn: str, *args: str) -> Any:
        try:
            return getattr(self._kr, fn)(KEYCHAIN_SERVICE, *args)
        except Exception as e:  # noqa: BLE001 - backend errors carry no secret; keep the type
            raise AuthError(f"keychain: {type(e).__name__}") from None

    def get(self, provider: str, field: str) -> str | None:
        value = self._call("get_password", f"{provider}/{field}")
        return value if isinstance(value, str) else None

    def set(self, provider: str, field: str, value: str) -> None:
        self._call("set_password", f"{provider}/{field}", value)

    def delete(self, provider: str, field: str) -> bool:
        if self.get(provider, field) is None:
            return False
        self._call("delete_password", f"{provider}/{field}")
        return True


class _UnavailableStore:
    """``secrets.backend = "keychain"`` without a usable keychain: reads fall back to the
    environment (with a warning), writes explain what to do."""

    name = "keychain"
    writable = False
    _MESSAGE = (
        'secrets.backend = "keychain" but no OS keychain is available in this session (the '
        "optional `keyring` package is missing or has no backend); use "
        "`frontier config set secrets.backend file` on headless machines"
    )

    def describe(self) -> str:
        return "OS keychain (unavailable)"

    def get(self, provider: str, field: str) -> str | None:
        raise AuthError(self._MESSAGE)

    def set(self, provider: str, field: str, value: str) -> None:
        raise AuthError(self._MESSAGE)

    def delete(self, provider: str, field: str) -> bool:
        raise AuthError(self._MESSAGE)


#: backends the SDK has no client of its own for: it asks the `frontier` command line, which
#: has (one implementation of each store, in one place)
REMOTE_BACKENDS = ("vault", "aws", "azure", "gcp")


class CliStore:
    """A store in the organisation's secret manager (``secrets.backend`` = ``vault``,
    ``aws``, ``azure`` or ``gcp``), reached through ``frontier secrets helper``: the command
    line holds the one implementation of each of them. The command runs with this process's
    environment, so it sees the same settings and the same store credentials."""

    name = "remote"
    writable = True

    def __init__(self, backend: str, env: Mapping[str, str]) -> None:
        self.name = backend
        self._env = dict(env)

    def describe(self) -> str:
        return f"{self.name} (through the `frontier` command line)"

    def _run(self, op: str, provider: str, field: str, value: str | None = None) -> str | None:
        import shutil
        import subprocess

        exe = self._env.get("FRONTIER_CLI") or shutil.which("frontier")
        if not exe:
            raise AuthError(
                f'secrets.backend = "{self.name}" is read through the `frontier` command line, '
                "which was not found on PATH (set FRONTIER_CLI to its location)"
            )
        try:
            done = subprocess.run(  # noqa: S603 - a fixed argv, no shell
                [exe, "secrets", "helper", op, provider, field],
                input=value,
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, **self._env},
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AuthError(f"the {self.name} secret store could not be reached: {exc}") from exc
        if done.returncode == 3:
            return None  # no such entry
        if done.returncode != 0:
            last = (done.stderr.strip().splitlines() or ["no message"])[-1]
            raise AuthError(f"the {self.name} secret store refused: {last}")
        return done.stdout

    def get(self, provider: str, field: str) -> str | None:
        return self._run("get", provider, field)

    def set(self, provider: str, field: str, value: str) -> None:
        self._run("set", provider, field, value)

    def delete(self, provider: str, field: str) -> bool:
        return self._run("delete", provider, field) is not None


Store = FileStore | EnvStore | MemoryStore | KeychainStore | _UnavailableStore | CliStore


def open_store(config: _config.Config, registry: Registry) -> Store:
    """The store selected by ``secrets.backend``. ``auto`` prefers the keychain when one is
    usable and falls back to the file store (headless nodes, containers)."""
    backend = config.str("secrets.backend")
    home = config.paths.home
    if backend in REMOTE_BACKENDS:
        return CliStore(backend, config.env)
    if backend == "file":
        return FileStore.in_home(home)
    if backend == "env":
        return EnvStore(config.env, registry)
    kr = _keyring(config.env)
    if kr is not None:
        return KeychainStore(kr)
    return _UnavailableStore() if backend == "keychain" else FileStore.in_home(home)


# -- resolver -------------------------------------------------------------------------------


def source_json(source: str | None) -> dict[str, Any] | None:
    """``"keychain"`` / ``"env:HF_TOKEN"`` as ``{"store", "detail"}``; ``None`` stays ``None``."""
    if source is None:
        return None
    store, _, detail = source.partition(":")
    return {"store": store, "detail": detail or None}


def source_label(source: Mapping[str, Any] | str | None) -> str:
    """A status row's ``source`` for people: ``env HF_TOKEN``, ``keychain``, or ``""``."""
    if not source:
        return ""
    if isinstance(source, str):
        return source.replace(":", " ", 1)
    return " ".join(str(v) for v in (source.get("store"), source.get("detail")) if v)


def _last_test(test: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not test:
        return None
    detail = str(test.get("detail") or "")
    ok = bool(test.get("ok"))
    signed_in = "signed in as "
    identity = detail.removeprefix(signed_in) if ok and detail.startswith(signed_in) else None
    return {"at": test.get("at"), "ok": ok, "identity": identity, "detail": detail}


@dataclass(frozen=True, repr=False)
class Resolved:
    """A resolved value and where it came from. ``repr`` never shows the value."""

    value: str
    #: ``job``, ``keychain``, ``file``, ``memory``, ``env:<VARIABLE>`` or ``keychain:legacy``
    source: str

    def __repr__(self) -> str:
        return f"Resolved(value={MASK}, source={self.source!r})"

    __str__ = __repr__


def _env_value(env: Mapping[str, str], f: Field) -> tuple[str, str] | None:
    for name in f.env:
        v = (env.get(name) or "").strip()
        if v:
            return name, v
    return None


class Redactor:
    """Replaces every known secret with ``***``. Values shorter than 6 characters are not
    treated as secrets (replacing them would mangle ordinary text)."""

    def __init__(self, secrets: Iterable[str]) -> None:
        found = {s.strip() for s in secrets if isinstance(s, str)}
        # longest first so a secret containing another is replaced whole
        self._secrets = sorted((s for s in found if len(s) >= 6), key=lambda s: (-len(s), s))

    def __bool__(self) -> bool:
        return bool(self._secrets)

    def redact(self, text: str) -> str:
        for s in self._secrets:
            if s in text:
                text = text.replace(s, MASK)
        return text


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_time(text: str | None) -> datetime | None:
    """An RFC 3339 timestamp (any number of fractional digits), or ``None``."""
    if not text or not text.strip():
        return None
    t = text.strip().replace("Z", "+00:00").replace("z", "+00:00")
    head, dot, rest = t.partition(".")
    if dot:
        digits = len(rest) - len(rest.lstrip("0123456789"))
        t = f"{head}.{rest[:digits][:6].ljust(6, '0')}{rest[digits:]}"
    try:
        when = datetime.fromisoformat(t)
    except ValueError:
        return None
    return when if when.tzinfo is not None else when.replace(tzinfo=UTC)


#: ``(token URL, form fields, timeout seconds) -> (HTTP status, body text)``
TokenTransport = Callable[[str, Mapping[str, str], float], tuple[int, str]]


class Resolver:
    """Finds credentials: job binding, then the local store, then the environment."""

    def __init__(
        self,
        registry: Registry,
        store: Store,
        env: Mapping[str, str],
        *,
        state_path: Path | None = None,
        legacy_keyring: Any | None = None,
        config: _config.Config | None = None,
        token_transport: TokenTransport | None = None,
    ) -> None:
        self.registry = registry
        self.store = store
        self.env = dict(env)
        self.state_path = state_path
        self._legacy = legacy_keyring
        self._config = config
        #: how an OAuth refresh is sent (tests inject a fake; default: urllib)
        self.token_transport = token_transport
        self._warned = False
        self.bound = {s.strip() for s in self.env.get(BOUND_ENV, "").split(",") if s.strip()}

    @classmethod
    def from_config(
        cls, config: _config.Config | None = None, *, keychain: bool = True
    ) -> Resolver:
        """The resolver for this process: registry from the Frontier home, store from
        ``secrets.backend``, environment from the loaded configuration.

        ``keychain=False`` never touches the OS keychain (no prompt): when the keychain is the
        configured store, only job bindings and the environment are consulted, and
        :attr:`complete` is false because a value may exist that was not looked at."""
        config = config if config is not None else _config.get_config()
        registry = Registry.load(config.paths.home)
        legacy = None
        complete = True
        if keychain:
            store = open_store(config, registry)
            if config.str("secrets.backend") in ("auto", "keychain"):
                legacy = _keyring(config.env, legacy=True)
        else:
            backend = config.str("secrets.backend")
            if backend == "file":
                store = FileStore.in_home(config.paths.home)
            else:
                store = EnvStore(config.env, registry)
                complete = backend == "env" or (
                    backend == "auto" and _keyring(config.env, legacy=True) is None
                )
                if complete and backend == "auto":
                    store = FileStore.in_home(config.paths.home)
        r = cls(
            registry,
            store,
            config.env,
            state_path=config.paths.home / STATE_FILE,
            legacy_keyring=legacy,
            config=config,
        )
        r.complete = complete
        return r

    #: false when a store was deliberately not consulted (``from_config(keychain=False)``)
    complete: bool = True

    def provider(self, id: str) -> Provider:
        p = self.registry.get(id)
        if p is None:
            raise UnknownProviderError(id, self.registry.ids())
        return p

    def _resolve_field(self, p: Provider, f: Field) -> Resolved | None:
        from_env = _env_value(self.env, f)
        if p.id in self.bound and from_env:
            return Resolved(from_env[1], "job")
        if self.store.name != "env":
            try:
                v = self.store.get(p.id, f.name)
            except AuthError as e:
                if not self._warned:
                    self._warned = True
                    log.warning("secret store unavailable, trying the environment: %s", e)
                v = None
            if v and v.strip():
                return Resolved(v.strip(), self.store.name)
        if from_env:
            return Resolved(from_env[1], f"env:{from_env[0]}")
        if self._legacy is not None:
            for name in f.env:
                try:
                    v = self._legacy.get_password(LEGACY_KEYRING_SERVICE, name)
                except Exception:  # noqa: BLE001 - no usable backend after all
                    return None
                if isinstance(v, str) and v.strip():
                    return Resolved(v.strip(), "keychain:legacy")
        return None

    def resolve(self, provider: str, field: str | None = None) -> Resolved | None:
        """The value of ``provider/field`` (default: the primary secret), if any source has
        one."""
        p = self.provider(provider)
        f = p.primary() if field is None else p.field(field)
        if f is None:
            if field is None:
                raise AuthError(f"credential `{provider}` declares no field")
            raise AuthError(f"credential `{provider}` has no field `{field}`")
        found = self._resolve_field(p, f)
        if found is not None and p.kind in OAUTH_KINDS and f.name == "access_token":
            return self._fresh_access_token(p, found)
        return found

    # -- OAuth token sets ---------------------------------------------------------------------

    def _fresh_access_token(self, p: Provider, found: Resolved) -> Resolved:
        """The stored access token, renewed first when ``expires_at`` has passed. Tokens that
        a launcher injected or that come from the environment are used as they are."""
        if found.source != self.store.name or not self.store.writable:
            return found
        try:
            expires_at = self.store.get(p.id, "expires_at")
        except AuthError:
            return found
        when = _parse_time(expires_at)
        if when is None or when.timestamp() - OAUTH_SKEW_SECS > datetime.now(UTC).timestamp():
            return found
        return Resolved(self.refresh(p.id), found.source)

    def refresh(self, provider: str) -> str:
        """Renew the access token of an OAuth provider with its refresh token (one POST to
        ``token_url``), store the new token set and return the access token. Raises
        :class:`ExpiredCredentialError` when that is not possible. No interactive flow is
        ever started here."""
        p = self.provider(provider)

        def expired(why: str) -> ExpiredCredentialError:
            return ExpiredCredentialError(p.id, p.title, why)

        oauth = p.oauth or {}
        url, client_id = str(oauth.get("token_url") or ""), str(oauth.get("client_id") or "")
        if p.kind not in OAUTH_KINDS or not url or not client_id:
            raise expired("the provider declares no token endpoint")
        config = self._config
        if config is not None and config.bool("network.offline"):
            # stricter than the shared guard on purpose: no renewal offline, wherever the
            # token endpoint is
            raise expired("offline mode is on, network.offline")
        if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise expired("the token endpoint is not https")
        try:
            refresh_token = (self.store.get(p.id, "refresh_token") or "").strip()
        except AuthError:
            refresh_token = ""
        if not refresh_token:
            raise expired("no refresh token is stored")
        form = {"grant_type": "refresh_token", "client_id": client_id}
        form["refresh_token"] = refresh_token
        send = self.token_transport or _urllib_token_transport(config)
        try:
            status, body = send(url, form, TEST_TIMEOUT_SECS)
        except _config.OfflineError:
            raise expired("offline mode is on, network.offline") from None
        except ValueError as e:
            raise expired(str(e)) from None
        except OSError as e:
            reason = getattr(e, "reason", None)
            what = type(reason).__name__ if isinstance(reason, Exception) else type(e).__name__
            raise expired(f"could not reach {_origin_of(url)}: {what}") from None
        try:
            doc = json.loads(body) if 200 <= status < 300 else None
        except ValueError:
            doc = None
        token = doc.get("access_token") if isinstance(doc, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise expired(f"{_origin_of(url)} answered HTTP {status}")
        assert isinstance(doc, dict)
        self.store.set(p.id, "access_token", token.strip())
        renewed = doc.get("refresh_token")
        if isinstance(renewed, str) and renewed.strip():
            self.store.set(p.id, "refresh_token", renewed.strip())
        lifetime = doc.get("expires_in")
        if isinstance(lifetime, int | float) and not isinstance(lifetime, bool) and lifetime > 0:
            at = datetime.fromtimestamp(datetime.now(UTC).timestamp() + lifetime, UTC)
            stamp = at.isoformat(timespec="seconds").replace("+00:00", "Z")
            self.store.set(p.id, "expires_at", stamp)
        else:
            self.store.delete(p.id, "expires_at")
        return token.strip()

    def missing(self, p: Provider) -> MissingCredentialError:
        primary = p.primary()
        return MissingCredentialError(
            p.id, p.title, list(primary.env) if primary else [], p.help_url
        )

    def require(self, provider: str) -> str:
        """The primary secret of ``provider``, or an error that tells the user how to provide
        it."""
        found = self.resolve(provider)
        if found is None:
            raise self.missing(self.provider(provider))
        return found.value

    def values(self, provider: str) -> dict[str, Resolved]:
        """Every field of ``provider`` that has a value."""
        p = self.provider(provider)
        out: dict[str, Resolved] = {}
        for f in p.fields:
            r = self._resolve_field(p, f)
            if r is not None:
                out[f.name] = r
        return out

    def login(self, provider: str, values: Mapping[str, str]) -> None:
        """Store ``values`` (field -> value). Unknown fields are rejected; required fields
        must end up with a value."""
        p = self.provider(provider)
        for name in values:
            if p.field(name) is None:
                names = ", ".join(f.name for f in p.fields)
                raise AuthError(f"credential `{provider}` has no field `{name}` (fields: {names})")
        for f in p.fields:
            given = (values.get(f.name) or "").strip()
            if f.required and not given and self._resolve_field(p, f) is None:
                raise AuthError(f"{p.title} needs a value for `{f.name}` ({f.title})")
        for name, value in values.items():
            value = value.strip()
            if value:
                self.store.set(p.id, name, value)
        self._forget_test(p.id)

    def logout(self, provider: str) -> int:
        """Remove every stored field of ``provider``. Returns how many entries were removed."""
        p = self.provider(provider)
        n = sum(1 for f in p.fields if self.store.delete(p.id, f.name))
        self._forget_test(p.id)
        return n

    # -- test state ---------------------------------------------------------------------------

    def _state(self) -> dict[str, dict[str, Any]]:
        if self.state_path is None:
            return {}
        try:
            doc = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(doc, dict):
            return {}
        return {k: v for k, v in doc.items() if isinstance(v, dict)}

    def _save_state(self, state: Mapping[str, Any]) -> None:
        if self.state_path is None:
            return
        try:
            atomic_write(self.state_path, json.dumps(dict(sorted(state.items())), indent=2))
        except OSError as e:
            log.debug("could not record credential test result: %s", e)

    def _forget_test(self, id: str) -> None:
        state = self._state()
        if state.pop(id, None) is not None:
            self._save_state(state)

    def record_test(self, id: str, ok: bool, detail: str) -> None:
        """Remember the outcome of a test. ``detail`` is redacted against the provider's
        values regardless of what the caller passed."""
        try:
            known = [r.value for r in self.values(id).values()]
        except AuthError:
            known = []
        state = self._state()
        state[id] = {"at": _now(), "ok": bool(ok), "detail": Redactor(known).redact(detail)}
        self._save_state(state)

    # -- status -------------------------------------------------------------------------------
    # Rows have the shape of the credentials API: ``source`` is ``None`` or
    # ``{"store": "keychain" | "file" | "env" | "job" | ..., "detail": <variable or None>}``
    # and ``last_test`` is ``None`` or ``{"at", "ok", "identity", "detail"}``. The flat
    # ``last_tested`` / ``last_test_ok`` / ``last_test_detail`` say the same for older readers.

    def status(self, id: str) -> dict[str, Any]:
        """What ``frontier auth status`` reports for one provider. Never a secret value."""
        return self._status_of(self.provider(id), self._state())

    def statuses(self) -> list[dict[str, Any]]:
        state = self._state()
        return [self._status_of(p, state) for p in self.registry]

    def _status_of(self, p: Provider, state: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        fields = []
        for f in p.fields:
            r = self._resolve_field(p, f)
            fields.append(
                {
                    "name": f.name,
                    "title": f.title,
                    "secret": f.secret,
                    "required": f.required,
                    "configured": r is not None,
                    "source": source_json(r.source if r else None),
                    "env": list(f.env),
                    # the value of a non-secret field (a user name, a region); never a secret
                    "value": r.value if r is not None and not f.secret else None,
                }
            )
        primary = p.primary()
        source = next((f["source"] for f in fields if primary and f["name"] == primary.name), None)
        test = state.get(p.id)
        return {
            "id": p.id,
            "title": p.title,
            "category": p.category,
            "kind": p.kind,
            "fields": fields,
            "configured": bool(fields)
            and all(f["configured"] or not f["required"] for f in fields),
            "source": source,
            "last_test": _last_test(test),
            "last_tested": test.get("at") if test else None,
            "last_test_ok": test.get("ok") if test else None,
            "last_test_detail": test.get("detail") if test else None,
            "env": [e for f in p.fields for e in f.env],
            "help_url": p.help_url,
            "scopes_hint": p.scopes_hint,
            "testable": p.test_http is not None,
            "declared_by": list(p.declared_by),
        }

    # -- children and logs --------------------------------------------------------------------

    def env_for(self, ids: Iterable[str]) -> dict[str, str]:
        """Environment for a child process that needs the given providers: each field under
        its first fallback variable, plus ``FRONTIER_CREDENTIALS_BOUND``. Providers without a
        value are skipped."""
        out: dict[str, str] = {}
        bound: list[str] = []
        for id in ids:
            p = self.registry.get(id)
            if p is None:
                continue
            found = False
            for f in p.fields:
                r = self._resolve_field(p, f) if f.env else None
                if r is not None:
                    out[f.env[0]] = r.value
                    found = True
            if found:
                bound.append(id)
        if bound:
            out[BOUND_ENV] = ",".join(bound)
        return out

    def secrets(self) -> list[str]:
        """Every secret value this resolver can see, for redacting logs."""
        out = []
        for p in self.registry:
            for f in p.fields:
                r = self._resolve_field(p, f) if f.secret else None
                if r is not None:
                    out.append(r.value)
        return out


# -- testing a credential ---------------------------------------------------------------------

#: ``(url, headers, timeout seconds) -> (HTTP status, body text)``
Transport = Callable[[str, Mapping[str, str], float], tuple[int, str]]


def _failed(message: str) -> dict[str, Any]:
    return {"ok": False, "identity": None, "error": message, "detail": message, "status": None}


def _origin_of(url: str) -> str:
    after = url.find("://")
    after = after + 3 if after >= 0 else 0
    slash = url.find("/", after)
    return url if slash < 0 else url[:slash]


def prepare_test(
    p: Provider, values: Mapping[str, Resolved], config: _config.Config
) -> tuple[str, dict[str, str]]:
    """The test request of ``p``: ``(url, headers)``. Raises ``ValueError`` when there is no
    test, no credential, or the URL is not https."""
    test = p.test_http
    if not test:
        raise ValueError(f"{p.title} has no built-in test")
    primary = p.primary()
    if primary is None:
        raise ValueError("provider declares no field")
    if primary.name not in values:
        raise ValueError(f"no {primary.title} is configured")
    secret = values[primary.name].value
    url = str(test.get("url") or "")
    origin: str | None = None
    url_field, url_setting = test.get("url_field"), test.get("url_setting")
    if url_field and url_field in values:
        origin = values[url_field].value
    elif url_setting:
        entry = config.entry(url_setting)
        if entry is not None and isinstance(entry.value, str) and entry.value:
            origin = entry.value
    if origin:
        path = test.get("url_path")
        if path is None:
            path = url[len(_origin_of(url)) :]
        url = origin.rstrip("/") + path
    if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise ValueError(
            f"refusing to send a credential over an insecure connection ({_origin_of(url)})"
        )
    headers = {"Accept": "application/json"}
    scheme = str(test.get("auth") or "")
    if scheme in ("", "bearer"):
        headers["Authorization"] = f"Bearer {secret}"
    elif scheme == "basic":
        user = values["username"].value if "username" in values else ""
        pair = base64.b64encode(f"{user}:{secret}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {pair}"
    elif scheme.startswith("header:"):
        name, _, prefix = scheme[len("header:") :].partition(":")
        headers[name] = f"{prefix}{secret}"
    else:
        raise ValueError(f"unsupported test auth scheme {json.dumps(scheme)}")
    return url, headers


def _pointer(doc: Any, pointer: str) -> Any:
    """RFC 6901 lookup; ``None`` when the path does not exist."""
    if pointer == "":
        return doc
    if not pointer.startswith("/"):
        return None
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(doc, dict) and token in doc:
            doc = doc[token]
        elif isinstance(doc, list) and token.isdigit() and int(token) < len(doc):
            doc = doc[int(token)]
        else:
            return None
    return doc


def interpret_test(test: Mapping[str, Any], status: int, body: str) -> dict[str, Any]:
    """Turn a response into ``{"ok", "identity", "error", "detail", "status"}``."""
    if 200 <= status < 300:
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        identity = None
        if test.get("identity") is not None and doc is not None:
            v = _pointer(doc, test["identity"])
            if v is not None:
                identity = v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))
        count = None
        if test.get("count") is not None and doc is not None:
            v = _pointer(doc, test["count"])
            count = len(v) if isinstance(v, list) else None
        if identity is not None:
            detail = f"signed in as {identity}"
        elif count is not None:
            detail = f"accepted ({count} item{'' if count == 1 else 's'} visible)"
        else:
            detail = "accepted"
        return {"ok": True, "identity": identity, "error": None, "detail": detail, "status": status}
    if status == 401:
        message = "rejected: the credential is invalid or expired (HTTP 401)"
    elif status == 403:
        message = "rejected: the credential is valid but lacks permission (HTTP 403)"
    else:
        message = f"the service answered HTTP {status}; the credential could not be verified"
    return {"ok": False, "identity": None, "error": message, "detail": message, "status": status}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A credential never follows a redirect: the 3xx answer is reported instead."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _no_proxy(host: str, patterns: list[str]) -> bool:
    host = host.lower()
    for raw in patterns:
        pat = raw.strip().lower()
        if not pat:
            continue
        if pat == "*" or host == pat.lstrip(".") or host.endswith("." + pat.lstrip(".")):
            return True
    return False


def build_opener(config: _config.Config, url: str) -> urllib.request.OpenerDirector:
    """A urllib opener that honours the network settings (proxy, proxy exceptions, CA bundle)
    and does not follow redirects. An unreadable CA bundle is an error: falling back to the
    public roots would hide a misconfiguration."""
    proxies: dict[str, str] = {}
    host = urllib.parse.urlsplit(url).hostname or ""
    if not _no_proxy(host, config.list("network.no_proxy")):
        for scheme in ("https", "http"):
            proxy = config.str(f"network.{scheme}_proxy")
            if proxy:
                proxies[scheme] = proxy
    ca = config.path("network.ca_bundle")
    try:
        context = ssl.create_default_context(cafile=str(ca) if ca else None)
    except (OSError, ssl.SSLError) as e:
        raise ValueError(f"network.ca_bundle {ca}: {e}") from None
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )


def _urllib_transport(config: _config.Config) -> Transport:
    def send(url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, str]:
        _config.require_online(f"contacting {_origin_of(url)}", config, url=url)
        opener = build_opener(config, url)
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with opener.open(request, timeout=timeout) as resp:
                return resp.status, resp.read(1 << 20).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""

    return send


def _urllib_token_transport(config: _config.Config | None) -> TokenTransport:
    """POST a form to a token endpoint through the network settings (proxy, CA bundle)."""

    def send(url: str, form: Mapping[str, str], timeout: float) -> tuple[int, str]:
        cfg = config if config is not None else _config.get_config()
        _config.require_online(f"contacting {_origin_of(url)}", cfg, url=url)
        opener = build_opener(cfg, url)
        request = urllib.request.Request(
            url,
            data=urllib.parse.urlencode(dict(form)).encode("ascii"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with opener.open(request, timeout=timeout) as resp:
                return resp.status, resp.read(1 << 20).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""

    return send


def _call_test_callable(spec: str) -> dict[str, Any] | None:
    """Run a provider's ``module:function`` test. ``None`` when it cannot be imported."""
    module, _, name = spec.partition(":")
    try:
        fn = getattr(importlib.import_module(module), name)
    except (ImportError, AttributeError):
        return None
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001 - a plugin's test must not take the caller down
        return _failed(f"the test failed with {type(e).__name__}")
    if not isinstance(out, Mapping):
        return _failed("the test returned no result")
    message = out.get("error")
    detail = out.get("detail")
    return {
        "ok": bool(out.get("ok")),
        "identity": out.get("identity") if isinstance(out.get("identity"), str) else None,
        "error": str(message) if message else None,
        "detail": str(detail if detail is not None else message or ""),
        "status": out.get("status") if isinstance(out.get("status"), int) else None,
    }


def test(
    id: str,
    *,
    config: _config.Config | None = None,
    transport: Transport | None = None,
    record: bool = True,
) -> dict[str, Any]:
    """Test the credential of provider ``id`` with one read-only request. Returns
    ``{"ok": bool, "identity": str | None, "error": str | None, "detail": str,
    "status": int | None}``; ``detail`` never contains the credential. Honours
    ``network.offline``, the proxy and the CA bundle. The outcome is recorded for ``status``
    unless ``record`` is false."""
    config = config if config is not None else _config.get_config()
    r = Resolver.from_config(config)
    p = r.provider(id)
    values = r.values(id)
    redactor = Redactor(v.value for v in values.values())
    out = _run_test(p, values, config, transport)
    out["detail"] = redactor.redact(out["detail"])
    if out["error"]:
        out["error"] = redactor.redact(out["error"])
    if record:
        r.record_test(id, out["ok"], out["detail"])
    return out


test.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


def _run_test(
    p: Provider,
    values: Mapping[str, Resolved],
    config: _config.Config,
    transport: Transport | None,
) -> dict[str, Any]:
    if config.bool("network.offline"):
        # stricter than the shared guard on purpose: no test runs offline, wherever it points
        return _failed("offline mode is on (network.offline); the credential was not tested")
    if p.test and not p.test.startswith(f"{__name__}:") and transport is None:
        out = _call_test_callable(p.test)
        if out is not None:
            return out
    if not p.test_http:
        return _failed(f"{p.title} has no built-in test")
    try:
        url, headers = prepare_test(p, values, config)
        send = transport or _urllib_transport(config)
        status, body = send(url, headers, TEST_TIMEOUT_SECS)
    except ValueError as e:
        return _failed(str(e))
    except (OSError, urllib.error.URLError) as e:
        reason = getattr(e, "reason", None)
        what = type(reason).__name__ if isinstance(reason, Exception) else type(e).__name__
        return _failed(f"could not reach {_origin_of(str(p.test_http.get('url') or ''))}: {what}")
    return interpret_test(p.test_http, status, body)


def test_huggingface(transport: Transport | None = None) -> dict[str, Any]:
    """``GET <endpoint>/api/whoami-v2`` with the Hugging Face token (the endpoint follows the
    setting ``hub.huggingface_endpoint``)."""
    return test("huggingface", transport=transport)


def test_runpod(transport: Transport | None = None) -> dict[str, Any]:
    """``GET https://rest.runpod.io/v1/pods`` with the RunPod API key."""
    return test("runpod", transport=transport)


test_huggingface.__test__ = False  # type: ignore[attr-defined]
test_runpod.__test__ = False  # type: ignore[attr-defined]


# -- module-level API (the process-wide resolver) ---------------------------------------------


def resolver(config: _config.Config | None = None) -> Resolver:
    """The resolver of ``config`` (default: the process-wide configuration)."""
    return Resolver.from_config(config)


def providers() -> list[Provider]:
    """Every known provider: built-in ones, then the ones installed plugins declared."""
    return list(resolver().registry)


def provider_for_env(var: str) -> tuple[str, str] | None:
    """``(provider id, field name)`` of the credential that accepts the environment variable
    ``var`` as a fallback."""
    found = resolver().registry.by_env(var)
    return (found[0].id, found[1].name) if found else None


def resolve(provider_id: str, field: str | None = None) -> Resolved | None:
    """The value of a credential field (default: the provider's primary secret) and where it
    came from, or ``None``. Raises :class:`UnknownProviderError` for an unknown id."""
    return resolver().resolve(provider_id, field)


def require(provider_id: str) -> str:
    """The primary secret of a provider. Raises :class:`MissingCredentialError` with the
    command, the environment fallbacks and the page where a credential is issued."""
    return resolver().require(provider_id)


def status(provider_id: str) -> dict[str, Any]:
    """Status of one provider (id, title, kind, fields, configured, source, last test ...).
    Never contains a secret value."""
    return resolver().status(provider_id)


def quiet_status(provider_id: str) -> dict[str, Any] | None:
    """:func:`status` without ever touching the OS keychain (no prompt) or the network: job
    bindings, the credentials file and the environment only. ``None`` when that cannot say
    whether the credential is configured (the keychain is the store and nothing else has a
    value). For listings."""
    r = Resolver.from_config(keychain=False)
    st = r.status(provider_id)
    return st if st["configured"] or r.complete else None


def statuses() -> list[dict[str, Any]]:
    """Status of every provider. Never contains a secret value."""
    return resolver().statuses()


SERVER_PROVIDER = "frontier"
"""The credential that authenticates this machine to a Frontier control plane."""


def local_server_token(server_url: str) -> str | None:
    """The local token of a single-user server (`auth.mode = "none"`) on this machine: the
    server writes it to `<frontier home>/servers/<port>.token`, readable by its owner only.
    `None` for a server elsewhere, or when there is no such file."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(server_url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https"):
            return None
        if host not in ("localhost", "127.0.0.1", "::1") and not host.endswith(".localhost"):
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = _config.frontier_home() / "servers" / f"{port}.token"
        token = path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return None
    return token or None


SERVER_TOKENS = "frontier-server"
"""Provider id under which tokens for individual control planes are kept in the secret store;
the field is :func:`server_key` of the server URL."""


def server_key(server_url: str) -> str | None:
    """The name of the server at `server_url` in the secret store: its host, with the port
    when the URL names one (`pod-8787.proxy.example.net`, `frontier.example.com_8443`)."""
    for scheme in ("https://", "http://"):
        if server_url.startswith(scheme):
            rest = server_url[len(scheme) :]
            break
    else:
        return None
    for sep in "/?#":
        rest = rest.split(sep, 1)[0]
    name = rest.lower().replace(":", "_")
    ok = (
        bool(name)
        and len(name) <= 255
        and not name.startswith(".")
        and ".." not in name
        and all(c.isascii() and (c.isalnum() or c in ".-_[]") for c in name)
    )
    return name if ok else None


def _kept_server_token(server_url: str) -> str | None:
    """The token kept for exactly this server (a pod started with `frontier cloud up
    --standalone`, or `frontier login` against it), from the configured secret store."""
    key = server_key(server_url)
    if not key:
        return None
    try:
        value = resolver().store.get(SERVER_TOKENS, key)
    except Exception as exc:  # noqa: BLE001 - an unusable store must not stop a run
        log.debug("frontier: no kept server token (%s)", type(exc).__name__)
        return None
    return value.strip() if value and value.strip() else None


def server_token(server_url: str | None = None) -> str | None:
    """The token for the control plane, most specific first: the local token of a
    single-user server at `server_url` on this machine; the token kept for exactly that
    server in the secret store (provider `frontier-server`); the `frontier` credential
    (`frontier login` stores it; `FRONTIER_TOKEN` is the fallback); else `None`. Never
    raises: an unusable secret store must not stop a run.
    """
    local = local_server_token(server_url) if server_url else None
    if local:
        return local
    kept = _kept_server_token(server_url) if server_url else None
    if kept:
        return kept
    try:
        found = resolve(SERVER_PROVIDER)
    except Exception as exc:  # noqa: BLE001 - tracking is best-effort
        log.debug("frontier: no server token (%s)", type(exc).__name__)
        found = None
    return found.value if found and found.value else None


def server_headers(server_url: str | None = None) -> dict[str, str]:
    """`Authorization` header for requests to the control plane (empty without a token)."""
    token = server_token(server_url)
    return {"Authorization": f"Bearer {token}"} if token else {}


def login(provider_id: str, values: Mapping[str, str]) -> None:
    """Store ``values`` (field -> value) in the configured secret store."""
    resolver().login(provider_id, values)


def logout(provider_id: str) -> int:
    """Remove the stored fields of a provider. Returns how many entries were removed."""
    return resolver().logout(provider_id)


def env_for(ids: Iterable[str]) -> dict[str, str]:
    """Environment for a child process that needs the given providers (including
    ``FRONTIER_CREDENTIALS_BOUND``)."""
    return resolver().env_for(ids)


def secrets() -> list[str]:
    """Every secret value that can be resolved in this process, for redacting logs."""
    return resolver().secrets()


def redact(text: str, extra: Iterable[str] = ()) -> str:
    """``text`` with every known secret (and ``extra``) replaced by ``***``."""
    return Redactor([*secrets(), *extra]).redact(text)


__all__ = [
    "BOUND_ENV",
    "KEYCHAIN_SERVICE",
    "AuthError",
    "EnvStore",
    "ExpiredCredentialError",
    "Field",
    "FileStore",
    "KeychainStore",
    "MemoryStore",
    "MissingCredentialError",
    "Provider",
    "Redactor",
    "Registry",
    "Resolved",
    "Resolver",
    "UnknownProviderError",
    "env_for",
    "login",
    "logout",
    "provider_for_env",
    "providers",
    "quiet_status",
    "redact",
    "require",
    "resolve",
    "resolver",
    "secrets",
    "status",
    "statuses",
    "test",
    "test_huggingface",
    "test_runpod",
]
