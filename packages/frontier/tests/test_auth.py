# SPDX-License-Identifier: Apache-2.0
"""`frontier.auth`: stores, resolution order, status without values, credential tests.
Nothing here touches the network or a real keychain."""

from __future__ import annotations

import json
import os
import stat
import sys
import tomllib
import types
from pathlib import Path

import pytest

from frontier import auth, config
from frontier.auth import AuthError, FileStore, MemoryStore, Registry, Resolver

HF = "hf_store_value_0001"


def resolver(env: dict[str, str] | None = None, store=None, **kw) -> Resolver:
    return Resolver(Registry.builtin(), store or MemoryStore(), env or {}, **kw)


class FakeKeyring(types.ModuleType):
    """Stands in for the optional `keyring` package."""

    def __init__(self) -> None:
        super().__init__("keyring")
        self.entries: dict[tuple[str, str], str] = {}

    def get_keyring(self):
        return types.SimpleNamespace(priority=5)

    def get_password(self, service: str, account: str) -> str | None:
        return self.entries.get((service, account))

    def set_password(self, service: str, account: str, value: str) -> None:
        self.entries[(service, account)] = value

    def delete_password(self, service: str, account: str) -> None:
        del self.entries[(service, account)]


@pytest.fixture
def keyring(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", fake)
    monkeypatch.setenv("FRONTIER_SECRETS__BACKEND", "auto")
    return fake


# -- registry -------------------------------------------------------------------------------


def test_builtin_providers_cover_the_contract():
    r = Registry.builtin()
    for id in (
        "frontier huggingface runpod anyscale flow360 luminary simscale rescale s3 gcs azure "
        "registry ssh"
    ).split():
        p = r.get(id)
        assert p is not None and p.title and p.fields, id
        assert all(f.title for f in p.fields), id
    hf = r.get("huggingface")
    assert hf is not None
    primary = hf.primary()
    assert primary is not None and primary.env == ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"]
    found = r.by_env("AWS_SECRET_ACCESS_KEY")
    assert found is not None and (found[0].id, found[1].name) == ("s3", "secret_access_key")
    assert auth.provider_for_env("RUNPOD_API_KEY") == ("runpod", "api_key")
    assert auth.provider_for_env("NOT_A_CREDENTIAL") is None
    # the normalised declarations are exactly the committed export
    assert [p.to_dict() for p in r] == auth.builtin_declarations()
    seen: set[str] = set()
    for p in r:
        for f in p.fields:
            assert not seen & set(f.env), f"{f.env} claimed twice"
            seen |= set(f.env)


def test_plugin_declarations_merge_by_id(_isolated_frontier_home):
    home: Path = _isolated_frontier_home
    (home / auth.PLUGIN_PROVIDERS_FILE).write_text(
        json.dumps(
            [
                {"id": "huggingface", "title": "Hugging Face", "env": ["HF_API_TOKEN"],
                 "declared_by": ["acme"]},
                {"id": "acme-cloud", "title": "Acme Cloud", "kind": "api_key",
                 "env": ["ACME_KEY"], "help_url": "https://acme.example/keys",
                 "declared_by": ["acme"]},
                {"id": "Bad Id", "title": "x"},
                "not a table",
            ]
        )
    )  # fmt: skip
    r = Registry.load(home)
    hf = r.get("huggingface")
    assert hf is not None and hf.declared_by == ["acme"]
    primary = hf.primary()
    assert primary is not None
    assert primary.env == ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HF_API_TOKEN"]
    acme = r.get("acme-cloud")
    assert acme is not None
    key = acme.primary()
    assert key is not None and (key.name, key.title, key.env) == (
        "api_key",
        "api key",
        ["ACME_KEY"],
    )
    assert r.ids()[-1] == "acme-cloud" and r.get("Bad Id") is None
    assert [p.id for p in auth.providers()][-1] == "acme-cloud"
    with pytest.raises(ValueError, match="lower-case letters"):
        auth.Provider.from_dict({"id": "Bad Id", "title": "x"})
    (home / auth.PLUGIN_PROVIDERS_FILE).write_text("{broken")
    assert Registry.load(home).ids() == Registry.builtin().ids()


# -- stores ---------------------------------------------------------------------------------


def test_file_store_round_trip_is_owner_only(tmp_path):
    store = FileStore.in_home(tmp_path / "home")
    assert store.get("huggingface", "token") is None
    awkward = 'quote " backslash \\ newline \n tab \t unicode é \x01'
    store.set("huggingface", "token", HF)
    store.set("s3", "access_key_id", "AKIA")
    store.set("s3", "secret_access_key", awkward)
    store.set("odd id", "a.b", "v")
    assert store.get("huggingface", "token") == HF
    assert store.get("s3", "secret_access_key") == awkward
    assert store.get("odd id", "a.b") == "v"
    if os.name == "posix":
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert not list(store.path.parent.glob("*.tmp*")), "the temporary file was renamed"
    assert store.delete("s3", "secret_access_key")
    assert not store.delete("s3", "secret_access_key")
    assert store.delete("s3", "access_key_id")
    text = store.path.read_text()
    assert "[s3]" not in text and text.startswith("# Frontier credentials")
    assert tomllib.loads(text)["huggingface"] == {"token": HF}


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_file_store_refuses_a_world_readable_file(tmp_path, caplog):
    store = FileStore.in_home(tmp_path)
    store.set("runpod", "api_key", "rp_secret_value")
    store.path.chmod(0o644)
    with pytest.raises(AuthError) as exc:
        store.get("runpod", "api_key")
    assert "chmod 600" in str(exc.value) and "mode 644" in str(exc.value)
    assert "rp_secret_value" not in str(exc.value)
    with pytest.raises(AuthError, match="chmod 600"):
        store.set("runpod", "api_key", "other")
    # the resolver warns and falls back to the environment instead of failing
    r = resolver({"RUNPOD_API_KEY": "rp_env_value"}, store)
    found = r.resolve("runpod")
    assert found is not None and found.source == "env:RUNPOD_API_KEY"
    assert "secret store unavailable" in caplog.text and "rp_secret_value" not in caplog.text


def test_env_store_reads_fallbacks_and_is_read_only():
    env = {"HUGGING_FACE_HUB_TOKEN": " hf_from_env ", "RUNPOD_API_KEY": ""}
    store = auth.EnvStore(env, Registry.builtin())
    assert store.variable("huggingface", "token") == ("HUGGING_FACE_HUB_TOKEN", "hf_from_env")
    assert store.get("runpod", "api_key") is None and not store.writable
    with pytest.raises(AuthError, match="read-only"):
        store.set("runpod", "api_key", "x")


def test_backend_selection(tmp_path, monkeypatch, keyring):
    def store_for(backend: str):
        cfg = config.load(home=tmp_path, env={"FRONTIER_SECRETS__BACKEND": backend})
        return auth.open_store(cfg, Registry.builtin())

    assert store_for("file").name == "file" and store_for("env").name == "env"
    assert isinstance(store_for("auto"), auth.KeychainStore)
    assert isinstance(store_for("keychain"), auth.KeychainStore)
    # no `keyring` package, or one without a backend: auto falls back to the file
    monkeypatch.setitem(sys.modules, "keyring", None)
    assert isinstance(store_for("auto"), FileStore)
    unavailable = store_for("keychain")
    with pytest.raises(AuthError, match="secrets.backend file"):
        unavailable.set("runpod", "api_key", "x")
    failing = FakeKeyring()
    failing.get_keyring = lambda: types.SimpleNamespace(priority=0)  # type: ignore[method-assign]
    monkeypatch.setitem(sys.modules, "keyring", failing)
    assert isinstance(store_for("auto"), FileStore)


def test_keychain_store_uses_the_shared_service_and_account(keyring):
    auth.login("huggingface", {"token": HF})
    assert keyring.entries == {(auth.KEYCHAIN_SERVICE, "huggingface/token"): HF}
    found = auth.resolve("huggingface")
    assert found is not None and (found.value, found.source) == (HF, "keychain")
    assert auth.status("huggingface")["source"] == {"store": "keychain", "detail": None}
    assert auth.logout("huggingface") == 1 and auth.logout("huggingface") == 0
    assert keyring.entries == {} and auth.resolve("huggingface") is None


def test_legacy_keyring_entries_are_the_last_fallback(keyring, monkeypatch):
    keyring.entries[(auth.LEGACY_KEYRING_SERVICE, "FLOW360_APIKEY")] = "legacy-flow-key"
    found = auth.resolve("flow360")
    assert found is not None
    assert (found.value, found.source) == ("legacy-flow-key", "keychain:legacy")
    monkeypatch.setenv("FLOW360_APIKEY", "env-flow-key")
    found = auth.resolve("flow360")
    assert found is not None and found.source == "env:FLOW360_APIKEY"
    # an explicit file backend never asks a keychain
    monkeypatch.delenv("FLOW360_APIKEY")
    monkeypatch.setenv("FRONTIER_SECRETS__BACKEND", "file")
    assert auth.resolve("flow360") is None


# -- resolver -------------------------------------------------------------------------------


def test_order_is_binding_then_store_then_env():
    r = resolver({"HF_TOKEN": "hf_env_value"})
    found = r.resolve("huggingface", "token")
    assert found is not None and (found.value, found.source) == ("hf_env_value", "env:HF_TOKEN")
    r.login("huggingface", {"token": HF})
    found = r.resolve("huggingface")
    assert found is not None and (found.value, found.source) == (HF, "memory")
    # a job binding wins over the store
    r2 = resolver({"HF_TOKEN": "hf_job_value", auth.BOUND_ENV: "runpod, huggingface"})
    r2.store.set("huggingface", "token", HF)
    found = r2.resolve("huggingface")
    assert found is not None and (found.value, found.source) == ("hf_job_value", "job")
    assert repr(found) == str(found) == "Resolved(value=***, source='job')"
    assert "hf_job_value" not in f"{found} {found!r} {[found]}"
    with pytest.raises(AuthError, match="no field `nope`"):
        r.resolve("huggingface", "nope")


def test_missing_credential_error_guides_the_user_without_values():
    r = resolver()
    with pytest.raises(auth.MissingCredentialError) as exc:
        r.require("huggingface")
    assert str(exc.value) == (
        "Hugging Face is not signed in: run `frontier auth login huggingface` (or set "
        "HF_TOKEN / HUGGING_FACE_HUB_TOKEN in the environment). Get a credential at "
        "https://huggingface.co/settings/tokens"
    )
    assert (exc.value.id, exc.value.help_url) == ("huggingface", hf_help())
    with pytest.raises(auth.MissingCredentialError) as exc:
        r.require("ssh")
    assert str(exc.value).endswith("run `frontier auth login ssh`")
    with pytest.raises(auth.UnknownProviderError) as unknown:
        r.require("nope")
    assert "unknown credential provider `nope`" in str(unknown.value)
    assert "huggingface" in str(unknown.value)
    assert resolver({"RUNPOD_API_KEY": " rp_value "}).require("runpod") == "rp_value"


def hf_help() -> str:
    p = Registry.builtin().get("huggingface")
    assert p is not None and p.help_url
    return p.help_url


def test_status_never_contains_secret_values(tmp_path):
    r = resolver({"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE"}, state_path=tmp_path / auth.STATE_FILE)
    r.login("s3", {"secret_access_key": "super-secret-value"})
    r.record_test("s3", False, "HTTP 403 for key super-secret-value")
    st = r.status("s3")
    assert st["configured"] and st["source"] == {"store": "memory", "detail": None}
    assert st["last_test"]["ok"] is False and st["last_test"]["detail"] == "HTTP 403 for key ***"
    assert (st["last_test_ok"], st["last_test_detail"]) == (False, "HTTP 403 for key ***")
    text = json.dumps(r.statuses())
    assert "super-secret-value" not in text
    assert "AKIAEXAMPLE" in text, "non-secret fields are shown"
    assert "super-secret-value" not in (tmp_path / auth.STATE_FILE).read_text()
    hf = r.status("huggingface")
    assert not hf["configured"] and hf["source"] is None and hf["testable"]
    assert set(hf) == {
        "id", "title", "category", "kind", "fields", "configured", "source", "last_test",
        "last_tested", "last_test_ok", "last_test_detail", "env", "help_url", "scopes_hint",
        "testable", "declared_by",
    }  # fmt: skip
    assert set(hf["fields"][0]) == {
        "name", "title", "secret", "required", "configured", "source", "env", "value"
    }  # fmt: skip


def test_state_file_is_shared_with_the_command_line(_isolated_frontier_home):
    home: Path = _isolated_frontier_home
    # as written by the command line (nanosecond timestamp)
    (home / auth.STATE_FILE).write_text(
        '{"runpod": {"at": "2026-10-10T08:15:30.123456789Z", "ok": true, "detail": "3 pods"}}'
    )
    auth.login("runpod", {"api_key": "rp_value_123"})
    assert auth.status("runpod")["last_tested"] is None, "a new login forgets the old test"
    auth.resolver().record_test("runpod", True, "accepted")
    record = json.loads((home / auth.STATE_FILE).read_text())["runpod"]
    assert set(record) == {"at", "ok", "detail"} and record["at"].endswith("Z")
    assert auth.status("runpod")["last_tested"] == record["at"]


def test_login_validates_and_logout_removes(_isolated_frontier_home):
    home: Path = _isolated_frontier_home
    with pytest.raises(AuthError, match="needs a value for `secret_access_key`"):
        auth.login("s3", {"access_key_id": "AKIA"})
    with pytest.raises(AuthError, match="no field `tokn`"):
        auth.login("runpod", {"tokn": "x"})
    with pytest.raises(auth.UnknownProviderError):
        auth.login("nope", {})
    assert not (home / auth.CREDENTIALS_FILE).exists(), "nothing is written on a refused login"
    auth.login("runpod", {"api_key": " rp_value_123 "})
    auth.resolver().record_test("runpod", True, "3 pods")
    st = auth.status("runpod")
    assert (st["configured"], st["source"]["store"], st["last_test_ok"]) == (True, "file", True)
    assert auth.require("runpod") == "rp_value_123"
    if os.name == "posix":
        assert stat.S_IMODE((home / auth.CREDENTIALS_FILE).stat().st_mode) == 0o600
    assert auth.logout("runpod") == 1
    st = auth.status("runpod")
    assert not st["configured"] and st["last_tested"] is None


def test_env_for_children_and_redaction(monkeypatch):
    r = resolver({"ANYSCALE_API_KEY": "as_value_123", "ANYSCALE_CLOUD_ID": "cld_1"})
    r.login("huggingface", {"token": HF})
    child = r.env_for(["huggingface", "runpod", "anyscale", "nope"])
    assert child["HF_TOKEN"] == HF and child["ANYSCALE_API_KEY"] == "as_value_123"
    assert child[auth.BOUND_ENV] == "huggingface,anyscale" and "RUNPOD_API_KEY" not in child
    # the child resolves them as job bindings
    bound = resolver(child).resolve("huggingface")
    assert bound is not None and bound.source == "job"
    assert sorted(r.secrets()) == ["as_value_123", HF]
    red = auth.Redactor(["hf_abcdef123456", "abc", "hf_abcdef", ""])
    assert (
        red.redact("Authorization: Bearer hf_abcdef123456 then hf_abcdef and abc")
        == "Authorization: Bearer *** then *** and abc"
    )
    assert not auth.Redactor([""])
    monkeypatch.setenv("HF_TOKEN", HF)
    assert auth.secrets() == [HF] and auth.env_for(["huggingface"])["HF_TOKEN"] == HF
    assert auth.redact(f"token {HF} and extra-secret", ["extra-secret"]) == "token *** and ***"


# -- credential tests -----------------------------------------------------------------------


def values(**pairs: str) -> dict[str, auth.Resolved]:
    return {k: auth.Resolved(v, "memory") for k, v in pairs.items()}


def provider(id: str) -> auth.Provider:
    p = Registry.builtin().get(id)
    assert p is not None
    return p


def test_requests_per_auth_scheme():
    cfg = config.load()
    url, headers = auth.prepare_test(provider("huggingface"), values(token="hf_x"), cfg)
    assert url == "https://huggingface.co/api/whoami-v2"
    assert headers["Authorization"] == "Bearer hf_x"
    mirror = config.load(env={"HF_ENDPOINT": "https://hf.example.com/"})
    url, _ = auth.prepare_test(provider("huggingface"), values(token="hf_x"), mirror)
    assert url == "https://hf.example.com/api/whoami-v2"
    url, _ = auth.prepare_test(provider("runpod"), values(api_key="rp_x"), cfg)
    assert url == "https://rest.runpod.io/v1/pods"
    _, headers = auth.prepare_test(provider("flow360"), values(api_key="k"), cfg)
    assert headers["simcloud-api-key"] == "k"
    url, headers = auth.prepare_test(
        provider("rescale"), values(api_key="k", api_url="https://eu.rescale.com/"), cfg
    )
    assert url == "https://eu.rescale.com/api/v2/users/me/"
    assert headers["Authorization"] == "Token k"
    with pytest.raises(ValueError, match="insecure"):
        auth.prepare_test(
            provider("simscale"), values(api_key="k", api_url="http://insecure.example"), cfg
        )
    with pytest.raises(ValueError, match="has no built-in test"):
        auth.prepare_test(provider("luminary"), values(api_key="k"), cfg)
    with pytest.raises(ValueError, match="no API key is configured"):
        auth.prepare_test(provider("runpod"), {}, cfg)
    basic = auth.Provider.from_dict(
        {"id": "b", "title": "B", "kind": "basic",
         "fields": [{"name": "username", "secret": False}, {"name": "password"}],
         "test_http": {"url": "https://b.example.com/me", "auth": "basic"}}
    )  # fmt: skip
    _, headers = auth.prepare_test(basic, values(username="ada", password="pw"), cfg)
    assert headers["Authorization"] == "Basic YWRhOnB3"


def test_responses():
    hf, rp = provider("huggingface").test_http, provider("runpod").test_http
    assert hf is not None and rp is not None
    ok = auth.interpret_test(hf, 200, '{"name":"ada","type":"user"}')
    assert ok == {
        "ok": True, "identity": "ada", "error": None, "detail": "signed in as ada", "status": 200
    }  # fmt: skip
    assert auth.interpret_test(rp, 200, "[{},{}]")["detail"] == "accepted (2 items visible)"
    assert auth.interpret_test(rp, 200, "[{}]")["detail"] == "accepted (1 item visible)"
    assert auth.interpret_test(hf, 200, "not json")["detail"] == "accepted"
    assert "invalid or expired" in auth.interpret_test(hf, 401, "")["error"]
    assert "lacks permission" in auth.interpret_test(hf, 403, "")["error"]
    assert "could not be verified" in auth.interpret_test(hf, 503, "")["error"]
    nested = {"identity": "/result/email"}
    assert auth.interpret_test(nested, 200, '{"result":{"email":"a@b"}}')["identity"] == "a@b"


def test_test_callables_use_the_resolved_credential_and_record_the_outcome(monkeypatch):
    calls: list[tuple[str, dict[str, str]]] = []

    def transport(url, headers, timeout):
        calls.append((url, dict(headers)))
        if "runpod" in url:
            return 401, ""
        return 200, json.dumps({"name": "ada", "echo": headers["Authorization"]})

    monkeypatch.setenv("HF_TOKEN", HF)
    monkeypatch.setenv("FRONTIER_HUB__HUGGINGFACE_ENDPOINT", "https://hf.example.com")
    out = auth.test_huggingface(transport=transport)
    assert out == {
        "ok": True, "identity": "ada", "error": None, "detail": "signed in as ada", "status": 200
    }  # fmt: skip
    assert calls == [
        ("https://hf.example.com/api/whoami-v2",
         {"Accept": "application/json", "Authorization": f"Bearer {HF}"})
    ]  # fmt: skip
    st = auth.status("huggingface")
    assert (st["last_test_ok"], st["last_test_detail"]) == (True, "signed in as ada")

    auth.login("runpod", {"api_key": "rp_value_123"})
    out = auth.test_runpod(transport=transport)
    assert (out["ok"], out["status"]) == (False, 401) and "invalid or expired" in out["error"]
    assert calls[-1][0] == "https://rest.runpod.io/v1/pods"
    assert auth.status("runpod")["last_test_ok"] is False

    out = auth.test("flow360", transport=transport, record=False)
    assert not out["ok"] and out["error"] == "no API key is configured"
    assert auth.status("flow360")["last_tested"] is None
    assert not auth.test("luminary", transport=transport)["ok"]


def test_a_test_never_leaks_the_credential_and_respects_offline(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", HF)

    def leaky(url, headers, timeout):
        raise OSError(f"connection reset while sending {headers['Authorization']}")

    out = auth.test("huggingface", transport=leaky)
    assert not out["ok"] and HF not in json.dumps(out)
    assert out["error"].startswith("could not reach https://huggingface.co")
    monkeypatch.setenv("FRONTIER_NETWORK__OFFLINE", "1")

    def forbidden(url, headers, timeout):
        raise AssertionError("offline mode must not connect")

    out = auth.test("huggingface", transport=forbidden)
    assert not out["ok"] and "offline mode is on (network.offline)" in out["error"]


def test_plugin_test_callable_is_used_when_it_can_be_imported(_isolated_frontier_home, monkeypatch):
    home: Path = _isolated_frontier_home
    module = types.ModuleType("acme_auth_test")
    module.check = lambda: {"ok": True, "identity": "acme-user", "detail": "fine"}  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "acme_auth_test", module)
    (home / auth.PLUGIN_PROVIDERS_FILE).write_text(
        json.dumps(
            [
                {"id": "acme", "title": "Acme", "env": ["ACME_TOKEN"],
                 "test": "acme_auth_test:check"},
                {"id": "gone", "title": "Gone", "env": ["GONE_TOKEN"],
                 "test": "not_installed_anywhere:check"},
            ]
        )
    )  # fmt: skip
    out = auth.test("acme")
    assert (out["ok"], out["identity"], out["detail"]) == (True, "acme-user", "fine")
    assert auth.test("gone")["error"] == "Gone has no built-in test"


def test_opener_honours_proxy_exceptions_and_a_missing_ca_bundle(tmp_path):
    cfg = config.load(
        env={
            "FRONTIER_NETWORK__HTTPS_PROXY": "http://proxy.example.com:3128",
            "FRONTIER_NETWORK__NO_PROXY": "localhost,.example.org",
        }
    )

    def proxies(url: str) -> dict[str, str]:
        opener = auth.build_opener(cfg, url)
        handlers = [h for h in vars(opener)["handlers"] if type(h).__name__ == "ProxyHandler"]
        return handlers[0].proxies if handlers else {}  # type: ignore[attr-defined]

    assert proxies("https://huggingface.co/x") == {"https": "http://proxy.example.com:3128"}
    assert proxies("https://mirror.example.org/x") == {}
    bad = config.load(env={"FRONTIER_NETWORK__CA_BUNDLE": str(tmp_path / "missing.pem")})
    with pytest.raises(ValueError, match="network.ca_bundle"):
        auth.build_opener(bad, "https://huggingface.co")


# -- OAuth token sets -------------------------------------------------------------------------


class TokenEndpoint:
    """A local identity provider: answers `POST /token` and records the forms it was sent."""

    def __init__(self) -> None:
        import http.server
        import threading
        import urllib.parse

        self.forms: list[dict[str, str]] = []
        self.answer: tuple[int, dict[str, object]] = (
            200,
            {"access_token": "at-new-0001", "refresh_token": "rt-new-0001", "expires_in": 3600},
        )
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                size = int(self.headers.get("content-length", "0"))
                form = urllib.parse.parse_qs(self.rfile.read(size).decode())
                outer.forms.append({k: v[0] for k, v in form.items()})
                status, doc = outer.answer
                body = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/token"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def idp(_isolated_frontier_home, monkeypatch):
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    endpoint = TokenEndpoint()
    declaration = {
        "id": "acme-cloud",
        "title": "Acme Cloud",
        "kind": "oauth_device",
        "oauth": {
            "token_url": endpoint.url,
            "device_code_url": "https://id.example.com/device",
            "client_id": "frontier-desktop",
            "scopes": ["read"],
        },
        "some_future_key": {"is": "tolerated"},
        "declared_by": ["acme"],
    }
    pkce = {
        "id": "acme-web",
        "title": "Acme Web",
        "kind": "oauth_pkce",
        "oauth": {
            "authorize_url": "https://id.example.com/authorize",
            "token_url": "https://id.example.com/token",
            "client_id": "frontier-desktop",
            "redirect_port": 8765,
        },
    }
    (_isolated_frontier_home / auth.PLUGIN_PROVIDERS_FILE).write_text(
        json.dumps([declaration, pkce])
    )
    yield endpoint
    endpoint.close()


def stamp(offset_secs: float) -> str:
    from datetime import UTC, datetime, timedelta

    at = datetime.now(UTC) + timedelta(seconds=offset_secs)
    return at.isoformat().replace("+00:00", "Z")


def test_oauth_providers_parse_with_the_stored_token_set(idp):
    by_id = {p.id: p for p in auth.providers()}
    acme, web = by_id["acme-cloud"], by_id["acme-web"]
    assert acme.kind == "oauth_device" and web.kind == "oauth_pkce"
    assert [(f.name, f.secret, f.required) for f in acme.fields] == [
        ("access_token", True, True),
        ("refresh_token", True, False),
        ("expires_at", False, False),
    ]
    primary = acme.primary()
    assert primary is not None and primary.name == "access_token"
    assert acme.oauth is not None and acme.oauth["client_id"] == "frontier-desktop"
    assert web.oauth is not None and web.oauth["redirect_port"] == 8765
    assert acme.to_dict()["oauth"]["token_url"] == idp.url
    assert "some_future_key" not in acme.to_dict()
    st = auth.status("acme-cloud")
    assert st["kind"] == "oauth_device" and not st["configured"]
    with pytest.raises(auth.MissingCredentialError, match="frontier auth login acme-cloud"):
        auth.require("acme-cloud")


def test_oauth_access_token_is_returned_while_valid_and_refreshed_when_expired(idp):
    auth.login(
        "acme-cloud",
        {"access_token": "at-old-0001", "refresh_token": "rt-old-0001", "expires_at": stamp(3600)},
    )
    found = auth.resolve("acme-cloud")
    assert found is not None and (found.value, found.source) == ("at-old-0001", "file")
    assert idp.forms == [], "a valid token is not refreshed"
    # no expiry recorded: used as it is
    auth.resolver().store.delete("acme-cloud", "expires_at")
    assert auth.require("acme-cloud") == "at-old-0001" and idp.forms == []

    auth.login("acme-cloud", {"expires_at": "2020-01-01T00:00:00.123456789Z"})
    assert auth.status("acme-cloud")["configured"] and idp.forms == [], "status never refreshes"
    assert auth.require("acme-cloud") == "at-new-0001"
    assert idp.forms == [
        {
            "grant_type": "refresh_token",
            "client_id": "frontier-desktop",
            "refresh_token": "rt-old-0001",
        }
    ]
    # the new token set was stored: the next call needs no request
    store = auth.resolver().store
    assert store.get("acme-cloud", "access_token") == "at-new-0001"
    assert store.get("acme-cloud", "refresh_token") == "rt-new-0001"
    expires = auth._parse_time(store.get("acme-cloud", "expires_at"))
    assert expires is not None and 3500 < expires.timestamp() - __import__("time").time() < 3700
    assert auth.require("acme-cloud") == "at-new-0001" and len(idp.forms) == 1
    # a token that is about to expire is renewed too
    auth.login("acme-cloud", {"expires_at": stamp(10)})
    idp.answer = (200, {"access_token": "at-newer-001"})
    assert auth.require("acme-cloud") == "at-newer-001" and len(idp.forms) == 2
    assert store.get("acme-cloud", "refresh_token") == "rt-new-0001", "kept when not rotated"
    assert store.get("acme-cloud", "expires_at") is None


def test_oauth_refresh_that_cannot_happen_asks_for_a_new_login(idp, monkeypatch):
    expired = {"access_token": "at-old-0001", "expires_at": stamp(-5)}
    auth.login("acme-cloud", expired)
    with pytest.raises(auth.ExpiredCredentialError) as exc:
        auth.require("acme-cloud")
    assert isinstance(exc.value, auth.MissingCredentialError)
    assert "no refresh token is stored" in str(exc.value)
    assert str(exc.value).endswith("run `frontier auth login acme-cloud`")
    assert idp.forms == []

    auth.login("acme-cloud", {"refresh_token": "rt-revoked-01"})
    idp.answer = (400, {"error": "invalid_grant"})
    with pytest.raises(auth.ExpiredCredentialError, match="answered HTTP 400") as exc:
        auth.resolve("acme-cloud")
    assert "rt-revoked-01" not in str(exc.value) and "at-old-0001" not in str(exc.value)
    assert auth.resolver().store.get("acme-cloud", "access_token") == "at-old-0001"

    monkeypatch.setenv("FRONTIER_NETWORK__OFFLINE", "1")
    before = len(idp.forms)
    with pytest.raises(auth.ExpiredCredentialError, match="offline mode is on"):
        auth.require("acme-cloud")
    assert len(idp.forms) == before
    monkeypatch.delenv("FRONTIER_NETWORK__OFFLINE")

    idp.close()
    with pytest.raises(auth.ExpiredCredentialError, match="could not reach http://127.0.0.1"):
        auth.require("acme-cloud")
    # a token injected by a launcher is used as it is, expired or not
    monkeypatch.setenv("ACME_ACCESS_TOKEN", "at-from-job")
    r = auth.resolver()
    provider = r.provider("acme-cloud")
    provider.fields[0].env.append("ACME_ACCESS_TOKEN")
    r.bound.add("acme-cloud")
    r.env["ACME_ACCESS_TOKEN"] = "at-from-job"
    found = r.resolve("acme-cloud")
    assert found is not None and (found.value, found.source) == ("at-from-job", "job")


def test_quiet_status_never_touches_the_keychain(keyring, monkeypatch):
    asked: list[tuple[str, str]] = []
    real = keyring.get_password

    def spy(service: str, account: str) -> str | None:
        asked.append((service, account))
        return real(service, account)

    keyring.get_password = spy
    keyring.entries[(auth.KEYCHAIN_SERVICE, "runpod/api_key")] = "rp_in_keychain"
    # only the keychain could tell: nothing is claimed, nothing is asked
    assert auth.quiet_status("runpod") is None and asked == []
    # the environment (or a job binding) answers without it
    monkeypatch.setenv("RUNPOD_API_KEY", "rp_env_value")
    st = auth.quiet_status("runpod")
    assert st is not None and st["configured"]
    assert st["source"] == {"store": "env", "detail": "RUNPOD_API_KEY"}
    assert asked == []
    assert auth.status("runpod")["source"]["store"] == "keychain" and asked
    # with the file store the answer is complete
    monkeypatch.delenv("RUNPOD_API_KEY")
    monkeypatch.setenv("FRONTIER_SECRETS__BACKEND", "file")
    st = auth.quiet_status("runpod")
    assert st is not None and st["configured"] is False
