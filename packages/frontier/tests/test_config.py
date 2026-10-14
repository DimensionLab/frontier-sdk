# SPDX-License-Identifier: Apache-2.0
"""`frontier.config`: the same behaviour as the command line's loader, checked with the same
cases."""

from __future__ import annotations

import json
import subprocess
import sys
from importlib import resources
from pathlib import Path

import pytest

from frontier import config
from frontier.config import PolicyViolation


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def layers(tmp_path):
    return {
        "system_file": tmp_path / "system.toml",
        "home": tmp_path / "home",
        "project_file": tmp_path / "proj" / config.PROJECT_FILE,
    }


def user_file(layers) -> Path:
    return layers["home"] / config.CONFIG_FILE


# -- loader ---------------------------------------------------------------------------------


def test_precedence_default_system_user_project_env_flag(layers):
    key = "compute.default_gpu"
    entry = config.load(**layers).entry(key)
    assert entry is not None and entry.source == "default"
    write(layers["system_file"], '[compute]\ndefault_gpu = "sys"\n')
    assert config.load(**layers).str(key) == "sys"
    write(user_file(layers), '[compute]\ndefault_gpu = "usr"\n')
    assert config.load(**layers).str(key) == "usr"
    write(layers["project_file"], '[compute]\ndefault_gpu = "prj"\n')
    assert config.load(**layers).str(key) == "prj"
    env = {"FRONTIER_COMPUTE__DEFAULT_GPU": "env"}
    c = config.load(**layers, env=env)
    entry = c.entry(key)
    assert entry is not None
    assert (c.str(key), entry.source, entry.origin) == (
        "env",
        "env",
        "FRONTIER_COMPUTE__DEFAULT_GPU",
    )
    c = config.load(**layers, env=env, overrides={key: "flag"})
    entry = c.entry(key)
    assert entry is not None
    assert (c.get(key), entry.source) == ("flag", "cli")
    # every lower layer is remembered, most recent last
    assert [s.source for s in entry.shadowed] == ["system", "user", "project", "env"]
    assert all(s.why == "overridden" for s in entry.shadowed)
    assert c.problems == []
    assert c.paths.user == user_file(layers) and c.paths.project == layers["project_file"]


def test_legacy_env_names_work_and_the_canonical_one_wins(layers):
    env = {"FRONTIER_SERVER": "http://legacy:1"}
    assert config.load(**layers, env=env).str("client.server_url") == "http://legacy:1"
    env["FRONTIER_CLIENT__SERVER_URL"] = "http://new:2/"
    c = config.load(**layers, env=env)
    assert c.str("client.server_url") == "http://new:2"
    entry = c.entry("client.server_url")
    assert entry is not None and entry.shadowed[0].origin == "FRONTIER_SERVER"


def test_system_lock_beats_every_lower_trust_layer_with_reason(layers):
    write(
        layers["system_file"],
        """
[policy]
allow_public_hub = false

[lock]
"policy.allow_public_hub" = "Data governance: internal mirror only"
"network.*" = true
""",
    )
    write(
        user_file(layers),
        '[policy]\nallow_public_hub = true\n[network]\nhttps_proxy = "http://evil:1"\n',
    )
    c = config.load(
        **layers,
        env={"FRONTIER_POLICY__ALLOW_PUBLIC_HUB": "true"},
        overrides={"policy.allow_public_hub": True},
    )
    e = c.entry("policy.allow_public_hub")
    assert e is not None
    assert e.value is False and e.locked and e.source == "system"
    assert e.reason == "Data governance: internal mirror only"
    assert len(e.shadowed) == 3 and all(s.why == "locked" for s in e.shadowed)
    # a locked key the system file does not set keeps its default
    p = c.entry("network.https_proxy")
    assert p is not None and p.locked and p.reason is None and p.value == ""
    text = c.explain("policy.allow_public_hub")
    assert text is not None
    assert "locked by the system file" in text and "Data governance" in text
    assert "ignored: true from env (FRONTIER_POLICY__ALLOW_PUBLIC_HUB)" in text
    assert "locked by the system file" in text
    # a lock is not reported as a problem: the shadowed values say what happened
    assert c.problems == []
    assert [s.source for s in c.ignored("policy.allow_public_hub")] == ["user", "env", "cli"]
    assert "set by: system file" in text and "default: true" in text
    assert c.explain("nope.key") is None


def test_nested_lock_tables_and_locks_outside_the_system_file(layers):
    write(layers["system_file"], '[lock.policy]\nmax_cost_per_run = "Finance"\n"nope" = true\n')
    write(user_file(layers), '[lock]\n"ui.theme" = true\n')
    c = config.load(**layers)
    cost, theme = c.entry("policy.max_cost_per_run"), c.entry("ui.theme")
    assert cost is not None and cost.locked and cost.reason == "Finance"
    assert theme is not None and not theme.locked
    messages = [p.message for p in c.problems]
    assert any("only honoured in the system file" in m for m in messages)
    assert any("locks no known setting" in m for m in messages)


def test_problems_are_reported_and_bad_values_skipped(layers):
    write(
        user_file(layers),
        '[ui]\ntheme = "pink"\n[storage]\ndataset_dir = "/x"\n[hub]\nmax_bytes = "1GB"\n'
        "top = 1\n[worker]\nheartbeat_secs = 2.5\n",
    )
    env = {"FRONTIER_WORKER__HEARTBEAT_SECS": "soon", "FRONTIER_NOPE__KEY": "1"}
    c = config.load(**layers, env=env)
    assert c.str("ui.theme") == "system"
    assert c.int("hub.max_bytes") == 1_000_000_000
    assert c.int("worker.heartbeat_secs") == 10
    text = [str(p) for p in c.problems]
    assert any("ui.theme" in t and "one of: system, light, dark" in t for t in text), text
    assert any(
        "storage.dataset_dir" in t and "did you mean storage.datasets_dir" in t for t in text
    ), text
    assert any("FRONTIER_WORKER__HEARTBEAT_SECS" in t and "an integer" in t for t in text), text
    assert any("FRONTIER_NOPE__KEY" in t for t in text), text
    assert any("worker.heartbeat_secs" in t and "got a number" in t for t in text), text
    assert all(
        p.severity in ("warning", "error") and p.source in config.SOURCES for p in c.problems
    )
    assert any(p.message.endswith("; the value is ignored") for p in c.problems)

    write(user_file(layers), "[ui\ntheme = 1")
    c = config.load(**layers)
    assert any("not valid TOML" in p.message and p.key is None for p in c.problems)
    write(user_file(layers), 'ui = "dark"\n')
    assert any("settings live in sections" in p.message for p in config.load(**layers).problems)


def test_typed_getters_and_network_env(layers):
    write(
        layers["system_file"],
        '[network]\nhttps_proxy = "http://proxy.example.com:3128"\n'
        'no_proxy = ["localhost", ".example.com"]\nca_bundle = "/etc/ssl/example.pem"\n'
        'offline = true\n[hub]\nhuggingface_endpoint = "https://hf.example.com/"\n',
    )
    c = config.load(**layers)
    env = c.network_env()
    assert env["HTTPS_PROXY"] == env["https_proxy"] == "http://proxy.example.com:3128"
    assert env["NO_PROXY"] == "localhost,.example.com"
    assert env["REQUESTS_CA_BUNDLE"] == env["SSL_CERT_FILE"] == "/etc/ssl/example.pem"
    assert env["HF_HUB_OFFLINE"] == env["FRONTIER_OFFLINE"] == "1"
    assert env["HF_ENDPOINT"] == "https://hf.example.com"
    assert "HTTP_PROXY" not in env
    datasets = c.path("storage.datasets_dir")
    assert datasets is not None and datasets.is_absolute()
    assert c.opt_str("client.server_url") is None and c.path("hub.catalog_path") is None
    assert c.list("policy.allowed_dataset_licences") == ["any"]
    assert c.float("policy.max_cost_per_run") == 0.0 and c.bool("network.offline") is True
    assert c.is_set("network.offline") and not c.is_set("ui.theme")
    with pytest.raises(KeyError, match="not a registered setting"):
        c.get("no.such_key")


# -- values ---------------------------------------------------------------------------------


def test_bytes_parse_with_units():
    assert config.parse_bytes("1024") == 1024
    assert config.parse_bytes("2GiB") == 2 * 1024**3
    assert config.parse_bytes("1.5 MB") == 1_500_000
    assert config.parse_bytes("1.5MiB") == 1_572_864
    assert config.parse_bytes("1_000k") == 1_000_000
    assert config.parse_bytes("lots") is None
    assert config.parse_bytes("5 parsecs") is None


def setting(key: str) -> dict:
    d = config.find(key)
    assert d is not None
    return d


def test_text_coercion_per_type():
    targets = setting("policy.allow_cloud_targets")
    assert config.from_text(targets, "local, slurm") == ["local", "slurm"]
    assert config.from_text(targets, '["local"]') == ["local"]
    with pytest.raises(ValueError, match='"moon" is not allowed'):
        config.from_text(targets, "local,moon")
    hub = setting("policy.allow_public_hub")
    assert config.from_text(hub, "no") is False and config.from_text(hub, "ON") is True
    with pytest.raises(ValueError, match="true or false"):
        config.from_text(hub, "maybe")
    assert config.from_text(setting("hub.max_bytes"), "1GB") == 1_000_000_000
    assert config.from_text(setting("policy.max_cost_per_run"), "2") == 2.0


def test_validation_messages_name_the_expectation():
    url = setting("client.server_url")
    with pytest.raises(ValueError, match="http://"):
        config.coerce(url, "frontier.example.com")
    assert config.coerce(url, "https://x/") == "https://x"
    with pytest.raises(ValueError, match="-1 is below the minimum 0"):
        config.coerce(setting("policy.max_cost_per_run"), -1.0)
    with pytest.raises(ValueError, match="99999 is above the maximum 3600"):
        config.coerce(setting("client.request_timeout_secs"), 99999)
    theme = setting("ui.theme")
    with pytest.raises(ValueError, match="one of: system, light, dark"):
        config.coerce(theme, "pink")
    with pytest.raises(ValueError, match="got a number"):
        config.coerce(theme, 3)
    with pytest.raises(ValueError, match="got a boolean"):
        config.coerce(setting("ui.refresh_ms"), True)
    with pytest.raises(ValueError, match="a list of strings"):
        config.coerce(setting("worker.labels"), ["gpu", 3])
    assert config.expand_path("~/x") == Path.home() / "x"
    assert config.expand_path("rel/x") == Path("rel/x")


# -- developer .env -------------------------------------------------------------------------


def test_dotenv_parsing():
    got = config.parse_dotenv(
        "# c\nA=1\nexport B=\"two words\"\nC='x' \nD=v # trailing\nbad line\n=x\n"
    )
    assert got == [("A", "1"), ("B", "two words"), ("C", "x"), ("D", "v")]


def test_dotenv_is_developer_only(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=from-dotenv\nKEEP=dotenv\n")
    sub = tmp_path / "a"
    sub.mkdir()
    # not a checkout, no FRONTIER_DEV: ignored
    assert "TOKEN" not in config.with_dotenv({}, sub)
    # FRONTIER_DEV=1: loaded, without overriding the real environment
    env = config.with_dotenv({"FRONTIER_DEV": "1", "KEEP": "real"}, sub)
    assert (env["TOKEN"], env["KEEP"]) == ("from-dotenv", "real")
    # a source checkout alone loads nothing (CFG-02: a cloned repository can look like one);
    # with FRONTIER_DEV=1 the checkout root's file is the one that applies
    (tmp_path / "Cargo.toml").write_text("[workspace]\n")
    (tmp_path / "crates" / "frontier-config").mkdir(parents=True)
    (tmp_path / "packages" / "frontier").mkdir(parents=True)
    (sub / ".env").write_text("TOKEN=nearer\n")
    assert config.source_checkout(sub) == tmp_path
    assert "TOKEN" not in config.with_dotenv({}, sub)
    assert config.dotenv_path(sub, {}) is None
    assert "TOKEN" not in config.with_dotenv({"FRONTIER_DEV": "0"}, sub)
    assert config.with_dotenv({"FRONTIER_DEV": "1"}, sub)["TOKEN"] == "from-dotenv"
    # FRONTIER_DEV inside the .env does not switch developer mode on
    (tmp_path / ".env").write_text("FRONTIER_DEV=1\nTOKEN=from-dotenv\n")
    assert "TOKEN" not in config.with_dotenv({}, sub)


def test_process_env_and_cached_config_follow_the_process(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    (work / ".env").write_text("FRONTIER_UI__THEME=dark\nFROM_DOTENV=1\n")
    monkeypatch.chdir(work)
    monkeypatch.setenv("FRONTIER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("FRONTIER_SYSTEM_CONFIG", str(tmp_path / "system.toml"))
    assert "FROM_DOTENV" not in config.process_env()
    first = config.get_config()
    assert first.str("ui.theme") == "system" and config.get_config() is first
    assert first.paths.home == tmp_path / "home"
    if not Path(config.SYSTEM_FILE_UNIX).is_file():
        assert first.paths.system == tmp_path / "system.toml"
    # the environment changed: the cached configuration is reloaded
    monkeypatch.setenv("FRONTIER_DEV", "1")
    assert config.process_env()["FROM_DOTENV"] == "1"
    assert config.get_config().str("ui.theme") == "dark"
    monkeypatch.setenv("FRONTIER_UI__THEME", "light")
    assert config.get_config().str("ui.theme") == "light"
    # so is a file that appears or changes
    monkeypatch.delenv("FRONTIER_UI__THEME")
    monkeypatch.setenv("FRONTIER_DEV", "0")
    write(work / config.PROJECT_FILE, '[ui]\ntheme = "light"\nunits = "imperial"\n')
    c = config.get_config()
    assert (c.str("ui.theme"), c.str("ui.units")) == ("light", "imperial")
    assert c.paths.project == work / config.PROJECT_FILE
    assert config.find_project_file(tmp_path) is None


# -- policy ---------------------------------------------------------------------------------


def policy(tmp_path: Path, system: str) -> config.Policy:
    path = write(tmp_path / "system.toml", system)
    return config.policy(config.load(system_file=path, home=tmp_path / "home"))


def test_policy_defaults_allow_everything(tmp_path):
    p = policy(tmp_path, "")
    for t in setting("policy.allow_cloud_targets")["enum"]:
        p.check_target(t)
    p.check_hub_pull(id="x", spdx="CC-BY-NC-4.0", commercial_use=False, public=True)
    p.check_cost(0.0)
    p.check_cost(1e6)
    # plugins: the official index and what an administrator configured, not `any`: an
    # arbitrary URL or path is code from anywhere and needs listing (SRV-04, SUP-02)
    for source in ("bundled", "pypi", "index", "wheel_dir"):
        p.check_plugin_source(source)
    with pytest.raises(config.PolicyViolation):
        p.check_plugin_source("https://x/y.whl")
    assert p.summary()["plugin_sources"] == ["bundled", "pypi", "index", "wheel_dir"]


def test_policy_targets(tmp_path):
    p = policy(
        tmp_path,
        '[policy]\nallow_cloud_targets = ["local", "slurm"]\n'
        '[lock]\n"policy.allow_cloud_targets" = "ITAR programme"\n',
    )
    p.check_target("slurm")
    with pytest.raises(PolicyViolation) as exc:
        p.check_target("runpod")
    v = exc.value
    assert v.policy == config.ALLOW_CLOUD_TARGETS and v.locked and v.reason == "ITAR programme"
    text = str(v)
    assert "target `runpod` is not allowed here; allowed targets: local, slurm" in text
    assert "set by your administrator" in text and "ITAR programme" in text
    assert text.endswith(f"(policy policy.allow_cloud_targets, {v.origin})")
    doc = v.to_json()
    assert set(doc) == {"policy", "message", "origin", "locked", "reason"}
    assert json.loads(json.dumps(doc)) == doc


def test_policy_hub_and_licences(tmp_path):
    p = policy(tmp_path, "[policy]\nallow_public_hub = false\n")
    public = {"id": "ahmedml", "spdx": "CC-BY-SA-4.0", "commercial_use": True}
    with pytest.raises(PolicyViolation) as exc:
        p.check_hub_pull(**public, public=True)
    assert exc.value.policy == config.ALLOW_PUBLIC_HUB and not exc.value.locked
    assert "downloading `ahmedml` from a public host is not allowed here" in exc.value.message
    p.check_hub_pull(**public, public=False)

    p = policy(tmp_path, '[policy]\nallowed_dataset_licences = ["commercial", "CC-BY-NC-4.0"]\n')
    p.check_hub_pull(**public, public=True)
    p.check_hub_pull(id="nc", spdx="cc-by-nc-4.0", commercial_use=False, public=True)
    with pytest.raises(PolicyViolation) as exc:
        p.check_hub_pull(id="drivaernet", spdx="CC-BY-NC-SA-4.0", commercial_use=False)
    assert exc.value.policy == config.ALLOWED_DATASET_LICENCES
    assert "CC-BY-NC-SA-4.0 (no commercial use)" in exc.value.message
    assert "(commercial, CC-BY-NC-4.0)" in exc.value.message
    with pytest.raises(PolicyViolation, match="licensed under unknown terms"):
        p.check_hub_pull(id="mystery")


def test_policy_cost_ceiling(tmp_path):
    p = policy(tmp_path, "[policy]\nmax_cost_per_run = 5.0\n")
    p.check_cost(5.0)
    p.check_cost(0.5)
    with pytest.raises(PolicyViolation, match=r"exceeds the allowed \$5.00"):
        p.check_cost(5.01)
    with pytest.raises(PolicyViolation, match="without a cost ceiling"):
        p.check_cost(0.0)


def test_policy_plugin_sources(tmp_path):
    p = policy(
        tmp_path,
        '[policy]\nplugin_sources = ["bundled", "wheel_dir", "https://pkgs.example.com/"]\n',
    )
    p.check_plugin_source("bundled")
    p.check_plugin_source("wheel_dir")
    p.check_plugin_source("https://pkgs.example.com/simple/x.whl")
    with pytest.raises(PolicyViolation, match="from `pypi` is not allowed"):
        p.check_plugin_source("pypi")
    with pytest.raises(PolicyViolation, match="allowed sources: bundled, wheel_dir"):
        p.check_plugin_source("/tmp/evil.whl")
    with pytest.raises(PolicyViolation):
        p.check_plugin_source("index")


# -- the committed exports --------------------------------------------------------------------


def test_schema_is_consistent_with_the_python_validator():
    doc = config.schema()
    assert doc["version"] == 1
    sections = {s["id"] for s in doc["sections"]}
    keys = [d["key"] for d in doc["settings"]]
    assert len(keys) == len(set(keys)) > 40
    defaults = config.load()
    assert defaults.problems == []
    for d in doc["settings"]:
        section, _, name = d["key"].partition(".")
        assert section in sections and name and name.count(".") <= 1, d["key"]  # one nested level
        assert d["type"] in (
            "string",
            "path",
            "url",
            "int",
            "float",
            "bool",
            "list",
            "bytes",
            "table",  # a nested table level, e.g. `policy.ai`
        )
        assert d["scope"] in ("user", "project", "system", "server")
        assert d["editable_by"] in ("user", "admin") and d["secret"] is False
        env_name = f"FRONTIER_{section.upper()}__{name.upper().replace('.', '_')}"
        assert d["env"][0] == env_name, d["key"]
        # the default passes the validator unchanged, and so does its text form
        assert config.coerce(d, d["default"]) == d["default"], d["key"]
        assert defaults.get(d["key"]) == d["default"]
        if d["type"] not in ("list", "table"):  # a table has no text form; its keys do
            text = str(d["default"]).lower() if d["type"] == "bool" else str(d["default"])
            assert config.from_text(d, text) == d["default"], d["key"]
    env_names = [e for d in doc["settings"] for e in d["env"]]
    assert len(env_names) == len(set(env_names)), "an environment name sets two settings"


def test_auth_providers_export_parses():
    text = resources.files("frontier").joinpath("auth_providers.json").read_text("utf-8")
    providers = json.loads(text)
    ids = [p["id"] for p in providers]
    assert len(ids) == len(set(ids))
    assert {"frontier", "huggingface", "runpod", "flow360", "luminary", "simscale", "rescale"} <= {
        *ids
    }
    for p in providers:
        assert p["title"] and p["kind"] and p["fields"], p["id"]
        setting_key = (p.get("test_http") or {}).get("url_setting")
        assert setting_key is None or config.find(setting_key) is not None


def test_config_and_auth_import_without_heavy_dependencies():
    code = (
        "import sys\n"
        "import frontier, frontier.config, frontier.auth\n"
        "heavy = [m for m in ('numpy', 'pydantic', 'httpx') if m in sys.modules]\n"
        "assert not heavy, heavy\n"
        "from frontier import Run, init, ServerClient\n"
        "assert 'pydantic' in sys.modules and frontier.__version__\n"
        "assert 'Run' in dir(frontier)\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_one_nested_table_level_flattens_to_dotted_keys(layers):
    write(user_file(layers), '[policy.ai]\nlocal_model = "qwen3:8b"\ndata_leaves_site = false\n')
    c = config.load(**layers)
    e = c.entry("policy.ai.local_model")
    assert e is not None and e.value == "qwen3:8b" and e.source == "user"
    leaves = c.entry("policy.ai.data_leaves_site")
    assert leaves is not None and leaves.value is False
    # the nested level works in the system file too, where the admin key may be set
    write(layers["system_file"], "[policy.ai]\ndata_leaves_site = true\n")
    leaves = config.load(**layers).entry("policy.ai.data_leaves_site")
    # ... and the user file may tighten it back
    assert leaves is not None and leaves.value is False and leaves.source == "user"
