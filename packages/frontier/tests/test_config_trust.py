# SPDX-License-Identifier: Apache-2.0
"""Trust layers of `frontier.config` (security review CFG-01 and CFG-02): which layer may
set which key, what counts as tightening, the server policy file and the developer `.env`."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from frontier import config

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")


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


def setting(key: str) -> dict:
    d = config.find(key)
    assert d is not None
    return d


def refused(c: config.Config, key: str) -> list[tuple[str, str]]:
    return [(s.source, s.why) for s in c.ignored(key)]


# -- classification -------------------------------------------------------------------------


def test_restriction_is_decided_from_the_registry():
    # organisation policy: only the system file and the server
    for key in (
        "policy.allow_cloud_targets",
        "policy.allow_public_hub",
        "policy.max_cost_per_run",
        "policy.plugin_sources",
        "policy.ai.allowed_providers",
        "policy.ai.data_leaves_site",
        "policy.ai.autonomous_op_classes",
        "compute.pools",
        "server.inject_credentials",
    ):
        assert config.restriction(key) == "admin", key
    # code execution and the network: never a project file or a .env
    for key in (
        "compute.python",
        "client.server_url",
        "hub.extra_catalogs",
        "plugins.index_url",
        "policy.ai.local_endpoint",
        "network.offline",
        "network.https_proxy",
        "network.ca_bundle",
        "hub.catalog_path",
        "hub.huggingface_endpoint",
        "compute.image",
        "server.bind",
        "secrets.key_file",
    ):
        assert config.restriction(key) == "trusted", key
    for key in ("ui.theme", "storage.runs_dir", "policy.ai.local_model", "compute.default_gpu"):
        assert config.restriction(key) is None, key
    assert config.restriction("no.such_key") is None
    # every registered key the registry marks server/system scope or admin-edited is
    # restricted one way or the other, and every policy.* admin key is admin-only
    for d in config.schema()["settings"]:
        admin = d["scope"] in ("server", "system") or d["editable_by"] == "admin"
        kind = config.restriction(d["key"])
        if admin:
            assert kind is not None, d["key"]
        if admin and d["key"].startswith("policy.") and d["key"] not in config.EXEC_NETWORK_KEYS:
            assert kind == "admin", d["key"]
    assert config.may_set("policy.allow_public_hub", "system")
    assert config.may_set("policy.allow_public_hub", "server")
    assert not config.may_set("policy.allow_public_hub", "user")
    assert not config.may_set("policy.allow_public_hub", "env")
    assert config.may_set("compute.python", "user") and config.may_set("compute.python", "env")
    assert not config.may_set("compute.python", "project")
    assert not config.may_set("compute.python", "dotenv")
    assert config.may_set("ui.theme", "project")


@pytest.mark.parametrize(
    ("key", "current", "proposed", "expected"),
    [
        ("network.offline", False, True, True),
        ("network.offline", True, False, False),
        ("policy.ai.data_leaves_site", True, False, True),
        ("policy.ai.data_leaves_site", False, True, False),
        ("policy.allow_public_hub", True, False, True),
        ("policy.allow_public_hub", False, True, False),
        ("policy.allow_plugin_changes", True, False, True),
        ("policy.allow_plugin_changes", False, True, False),
        ("policy.allow_cloud_targets", ["local", "slurm", "runpod"], ["local"], True),
        ("policy.allow_cloud_targets", ["local", "slurm"], [], True),
        ("policy.allow_cloud_targets", ["local"], ["local", "runpod"], False),
        ("policy.allowed_dataset_licences", ["any"], ["commercial"], True),
        ("policy.allowed_dataset_licences", ["commercial"], ["any"], False),
        ("policy.allowed_dataset_licences", ["CC-BY-4.0", "MIT"], ["mit"], True),
        # "commercial" is a class of licences: whether MIT is inside it is not known here
        ("policy.allowed_dataset_licences", ["commercial"], ["MIT"], False),
        ("policy.plugin_sources", ["any"], ["bundled"], True),
        ("policy.plugin_sources", ["bundled"], ["bundled", "pypi"], False),
        ("policy.plugin_sources", ["bundled"], ["*"], False),
        ("policy.ai.allowed_providers", ["local", "anthropic"], ["local"], True),
        ("policy.ai.allowed_providers", ["local"], ["local", "anthropic"], False),
        ("policy.ai.allowed_providers", ["local"], ["any"], False),
        ("policy.ai.autonomous_op_classes", ["all"], ["prep.fields"], True),
        ("policy.ai.autonomous_op_classes", [], ["prep.fields"], False),
        ("policy.ai.autonomous_op_classes", ["prep.fields"], ["all"], False),
        ("policy.max_cost_per_run", 0.0, 5.0, True),  # 0 = no ceiling
        ("policy.max_cost_per_run", 10.0, 5.0, True),
        ("policy.max_cost_per_run", 5.0, 10.0, False),
        ("policy.max_cost_per_run", 5.0, 0.0, False),
        ("policy.compute_max_gpus_per_run", 8, 4, True),
        ("policy.compute_max_gpus_per_run", 4, 8, False),
        ("policy.compute_max_gpus_per_run", 4, 0, False),
        # no known strict direction: loosening
        ("client.server_url", "", "https://evil.example", False),
        ("compute.python", "/usr/bin/python3", "./tools/py", False),
        ("compute.local_executor", True, False, False),
        ("network.https_proxy", "", "http://proxy:1", False),
        # wrong types never tighten
        ("network.offline", False, "true", False),
        ("policy.allow_cloud_targets", ["local"], "local", False),
    ],
)
def test_tightens(key, current, proposed, expected):
    assert config.tightens(setting(key), current, proposed) is expected


# -- CFG-01: policy only from the system file and the server --------------------------------


def test_cfg01_project_file_and_environment_cannot_loosen_a_locked_policy(layers):
    """The review's test: the system file sets data_leaves_site = false and locks
    policy.ai.*; a project frontier.toml, or the environment alone, must not change it."""
    write(
        layers["system_file"],
        '[policy.ai]\ndata_leaves_site = false\nallowed_providers = ["local"]\n'
        '[lock]\n"policy.*" = "Data governance"\n',
    )
    loosen_file = (
        '[policy.ai]\ndata_leaves_site = true\nallowed_providers = ["any"]\n'
        'autonomous_op_classes = ["all"]\n'
    )
    loosen_env = {
        "FRONTIER_POLICY__AI_DATA_LEAVES_SITE": "true",
        "FRONTIER_POLICY__AI_ALLOWED_PROVIDERS": "any",
        "FRONTIER_POLICY__AI_AUTONOMOUS_OP_CLASSES": "all",
    }
    write(layers["project_file"], loosen_file)
    for c in (
        config.load(**layers),
        config.load(**{**layers, "project_file": None}, env=loosen_env),
    ):
        assert c.bool("policy.ai.data_leaves_site") is False
        assert c.list("policy.ai.allowed_providers") == ["local"]
        assert c.list("policy.ai.autonomous_op_classes") == []
        for key in ("policy.ai.data_leaves_site", "policy.ai.allowed_providers"):
            e = c.entry(key)
            assert e is not None and e.locked and e.source == "system"
            assert c.trusted_source(key) == "system"
            assert [why for _, why in refused(c, key)] == ["locked"]


@pytest.mark.parametrize("locked", [False, True])
def test_cfg01_policy_keys_are_refused_from_every_untrusted_layer(layers, locked):
    """Without a lock the result is the same: an admin key is not a lower layer's to set."""
    system = "[policy.ai]\ndata_leaves_site = false\n[policy]\nmax_cost_per_run = 5.0\n"
    if locked:
        system += '[lock]\n"policy.*" = true\n'
    write(layers["system_file"], system)
    write(
        user_file(layers),
        "[policy.ai]\ndata_leaves_site = true\n[policy]\nmax_cost_per_run = 50.0\n",
    )
    write(
        layers["project_file"],
        '[policy.ai]\ndata_leaves_site = true\nallowed_providers = ["any"]\n',
    )
    c = config.load(
        **layers,
        env={
            "FRONTIER_POLICY__AI_DATA_LEAVES_SITE": "1",
            "FRONTIER_POLICY__ALLOW_CLOUD_TARGETS": "local,runpod,anyscale,ssh,slurm,k8s",
            "FRONTIER_POLICY__MAX_COST_PER_RUN": "0",
        },
        overrides={"policy.ai.data_leaves_site": True},
    )
    assert c.bool("policy.ai.data_leaves_site") is False
    assert c.float("policy.max_cost_per_run") == 5.0
    assert c.list("policy.ai.allowed_providers") == ["local"]
    assert c.trusted_source("policy.ai.data_leaves_site") == "system"
    assert [s for s, _ in refused(c, "policy.ai.data_leaves_site")] == [
        "user",
        "project",
        "env",
        "cli",
    ]
    if locked:
        assert all(why == "locked" for _, why in refused(c, "policy.ai.data_leaves_site"))
        return
    assert all(why == config.RESTRICTED_WHY for _, why in refused(c, "policy.ai.data_leaves_site"))
    assert config.RESTRICTED_WHY == "restricted: only the system file or the server may set this"
    # every refusal is a warning naming the layer and the key ...
    warned = {(p.source, p.key) for p in c.problems if p.severity == "warning"}
    assert {
        ("user", "policy.ai.data_leaves_site"),
        ("project", "policy.ai.data_leaves_site"),
        ("env", "policy.ai.data_leaves_site"),
        ("cli", "policy.ai.data_leaves_site"),
        ("user", "policy.max_cost_per_run"),
        ("env", "policy.max_cost_per_run"),
        ("project", "policy.ai.allowed_providers"),
    } <= warned
    assert all(
        "restricted" in p.message and p.message.endswith("the value is ignored") for p in c.problems
    )
    # ... and `explain` says why the value had no effect
    text = c.explain("policy.ai.data_leaves_site")
    assert text is not None
    assert "restricted: only the system file or the server may set this" in text
    assert (
        "ignored: true from env (FRONTIER_POLICY__AI_DATA_LEAVES_SITE): "
        "restricted: only the system file or the server may set this"
    ) in text
    assert f"ignored: true from project ({layers['project_file']})" in text
    assert "set by: system file" in text
    # the same value as the effective one is not a problem
    assert not any(p.key == "policy.allow_cloud_targets" for p in c.problems)


def test_policy_from_environment_alone_does_not_apply(layers):
    c = config.load(**layers, env={"FRONTIER_POLICY__AI_DATA_LEAVES_SITE": "true"})
    e = c.entry("policy.ai.data_leaves_site")
    assert e is not None and e.value is False and e.source == "default"
    assert refused(c, "policy.ai.data_leaves_site") == [("env", config.RESTRICTED_WHY)]
    # user-scope keys of the same section are still the user's
    c = config.load(**layers, env={"FRONTIER_POLICY__AI_LOCAL_MODEL": "qwen3:8b"})
    assert c.str("policy.ai.local_model") == "qwen3:8b" and c.problems == []


def test_any_layer_may_tighten(layers):
    write(
        layers["system_file"],
        '[policy]\nallow_cloud_targets = ["local", "slurm", "runpod"]\nmax_cost_per_run = 20.0\n'
        "[policy.ai]\ndata_leaves_site = true\n",
    )
    write(user_file(layers), "[policy]\nallow_public_hub = false\n")
    write(
        layers["project_file"],
        '[policy]\nallow_cloud_targets = ["local", "slurm"]\n[network]\noffline = true\n',
    )
    c = config.load(
        **layers,
        env={
            "FRONTIER_POLICY__AI_DATA_LEAVES_SITE": "false",
            "FRONTIER_POLICY__MAX_COST_PER_RUN": "5",
        },
        overrides={"policy.allow_cloud_targets": ["local"]},
    )
    assert c.problems == []
    assert c.bool("policy.allow_public_hub") is False
    assert c.trusted_source("policy.allow_public_hub") == "user"
    assert c.list("policy.allow_cloud_targets") == ["local"]
    assert c.bool("policy.ai.data_leaves_site") is False
    assert c.float("policy.max_cost_per_run") == 5.0
    assert c.bool("network.offline") is True and c.trusted_source("network.offline") == "project"
    # once tightened, a later layer cannot loosen it again
    c = config.load(**layers, env={"FRONTIER_POLICY__ALLOW_CLOUD_TARGETS": "local,slurm,runpod"})
    assert c.list("policy.allow_cloud_targets") == ["local", "slurm"]
    assert refused(c, "policy.allow_cloud_targets") == [("env", config.RESTRICTED_WHY)]


def test_offline_exported_by_the_command_line_keeps_working(layers):
    """The Rust loader exports FRONTIER_OFFLINE=1 to child processes."""
    c = config.load(**layers, env={"FRONTIER_OFFLINE": "1"})
    assert c.bool("network.offline") is True and c.problems == []
    assert c.network_env()["FRONTIER_OFFLINE"] == "1"
    # a project cannot switch the user's offline mode off
    write(user_file(layers), "[network]\noffline = true\n")
    write(layers["project_file"], "[network]\noffline = false\n")
    c = config.load(**layers)
    assert c.bool("network.offline") is True
    assert refused(c, "network.offline") == [("project", config.UNTRUSTED_WHY)]


def test_offline_children_do_not_reach_a_package_index(layers):
    env = config.load(**layers, env={"FRONTIER_OFFLINE": "1"}).network_env()
    assert env["PIP_NO_INDEX"] == env["UV_OFFLINE"] == env["HF_HUB_OFFLINE"] == "1"
    online = config.load(**layers).network_env()
    assert "PIP_NO_INDEX" not in online and "UV_OFFLINE" not in online


# -- CFG-02: a cloned repository configures nothing that executes or connects ----------------

CFG02_PROJECT = """
[compute]
python = "./tools/py"
image = "evil.example/trainer:latest"
[client]
server_url = "https://evil.example"
[hub]
extra_catalogs = ["./catalog"]
catalog_path = "./catalog.json"
huggingface_endpoint = "https://hf.evil.example"
[plugins]
index_url = "https://pkgs.evil.example/simple"
wheel_dir = "./wheels"
[network]
https_proxy = "http://mitm.evil.example:8080"
http_proxy = "http://mitm.evil.example:8080"
no_proxy = ["*"]
ca_bundle = "./ca.pem"
[policy.ai]
local_endpoint = "https://llm.evil.example"
"""
CFG02_KEYS = (
    "compute.python",
    "compute.image",
    "client.server_url",
    "hub.extra_catalogs",
    "hub.catalog_path",
    "hub.huggingface_endpoint",
    "plugins.index_url",
    "plugins.wheel_dir",
    "network.https_proxy",
    "network.http_proxy",
    "network.no_proxy",
    "network.ca_bundle",
    "policy.ai.local_endpoint",
)
CFG02_DOTENV = {
    "FRONTIER_COMPUTE__PYTHON": "./tools/py",
    "FRONTIER_PYTHON": "./tools/py2",
    "FRONTIER_SERVER": "https://evil.example",
    "FRONTIER_HUB_CATALOGS": "./catalog",
    "FRONTIER_PLUGIN_INDEX": "https://pkgs.evil.example/simple",
    "HTTPS_PROXY": "http://mitm.evil.example:8080",
    "SSL_CERT_FILE": "./ca.pem",
    "HF_ENDPOINT": "https://hf.evil.example",
    "FRONTIER_POLICY__AI_LOCAL_ENDPOINT": "https://llm.evil.example",
    "FRONTIER_POLICY__AI_DATA_LEAVES_SITE": "true",
}


def test_cfg02_project_file_cannot_configure_execution_or_the_network(layers):
    write(
        layers["project_file"],
        CFG02_PROJECT + '[ui]\ntheme = "dark"\n[storage]\nruns_dir = "out"\n',
    )
    c = config.load(**layers)
    for key in CFG02_KEYS:
        e = c.entry(key)
        assert e is not None and e.source == "default", key
        assert e.value == setting(key)["default"], key
        assert refused(c, key) == [("project", config.UNTRUSTED_WHY)], key
        problem = [p for p in c.problems if p.key == key]
        assert len(problem) == 1 and problem[0].severity == "warning", key
        assert problem[0].source == "project" and "restricted" in problem[0].message
        text = c.explain(key)
        assert text is not None and "a project file or .env may not set this" in text
    assert len(c.problems) == len(CFG02_KEYS)
    # what a project is for still works
    assert c.str("ui.theme") == "dark" and c.str("storage.runs_dir") == "out"
    assert c.network_env() == {}


def test_cfg02_the_same_keys_stay_settable_by_the_user(layers):
    """The user's own config file and real environment have the user's trust."""
    write(user_file(layers), CFG02_PROJECT)
    c = config.load(**layers)
    assert c.problems == []
    assert c.str("compute.python") == "./tools/py"
    assert c.str("client.server_url") == "https://evil.example"
    assert c.trusted_source("network.https_proxy") == "user"
    c = config.load(
        **layers,
        env={"FRONTIER_SERVER": "https://frontier.example.com", "FRONTIER_PYTHON": "/opt/py"},
        overrides={"compute.python": "/opt/py2"},
    )
    assert c.str("client.server_url") == "https://frontier.example.com"
    assert c.get("compute.python") == "/opt/py2" and c.problems == []


def test_cfg02_dotenv_layer_cannot_set_restricted_keys(layers):
    c = config.load(**layers, dotenv=CFG02_DOTENV, dotenv_file="/repo/.env")
    for key in (
        "compute.python",
        "client.server_url",
        "hub.extra_catalogs",
        "plugins.index_url",
        "network.https_proxy",
        "network.ca_bundle",
        "hub.huggingface_endpoint",
        "policy.ai.local_endpoint",
        "policy.ai.data_leaves_site",
    ):
        e = c.entry(key)
        assert e is not None and e.source == "default", key
        assert c.ignored(key) and all(s.source == "dotenv" for s in c.ignored(key)), key
        assert any(p.key == key and p.source == "dotenv" for p in c.problems), key
    origin = c.ignored("client.server_url")[0].origin
    assert origin == "FRONTIER_SERVER in /repo/.env"
    text = c.explain("client.server_url")
    assert text is not None and "from dotenv (FRONTIER_SERVER in /repo/.env)" in text
    # a .env may still switch offline mode on
    c = config.load(**layers, dotenv={"FRONTIER_OFFLINE": "1"}, dotenv_file="/repo/.env")
    assert c.bool("network.offline") is True and c.trusted_source("network.offline") == "dotenv"


def test_cfg02_read_dotenv_holds_restricted_names_back(tmp_path):
    lines = [f"{k}={v}" for k, v in CFG02_DOTENV.items()]
    lines += [
        "FRONTIER_UI__THEME=dark",
        "RUNPOD_API_KEY=rp-test-000000",
        "FRONTIER_HOME=/tmp/evil-home",
        "FRONTIER_SYSTEM_CONFIG=/tmp/evil-system.toml",
        "FRONTIER_SERVER_CONFIG=/tmp/evil-server.toml",
    ]
    (tmp_path / ".env").write_text("\n".join(lines) + "\n")
    # without FRONTIER_DEV=1 in the real environment nothing is read at all
    assert config.read_dotenv({}, tmp_path) == config.Dotenv(None, {}, {}, ())
    real = {"FRONTIER_DEV": "1", "HF_ENDPOINT": "https://hf.example.com"}
    got = config.read_dotenv(real, tmp_path)
    assert got.path == tmp_path / ".env"
    # harmless variables are merged; a variable that is really set wins
    assert got.env["FRONTIER_UI__THEME"] == "dark" and got.env["RUNPOD_API_KEY"]
    assert got.env["HF_ENDPOINT"] == "https://hf.example.com"
    # restricted settings are held back, the variables that locate trusted layers dropped
    assert set(got.held) == set(CFG02_DOTENV) - {"HF_ENDPOINT"}
    assert not set(got.held) & set(got.env)
    assert set(got.dropped) == {
        "FRONTIER_HOME",
        "FRONTIER_SYSTEM_CONFIG",
        "FRONTIER_SERVER_CONFIG",
    }
    assert not set(got.dropped) & set(got.env)
    assert config.with_dotenv(real, tmp_path) == got.env


def test_cfg02_process_config_in_a_cloned_repository(tmp_path, monkeypatch):
    """End to end through `get_config()`: a repository with frontier.toml and .env."""
    repo = tmp_path / "repo"
    write(repo / config.PROJECT_FILE, CFG02_PROJECT)
    write(repo / ".env", "\n".join(f"{k}={v}" for k, v in CFG02_DOTENV.items()) + "\n")
    # it even looks like a source checkout
    write(repo / "Cargo.toml", "[workspace]\n")
    (repo / "crates" / "frontier-config").mkdir(parents=True)
    (repo / "packages" / "frontier").mkdir(parents=True)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("FRONTIER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("FRONTIER_SYSTEM_CONFIG", str(tmp_path / "system.toml"))
    for name in CFG02_DOTENV:
        monkeypatch.delenv(name, raising=False)
    for dev in (None, "1"):
        if dev:
            monkeypatch.setenv("FRONTIER_DEV", dev)
        else:
            monkeypatch.delenv("FRONTIER_DEV", raising=False)
        c = config.get_config()
        for key in (*CFG02_KEYS, "policy.ai.data_leaves_site"):
            e = c.entry(key)
            assert e is not None and e.source == "default", (dev, key)
        assert c.opt_str("client.server_url") is None and c.opt_str("compute.python") is None
        assert "FRONTIER_SERVER" not in c.env and "HTTPS_PROXY" not in c.env
        sources = {p.source for p in c.problems}
        assert sources == ({"project", "dotenv"} if dev else {"project"})
        assert c.paths.home == tmp_path / "home"


# -- the server layer -----------------------------------------------------------------------

SERVER_POLICY = """
[policy]
allow_cloud_targets = ["local", "slurm"]
max_cost_per_run = 25.0
[policy.ai]
data_leaves_site = true
allowed_providers = ["local", "anthropic"]
[client]
server_url = "https://frontier.example.com"
"""


def private(path: Path) -> Path:
    path.chmod(0o600)
    return path


def test_server_layer_sets_policy_between_system_and_user(layers, tmp_path):
    server = private(write(tmp_path / "job" / "policy.toml", SERVER_POLICY))
    write(layers["system_file"], "[policy]\nmax_cost_per_run = 100.0\nallow_public_hub = false\n")
    write(
        user_file(layers),
        '[policy.ai]\nallowed_providers = ["any"]\n[policy]\nmax_cost_per_run = 10.0\n',
    )
    c = config.load(**layers, server_file=server, env={"FRONTIER_POLICY__AI_DATA_LEAVES_SITE": "0"})
    assert c.paths.server == server
    assert c.list("policy.allow_cloud_targets") == ["local", "slurm"]
    assert c.trusted_source("policy.allow_cloud_targets") == "server"
    e = c.entry("policy.allow_cloud_targets")
    assert e is not None and e.origin == str(server)
    # the server overrides the system file's unlocked value; the user tightens it further
    assert c.float("policy.max_cost_per_run") == 10.0
    assert c.list("policy.ai.allowed_providers") == ["local", "anthropic"]
    assert refused(c, "policy.ai.allowed_providers") == [("user", config.RESTRICTED_WHY)]
    assert c.bool("policy.ai.data_leaves_site") is False  # tightened by the environment
    assert c.bool("policy.allow_public_hub") is False
    assert c.str("client.server_url") == "https://frontier.example.com"
    text = c.explain("policy.allow_cloud_targets")
    assert text is not None and f"set by: server policy file {server}" in text
    with pytest.raises(config.PolicyViolation, match="set by your administrator on the server"):
        config.policy(c).check_target("runpod")


def test_server_layer_does_not_beat_a_system_lock(layers, tmp_path):
    server = private(write(tmp_path / "policy.toml", SERVER_POLICY + '[lock]\n"ui.theme" = true\n'))
    write(
        layers["system_file"],
        '[policy.ai]\ndata_leaves_site = false\n[lock]\n"policy.ai.data_leaves_site" = "No"\n',
    )
    c = config.load(**layers, server_file=server)
    e = c.entry("policy.ai.data_leaves_site")
    assert e is not None and e.value is False and e.source == "system" and e.locked
    assert refused(c, "policy.ai.data_leaves_site") == [("server", "locked")]
    theme = c.entry("ui.theme")
    assert theme is not None and not theme.locked
    assert any("only honoured in the system file" in p.message for p in c.problems)


def test_server_layer_accepts_json_sections_and_flat_dotted_keys(layers, tmp_path):
    doc = {
        "policy": {"allow_public_hub": False, "ai": {"data_leaves_site": True}},
        "policy.ai.allowed_providers": ["local", "openai"],
        "policy.max_cost_per_run": 3,
    }
    server = private(write(tmp_path / "policy.json", json.dumps(doc)))
    c = config.load(**layers, server_file=server)
    assert c.problems == []
    assert c.bool("policy.allow_public_hub") is False
    assert c.bool("policy.ai.data_leaves_site") is True
    assert c.list("policy.ai.allowed_providers") == ["local", "openai"]
    assert c.float("policy.max_cost_per_run") == 3.0
    assert {
        c.trusted_source(k) for k in ("policy.allow_public_hub", "policy.max_cost_per_run")
    } == {"server"}
    bad = private(write(tmp_path / "bad.json", "[1, 2"))
    c = config.load(**layers, server_file=bad)
    assert any("not valid JSON" in p.message and p.source == "server" for p in c.problems)


@posix_only
@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666, 0o664])
def test_server_layer_is_refused_when_others_can_write_it(layers, tmp_path, mode):
    server = write(tmp_path / "policy.toml", SERVER_POLICY)
    server.chmod(mode)
    c = config.load(**layers, server_file=server)
    assert c.bool("policy.ai.data_leaves_site") is False
    assert c.trusted_source("policy.allow_cloud_targets") == "default"
    problem = [p for p in c.problems if p.source == "server"]
    assert len(problem) == 1 and problem[0].severity == "warning"
    assert "writable by group or others" in problem[0].message
    assert "the server layer is ignored" in problem[0].message
    # readable by others is fine: the policy is not a secret
    server.chmod(0o644)
    assert config.load(**layers, server_file=server).bool("policy.ai.data_leaves_site") is True


@posix_only
def test_server_layer_is_refused_when_owned_by_somebody_else(layers, tmp_path, monkeypatch):
    server = private(write(tmp_path / "policy.toml", SERVER_POLICY))
    uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: uid + 1 if uid else 12345)
    if uid == 0:
        pytest.skip("root owns the file: always accepted")
    c = config.load(**layers, server_file=server)
    assert c.bool("policy.ai.data_leaves_site") is False
    assert any("owned by another user" in p.message for p in c.problems)


def test_server_layer_problems_for_missing_and_non_regular_files(layers, tmp_path):
    c = config.load(**layers, server_file=tmp_path / "missing.toml")
    assert any(p.source == "server" and "cannot be read" in p.message for p in c.problems)
    c = config.load(**layers, server_file=tmp_path)
    assert any(p.source == "server" for p in c.problems)
    assert c.trusted_source("policy.allow_cloud_targets") == "default"


def test_server_config_variable_is_read_from_the_real_environment_only(tmp_path, monkeypatch):
    server = private(write(tmp_path / "policy.toml", SERVER_POLICY))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setenv("FRONTIER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("FRONTIER_SYSTEM_CONFIG", str(tmp_path / "system.toml"))
    monkeypatch.setenv("FRONTIER_DEV", "1")
    monkeypatch.delenv(config.SERVER_CONFIG_ENV, raising=False)
    (work / ".env").write_text(f"{config.SERVER_CONFIG_ENV}={server}\n")
    c = config.get_config()
    assert c.paths.server is None and c.bool("policy.ai.data_leaves_site") is False
    monkeypatch.setenv(config.SERVER_CONFIG_ENV, str(server))
    c = config.get_config()
    assert c.paths.server == server and c.bool("policy.ai.data_leaves_site") is True
    assert c.trusted_source("policy.ai.data_leaves_site") == "server"
    # the cached configuration follows the file
    private(write(server, "[policy.ai]\ndata_leaves_site = false\n"))
    os.utime(server, ns=(1, 1))
    assert config.get_config().bool("policy.ai.data_leaves_site") is False
