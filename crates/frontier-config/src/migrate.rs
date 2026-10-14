// SPDX-License-Identifier: Apache-2.0
//! State that predates the config file. Bookkeeping files (rented instances, the run
//! registry, plugin state, site profiles) stay where they are in the Frontier home and are
//! reported by `frontier config path`; values that are really settings (plugin sources in
//! `plugins.toml`) are offered for migration into the user config.

use crate::loader::{Config, Source};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// A state file or directory in the Frontier home.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StateItem {
    pub name: &'static str,
    pub path: PathBuf,
    pub what: &'static str,
    pub exists: bool,
}

/// Bookkeeping kept next to the user config (not configuration; never edited by hand).
pub fn state_items(home: &Path) -> Vec<StateItem> {
    let item = |name: &'static str, what: &'static str| {
        let path = home.join(name);
        StateItem {
            name,
            exists: path.exists(),
            path,
            what,
        }
    };
    vec![
        item(
            "credentials.toml",
            "credentials of the file secret store (mode 0600)",
        ),
        item(
            "auth-state.json",
            "result of the last test of each credential (no secrets)",
        ),
        item(
            "auth-providers.json",
            "credential providers declared by installed plugins",
        ),
        item(
            "cloud.json",
            "instances rented with `frontier cloud up` and their cost",
        ),
        item("runs.json", "registry of runs started with `frontier run`"),
        item("runs", "per-run records: spec, logs, generated scripts"),
        item("sweeps", "sweep state"),
        item("sites", "site profiles for --on slurm / --on ssh"),
        item("plugins.toml", "enabled plugins and deployed exporters"),
        item(
            "commands.json",
            "advanced: command templates of the Python tools",
        ),
    ]
}

/// A value found in old state that should become a setting.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suggestion {
    pub key: String,
    pub value: Value,
    pub from: String,
}

/// Settings found in legacy places that the user config does not set yet.
pub fn suggestions(config: &Config) -> Vec<Suggestion> {
    let mut out = Vec::new();
    let home = &config.paths.home;
    let unset = |key: &str| {
        config
            .entry(key)
            .is_some_and(|e| matches!(e.source, Source::Default | Source::Env))
    };
    // plugins.toml: [sources] index_url / find_links
    let plugins = home.join("plugins.toml");
    if let Ok(text) = std::fs::read_to_string(&plugins)
        && let Ok(table) = text.parse::<toml::Table>()
        && let Some(sources) = table.get("sources").and_then(|s| s.as_table())
    {
        if let Some(url) = sources.get("index_url").and_then(|v| v.as_str())
            && !url.is_empty()
            && unset("plugins.index_url")
        {
            out.push(Suggestion {
                key: "plugins.index_url".into(),
                value: json!(url),
                from: format!("{} [sources] index_url", plugins.display()),
            });
        }
        let links = sources.get("find_links");
        let first = links
            .and_then(|v| v.as_str().map(str::to_string))
            .or_else(|| links?.as_array()?.first()?.as_str().map(str::to_string));
        if let Some(dir) = first
            && !dir.is_empty()
            && unset("plugins.wheel_dir")
        {
            out.push(Suggestion {
                key: "plugins.wheel_dir".into(),
                value: json!(dir),
                from: format!("{} [sources] find_links", plugins.display()),
            });
        }
    }
    // settings that only the environment (typically the developer .env) provides
    for (key, entry) in config.entries() {
        if entry.source == Source::Env && !entry.origin.contains("__") {
            out.push(Suggestion {
                key: key.clone(),
                value: entry.value.clone(),
                from: format!("environment variable {}", entry.origin),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::LoadOptions;

    #[test]
    fn plugin_sources_and_legacy_env_become_suggestions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("plugins.toml"),
            "[sources]\nindex_url = \"https://pkgs.example.com/simple\"\nfind_links = [\"/opt/wheels\"]\n",
        )
        .unwrap();
        let mut opts = LoadOptions {
            home: dir.path().to_path_buf(),
            ..Default::default()
        };
        opts.env
            .insert("FRONTIER_SERVER".into(), "http://127.0.0.1:8787".into());
        let cfg = Config::load(&opts);
        let got = suggestions(&cfg);
        let keys: Vec<&str> = got.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "plugins.index_url",
                "plugins.wheel_dir",
                "client.server_url"
            ]
        );
        assert_eq!(got[1].value, json!("/opt/wheels"));
        assert!(
            state_items(dir.path())
                .iter()
                .any(|i| i.name == "plugins.toml" && i.exists)
        );
    }
}
