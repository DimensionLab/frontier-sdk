// SPDX-License-Identifier: Apache-2.0
//! Developer conveniences. A `.env` file is **not** product configuration: it is read only
//! when `FRONTIER_DEV=1` or when the working directory is inside a Frontier source checkout,
//! and it only fills variables the real environment does not set. Customers configure
//! Frontier through config files, the CLI and the Settings page instead.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Parse `KEY=VALUE` lines (`export` prefix, `#` comments and single or double quotes are
/// understood; no interpolation).
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let value = value.trim();
        let value = if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            &value[1..value.len() - 1]
        } else {
            value.split(" #").next().unwrap_or(value).trim()
        };
        out.push((key.to_string(), value.to_string()));
    }
    out
}

/// The root of a Frontier source checkout containing `start`, if any.
pub fn source_checkout(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| {
            d.join("Cargo.toml").is_file()
                && d.join("crates").join("frontier-config").is_dir()
                && d.join("packages").join("frontier").is_dir()
        })
        .map(Path::to_path_buf)
}

/// The `.env` file that applies in developer mode: the checkout root's, or with
/// `FRONTIER_DEV=1` the nearest one walking up from `cwd`. `None` outside developer mode.
pub fn dotenv_path(cwd: &Path, env: &BTreeMap<String, String>) -> Option<PathBuf> {
    let forced = env
        .get("FRONTIER_DEV")
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));
    if env.get("FRONTIER_DEV").is_some_and(|v| v == "0") {
        return None;
    }
    if let Some(root) = source_checkout(cwd) {
        let p = root.join(".env");
        return p.is_file().then_some(p);
    }
    if forced {
        return cwd
            .ancestors()
            .map(|d| d.join(".env"))
            .find(|p| p.is_file());
    }
    None
}

/// `env` plus the developer `.env` (which never overrides a variable that is already set).
pub fn with_dotenv(mut env: BTreeMap<String, String>, cwd: &Path) -> BTreeMap<String, String> {
    if let Some(path) = dotenv_path(cwd, &env)
        && let Ok(text) = std::fs::read_to_string(&path)
    {
        tracing::debug!(path = %path.display(), "developer mode: loaded .env");
        for (k, v) in parse_dotenv(&text) {
            env.entry(k).or_insert(v);
        }
    }
    env
}

static PROCESS_ENV: OnceLock<BTreeMap<String, String>> = OnceLock::new();
static DOTENV_VARS: OnceLock<std::collections::BTreeSet<String>> = OnceLock::new();

/// The process environment with the developer `.env` folded in, read once.
pub fn process_env() -> &'static BTreeMap<String, String> {
    PROCESS_ENV.get_or_init(|| {
        let env: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let merged = with_dotenv(env.clone(), &cwd);
        let _ = DOTENV_VARS.set(
            merged
                .keys()
                .filter(|k| !env.contains_key(*k))
                .cloned()
                .collect(),
        );
        merged
    })
}

/// Names of the variables of [`process_env`] that came from the developer `.env`, not from
/// the real environment. The loader trusts them as little as a project file.
pub fn dotenv_vars() -> &'static std::collections::BTreeSet<String> {
    process_env();
    DOTENV_VARS.get_or_init(Default::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_parsing() {
        let got = parse_dotenv(
            "# c\nA=1\nexport B=\"two words\"\nC='x' \nD=v # trailing\nbad line\n=x\n",
        );
        assert_eq!(
            got,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "x".into()),
                ("D".into(), "v".into())
            ]
        );
    }

    #[test]
    fn dotenv_is_developer_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "TOKEN=from-dotenv\nKEEP=dotenv\n").unwrap();
        let sub = dir.path().join("a");
        std::fs::create_dir_all(&sub).unwrap();
        // not a checkout, no FRONTIER_DEV: ignored
        let env = with_dotenv(BTreeMap::new(), &sub);
        assert!(!env.contains_key("TOKEN"));
        // FRONTIER_DEV=1: loaded, without overriding the real environment
        let mut base = BTreeMap::new();
        base.insert("FRONTIER_DEV".to_string(), "1".to_string());
        base.insert("KEEP".to_string(), "real".to_string());
        let env = with_dotenv(base, &sub);
        assert_eq!(env["TOKEN"], "from-dotenv");
        assert_eq!(env["KEEP"], "real");
        // a source checkout: loaded from its root, unless FRONTIER_DEV=0
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::create_dir_all(dir.path().join("crates/frontier-config")).unwrap();
        std::fs::create_dir_all(dir.path().join("packages/frontier")).unwrap();
        assert_eq!(with_dotenv(BTreeMap::new(), &sub)["TOKEN"], "from-dotenv");
        let mut off = BTreeMap::new();
        off.insert("FRONTIER_DEV".to_string(), "0".to_string());
        assert!(!with_dotenv(off, &sub).contains_key("TOKEN"));
    }
}
