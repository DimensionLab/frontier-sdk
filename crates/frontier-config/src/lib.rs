// SPDX-License-Identifier: Apache-2.0
//! Configuration and credentials for DimensionLab Frontier.
//!
//! * [`schema`]: the typed settings registry (single source of truth; JSON and Markdown
//!   exports are generated from it).
//! * [`Config`]: the layered loader (defaults < system file < server < user file < project
//!   file < environment < flags), system-file locks, `explain`.
//! * [`edit`]: comment-preserving, atomic edits of config files.
//! * [`policy`]: organisation policy checks for every enforcement point.
//! * [`credentials`]: `[[auth]]` provider declarations, local secret stores and the resolver.
//! * [`dev`]: the developer-only `.env` loader.
//!
//! The Python mirror is `frontier.config` / `frontier.auth` in `packages/frontier`; both
//! read the same files and the same exported schema.

pub mod compute;
pub mod credentials;
pub mod dev;
pub mod edit;
#[cfg(feature = "http")]
pub mod http;
pub mod hub;
pub mod loader;
pub mod local_token;
pub mod migrate;
pub mod policy;
pub mod redact;
pub mod schema;
pub mod value;
pub mod watch;

pub use loader::{Config, Entry, LoadOptions, Paths, Problem, Severity, Source};
pub use schema::{Scope, SettingDef, SettingType};

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{}: not valid TOML: {message}", path.display())]
    Parse { path: PathBuf, message: String },
    #[error("unknown setting `{key}`{}", suggestion(suggestions))]
    UnknownKey {
        key: String,
        suggestions: Vec<String>,
    },
    #[error("{key}: {message}")]
    Invalid { key: String, message: String },
    #[error("`{key}` is locked by your administrator in {}{}", system.display(), reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default())]
    Locked {
        key: String,
        reason: Option<String>,
        system: PathBuf,
    },
    #[error("{0}")]
    Store(String),
    #[error("unknown credential provider `{id}` (known: {})", known.join(", "))]
    UnknownProvider { id: String, known: Vec<String> },
    #[error("{title} is not signed in: run `frontier auth login {id}`{}{}", env_hint(env), help_url.as_deref().map(|u| format!(". Get a credential at {u}")).unwrap_or_default())]
    MissingCredential {
        id: String,
        title: String,
        env: Vec<String>,
        help_url: Option<String>,
    },
}

fn suggestion(list: &[String]) -> String {
    if list.is_empty() {
        " (see `frontier config list`)".into()
    } else {
        format!(" (did you mean {}?)", list.join(", "))
    }
}

fn env_hint(env: &[String]) -> String {
    if env.is_empty() {
        String::new()
    } else {
        format!(" (or set {} in the environment)", env.join(" / "))
    }
}

impl Error {
    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Which file a `set`/`unset` writes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileScope {
    User,
    Project,
    System,
}

impl FileScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "project" => Some(Self::Project),
            "system" => Some(Self::System),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::System => "system",
        }
    }

    /// The file of this scope. A project scope without a project file means `./frontier.toml`.
    pub fn file(self, paths: &Paths) -> PathBuf {
        match self {
            Self::User => paths.user.clone(),
            Self::System => paths.system.clone(),
            Self::Project => paths
                .project
                .clone()
                .unwrap_or_else(|| PathBuf::from(loader::PROJECT_FILE)),
        }
    }
}

/// Set `key` in the file of `scope`, refusing keys the system file locks (unless the system
/// file itself is being edited). Returns the file written and the normalised value.
pub fn set(
    config: &Config,
    scope: FileScope,
    key: &str,
    value: &serde_json::Value,
) -> Result<(PathBuf, serde_json::Value)> {
    if scope != FileScope::System
        && let Some(entry) = config.entry(key)
        && entry.locked
    {
        return Err(Error::Locked {
            key: key.to_string(),
            reason: entry.reason.clone(),
            system: config.paths.system.clone(),
        });
    }
    let path = scope.file(&config.paths);
    let value = edit::set_in_file(&path, key, value)?;
    Ok((path, value))
}

/// Remove `key` from the file of `scope`.
pub fn unset(config: &Config, scope: FileScope, key: &str) -> Result<(PathBuf, bool)> {
    let path = scope.file(&config.paths);
    let removed = edit::unset_in_file(&path, key)?;
    Ok((path, removed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn set_refuses_locked_keys_below_the_system_scope() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("system.toml");
        std::fs::write(
            &system,
            "[lock]\n\"policy.allow_public_hub\" = \"governance\"\n",
        )
        .unwrap();
        let opts = LoadOptions {
            system_file: Some(system.clone()),
            home: dir.path().join("home"),
            ..Default::default()
        };
        let cfg = Config::load(&opts);
        let err = set(
            &cfg,
            FileScope::User,
            "policy.allow_public_hub",
            &json!(false),
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("locked by your administrator") && text.contains("governance"),
            "{text}"
        );
        assert!(!cfg.paths.user.exists());
        let (path, v) = set(
            &cfg,
            FileScope::System,
            "policy.allow_public_hub",
            &json!("false"),
        )
        .unwrap();
        assert_eq!((path, v), (system.clone(), json!(false)));
        // the lock table survived the edit
        assert!(
            Config::load(&opts)
                .entry("policy.allow_public_hub")
                .unwrap()
                .locked
        );
        let (path, _) = set(&cfg, FileScope::User, "ui.theme", &json!("dark")).unwrap();
        assert_eq!(path, cfg.paths.user);
        assert_eq!(Config::load(&opts).str("ui.theme"), "dark");
        assert!(unset(&cfg, FileScope::User, "ui.theme").unwrap().1);
    }
}
