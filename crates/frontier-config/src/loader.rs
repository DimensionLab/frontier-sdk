// SPDX-License-Identifier: Apache-2.0
//! The layered loader. Precedence, lowest to highest:
//!
//! 1. built-in defaults (the schema)
//! 2. system file `/etc/frontier/config.toml` (may lock keys)
//! 3. server layer (settings an administrator changed through the API; server process only)
//! 4. user file `~/.frontier/config.toml` (`FRONTIER_HOME` moves it)
//! 5. project file `./frontier.toml` (nearest ancestor of the working directory)
//! 6. environment `FRONTIER_<SECTION>__<KEY>` (and the legacy names listed per setting)
//! 7. command-line flags
//!
//! A key locked by the system file keeps the system value (or the default when the system
//! file does not set it); values from higher layers are recorded as ignored so `explain` can
//! say why they had no effect.

use crate::schema::{self, SettingType};
use crate::value;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// File name of the user and system config.
pub const CONFIG_FILE: &str = "config.toml";
/// File name of a project config.
pub const PROJECT_FILE: &str = "frontier.toml";
/// Default system config path on Unix.
pub const SYSTEM_FILE_UNIX: &str = "/etc/frontier/config.toml";

/// Which layer a value came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Default,
    System,
    Server,
    User,
    Project,
    Env,
    /// A command-line flag (`--setting KEY=VALUE` and the typed flags). `cli` on the wire.
    #[serde(rename = "cli")]
    Flag,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::System => "system",
            Self::Server => "server",
            Self::User => "user",
            Self::Project => "project",
            Self::Env => "env",
            Self::Flag => "cli",
        }
    }
}

/// A value a layer provided that did not become the effective one.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Shadowed {
    pub source: Source,
    /// File path, environment variable name, or `--flag`.
    pub origin: String,
    pub value: Value,
    /// `"overridden"` (a higher layer won), `"locked"` (the system file forbids it) or
    /// `"not trusted"` (this layer may not set the key, see [`restriction`]).
    pub why: &'static str,
}

/// The effective value of one key and how it came about.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub value: Value,
    pub source: Source,
    /// File path or environment variable that set the value (empty for defaults).
    pub origin: String,
    pub locked: bool,
    pub reason: Option<String>,
    pub shadowed: Vec<Shadowed>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Error,
}

/// Something wrong in a layer. Loading never fails because of one: the offending value is
/// skipped and reported, so a typo cannot lock a user out of the CLI.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Problem {
    pub severity: Severity,
    pub source: Source,
    pub origin: String,
    pub key: Option<String>,
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.key {
            Some(key) => write!(f, "{}: {}: {}", self.origin, key, self.message),
            None => write!(f, "{}: {}", self.origin, self.message),
        }
    }
}

/// Where the layers live on this machine.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Paths {
    /// `$FRONTIER_HOME` or `~/.frontier`: user config, local credentials and state.
    pub home: PathBuf,
    pub system: PathBuf,
    pub user: PathBuf,
    /// The project file in effect, if the working directory is inside a project.
    pub project: Option<PathBuf>,
}

/// `$FRONTIER_HOME` or `~/.frontier`.
pub fn frontier_home(env: &BTreeMap<String, String>) -> PathBuf {
    match env.get("FRONTIER_HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h),
        _ => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".frontier"),
    }
}

/// The system config path. `/etc/frontier/config.toml` (or `%PROGRAMDATA%\Frontier\config.toml`)
/// always wins when it exists; only when it does not is `FRONTIER_SYSTEM_CONFIG` honoured, so
/// a user cannot point an installed lock file elsewhere. Client-side locks are a guard rail:
/// the control plane enforces policy on its own copy.
pub fn system_path(env: &BTreeMap<String, String>) -> PathBuf {
    let default = if cfg!(windows) {
        PathBuf::from(
            env.get("PROGRAMDATA")
                .cloned()
                .unwrap_or_else(|| r"C:\ProgramData".into()),
        )
        .join("Frontier")
        .join(CONFIG_FILE)
    } else {
        PathBuf::from(SYSTEM_FILE_UNIX)
    };
    if default.is_file() {
        return default;
    }
    match env.get("FRONTIER_SYSTEM_CONFIG") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => default,
    }
}

/// Nearest `frontier.toml` walking up from `start`.
pub fn find_project_file(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|d| d.join(PROJECT_FILE))
        .find(|p| p.is_file())
}

/// Everything the loader reads. Tests build one by hand; processes use [`LoadOptions::from_process`].
#[derive(Clone, Default)]
pub struct LoadOptions {
    pub system_file: Option<PathBuf>,
    pub home: PathBuf,
    pub project_file: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    /// Values from command-line flags, by setting key.
    pub flags: BTreeMap<String, Value>,
    /// Server-scope values from the control plane's database.
    pub server: BTreeMap<String, Value>,
    /// Names of the variables in `env` that came from a developer `.env` rather than the
    /// process environment: as trusted as a project file, no more.
    pub dotenv_vars: std::collections::BTreeSet<String>,
}

/// Which layers may set a key, whatever their precedence (precedence is not trust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restriction {
    /// Organisation policy: only the system file and the control plane's own settings.
    Admin,
    /// Code execution and the network: anything but a project file or a developer `.env`,
    /// which arrive with a cloned repository.
    Trusted,
}

/// Keys that decide what runs or where data and credentials are sent, whatever the
/// registry says about their scope.
pub const EXEC_NETWORK_KEYS: &[&str] = &[
    "compute.python",
    "client.server_url",
    "hub.extra_catalogs",
    "plugins.index_url",
    "plugins.wheel_dir",
    "policy.ai.local_endpoint",
    "policy.ai.local_endpoints",
];

/// The restriction on `def`, decided from the registry (the same rule as the Python
/// loader, `frontier.config.restriction`):
/// * `Admin`: every server-scope setting, and every `policy.*` setting that is server or
///   system scope or administrator-edited;
/// * `Trusted`: [`EXEC_NETWORK_KEYS`], `network.*`, and every other system-scope or
///   administrator-edited setting;
/// * `None`: any layer may set it.
pub fn restriction(def: &schema::SettingDef) -> Option<Restriction> {
    if EXEC_NETWORK_KEYS.contains(&def.key.as_str()) || def.key.starts_with("network.") {
        return Some(Restriction::Trusted);
    }
    let admin = matches!(def.scope, schema::Scope::Server | schema::Scope::System)
        || def.editable_by == schema::EditableBy::Admin;
    if def.scope == schema::Scope::Server || (admin && def.key.starts_with("policy.")) {
        return Some(Restriction::Admin);
    }
    admin.then_some(Restriction::Trusted)
}

/// Whether the layer `source` may set `def` to any value. `from_dotenv`: the value came
/// from a developer `.env`, which is as trusted as a project file.
pub fn may_set(def: &schema::SettingDef, source: &Source, from_dotenv: bool) -> bool {
    let untrusted_file = *source == Source::Project || from_dotenv;
    match restriction(def) {
        None => true,
        Some(Restriction::Admin) => matches!(source, Source::System | Source::Server),
        Some(Restriction::Trusted) => !untrusted_file,
    }
}

/// Whether changing `def` from `current` to `proposed` can only make things stricter, so
/// that a layer without the right to set the key may still apply it: a switch moved in
/// its strict direction, an allow-list narrowed, a cap lowered. Anything not known to be
/// stricter counts as loosening.
pub fn tightens(def: &schema::SettingDef, current: &Value, proposed: &Value) -> bool {
    const WILDCARDS: &[&str] = &["any", "*", "all"];
    let how = match def.key.as_str() {
        "network.offline" => "true",
        "policy.ai.data_leaves_site"
        | "policy.allow_public_hub"
        | "policy.allow_plugin_changes" => "false",
        "policy.max_cost_per_run" | "policy.compute_max_gpus_per_run" => "cap",
        _ if def.ty == SettingType::List
            && def
                .name()
                .rsplit('.')
                .next()
                .is_some_and(|n| n.starts_with("allow_") || n.starts_with("allowed_"))
            || matches!(
                def.key.as_str(),
                "policy.plugin_sources"
                    | "policy.compute_allowed_pools"
                    | "policy.ai.autonomous_op_classes"
            ) =>
        {
            "subset"
        }
        _ => return false,
    };
    match how {
        "true" => proposed.as_bool() == Some(true) && current.is_boolean(),
        "false" => proposed.as_bool() == Some(false) && current.is_boolean(),
        "subset" => {
            let set = |v: &Value| -> Option<Vec<String>> {
                v.as_array()?
                    .iter()
                    .map(|i| i.as_str().map(str::to_lowercase))
                    .collect()
            };
            let (Some(cur), Some(new)) = (set(current), set(proposed)) else {
                return false;
            };
            if cur.iter().any(|c| WILDCARDS.contains(&c.as_str())) {
                return true;
            }
            !new.iter().any(|n| WILDCARDS.contains(&n.as_str()))
                && new.iter().all(|n| cur.contains(n))
        }
        _ => {
            let (Some(cur), Some(new)) = (current.as_f64(), proposed.as_f64()) else {
                return false;
            };
            if new <= 0.0 {
                cur <= 0.0
            } else {
                cur <= 0.0 || new <= cur
            }
        }
    }
}

/// The environment can hold credentials: `Debug` shows how many variables there are, never
/// their values.
impl std::fmt::Debug for LoadOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadOptions")
            .field("system_file", &self.system_file)
            .field("home", &self.home)
            .field("project_file", &self.project_file)
            .field("env", &format_args!("<{} variables>", self.env.len()))
            .field("flags", &self.flags)
            .field("server", &self.server)
            .finish()
    }
}

impl LoadOptions {
    /// The process environment (plus the developer `.env`, see [`crate::dev`]) and the
    /// standard file locations.
    pub fn from_process() -> Self {
        let env = crate::dev::process_env().clone();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            system_file: Some(system_path(&env)),
            home: frontier_home(&env),
            project_file: find_project_file(&cwd),
            env,
            flags: BTreeMap::new(),
            server: BTreeMap::new(),
            dotenv_vars: crate::dev::dotenv_vars().clone(),
        }
    }

    pub fn with_flag(mut self, key: &str, value: Option<Value>) -> Self {
        if let Some(v) = value {
            self.flags.insert(key.to_string(), v);
        }
        self
    }
}

fn toml_to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a) => Value::Array(a.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => Value::Object(
            t.iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect(),
        ),
    }
}

/// One parsed config file: flat values and (system file only) locks.
#[derive(Debug, Default)]
struct FileLayer {
    values: Vec<(String, Value)>,
    /// Pattern (`section.key` or `section.*`) -> reason.
    locks: Vec<(String, Option<String>)>,
    problems: Vec<(Option<String>, Severity, String)>,
}

fn parse_file(text: &str, allow_locks: bool) -> FileLayer {
    let mut layer = FileLayer::default();
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => {
            layer.problems.push((
                None,
                Severity::Error,
                format!("not valid TOML, the whole file is ignored: {e}"),
            ));
            return layer;
        }
    };
    for (section, body) in &table {
        if section == "lock" {
            if !allow_locks {
                layer.problems.push((
                    Some("lock".into()),
                    Severity::Warning,
                    "locks are only honoured in the system file; ignored here".into(),
                ));
                continue;
            }
            parse_locks(body, &mut layer);
            continue;
        }
        let Some(body) = body.as_table() else {
            layer.problems.push((
                Some(section.clone()),
                Severity::Error,
                "settings live in sections, for example `[storage]` then `datasets_dir = \"...\"`"
                    .into(),
            ));
            continue;
        };
        for (name, v) in body {
            // `[policy.ai]` holds registered keys of its own: one level deeper.
            if let Some(sub) = v.as_table()
                && schema::is_subtable(section, name)
            {
                for (leaf, v) in sub {
                    layer
                        .values
                        .push((format!("{section}.{name}.{leaf}"), toml_to_json(v)));
                }
                continue;
            }
            layer
                .values
                .push((format!("{section}.{name}"), toml_to_json(v)));
        }
    }
    layer
}

fn parse_locks(body: &toml::Value, layer: &mut FileLayer) {
    let Some(table) = body.as_table() else {
        layer.problems.push((
            Some("lock".into()),
            Severity::Error,
            "`[lock]` must be a table of `\"section.key\" = \"reason\"`".into(),
        ));
        return;
    };
    let add = |pattern: String, v: &toml::Value, layer: &mut FileLayer| match v {
        toml::Value::String(reason) => layer.locks.push((pattern, Some(reason.clone()))),
        toml::Value::Boolean(true) => layer.locks.push((pattern, None)),
        toml::Value::Boolean(false) => {}
        _ => layer.problems.push((
            Some(format!("lock.{pattern}")),
            Severity::Error,
            "a lock is `true` or a string with the reason".into(),
        )),
    };
    for (k, v) in table {
        match v {
            // [lock.policy] allow_public_hub = "reason"
            toml::Value::Table(inner) => {
                for (name, v) in inner {
                    add(format!("{k}.{name}"), v, layer);
                }
            }
            // [lock] "policy.allow_public_hub" = "reason"
            _ => add(k.clone(), v, layer),
        }
    }
}

fn lock_matches(pattern: &str, key: &str) -> bool {
    match pattern.strip_suffix(".*") {
        // `policy.*` covers `policy.ai.allowed_providers` too; `policy.ai.*` only the sub-table
        Some(prefix) => key
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('.')),
        None => pattern == key || pattern == "*",
    }
}

type Apply<'a> = &'a mut dyn FnMut(
    Source,
    &str,
    &str,
    Result<Value, String>,
    &mut BTreeMap<String, Entry>,
    &mut Vec<Problem>,
);

/// The effective configuration.
#[derive(Clone)]
pub struct Config {
    entries: BTreeMap<String, Entry>,
    pub problems: Vec<Problem>,
    pub paths: Paths,
    env: BTreeMap<String, String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("entries", &self.entries)
            .field("problems", &self.problems)
            .field("paths", &self.paths)
            .field("env", &format_args!("<{} variables>", self.env.len()))
            .finish()
    }
}

static GLOBAL: OnceLock<Config> = OnceLock::new();

impl Config {
    /// The process-wide configuration, loaded once from the standard locations.
    pub fn global() -> &'static Config {
        GLOBAL.get_or_init(|| Config::load(&LoadOptions::from_process()))
    }

    /// Install `config` as the process-wide configuration (the CLI does this after parsing
    /// flags). Returns `false` when one was already loaded.
    pub fn set_global(config: Config) -> bool {
        GLOBAL.set(config).is_ok()
    }

    /// Defaults only: no files, no environment.
    pub fn defaults() -> Config {
        Config::load(&LoadOptions {
            home: PathBuf::from("."),
            ..Default::default()
        })
    }

    pub fn load(opts: &LoadOptions) -> Config {
        let user_file = opts.home.join(CONFIG_FILE);
        let paths = Paths {
            home: opts.home.clone(),
            system: opts
                .system_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(SYSTEM_FILE_UNIX)),
            user: user_file.clone(),
            project: opts.project_file.clone(),
        };
        let mut problems = Vec::new();
        let mut entries: BTreeMap<String, Entry> = schema::registry()
            .iter()
            .map(|d| {
                (
                    d.key.clone(),
                    Entry {
                        value: d.default.clone(),
                        source: Source::Default,
                        origin: String::new(),
                        locked: false,
                        reason: None,
                        shadowed: Vec::new(),
                    },
                )
            })
            .collect();

        let dotenv_vars = &opts.dotenv_vars;
        let mut apply = |source: Source,
                         origin: &str,
                         key: &str,
                         raw: Result<Value, String>,
                         entries: &mut BTreeMap<String, Entry>,
                         problems: &mut Vec<Problem>| {
            let Some(def) = schema::find(key) else {
                let hint = schema::suggest(key);
                let mut message = "unknown setting".to_string();
                if !hint.is_empty() {
                    message.push_str(&format!(" (did you mean {}?)", hint.join(", ")));
                }
                problems.push(Problem {
                    severity: Severity::Warning,
                    source,
                    origin: origin.to_string(),
                    key: Some(key.to_string()),
                    message,
                });
                return;
            };
            let value = match raw.and_then(|v| value::coerce(def, &v)) {
                Ok(v) => v,
                Err(message) => {
                    problems.push(Problem {
                        severity: Severity::Error,
                        source,
                        origin: origin.to_string(),
                        key: Some(key.to_string()),
                        message: format!("{message}; the value is ignored"),
                    });
                    return;
                }
            };
            let entry = entries.get_mut(key).expect("registry key");
            if entry.locked && source != Source::System {
                entry.shadowed.push(Shadowed {
                    source,
                    origin: origin.to_string(),
                    value,
                    why: "locked",
                });
                return;
            }
            // Precedence is not trust: a project file or a `.env` arrives with a cloned
            // repository and must not decide what runs or where data goes, and policy is
            // the administrator's (CFG-01, CFG-02). Tightening is always accepted.
            let from_dotenv = source == Source::Env && dotenv_vars.contains(origin);
            if !may_set(def, &source, from_dotenv) && !tightens(def, &entry.value, &value) {
                problems.push(Problem {
                    severity: Severity::Warning,
                    source: source.clone(),
                    origin: origin.to_string(),
                    key: Some(key.to_string()),
                    message: match restriction(def) {
                        Some(Restriction::Admin) => "is organisation policy: it can be set in the system file or on the control plane only; the value is ignored (a stricter value would be accepted)".to_string(),
                        _ => "decides what runs or where data is sent: a project file or a .env cannot set it; the value is ignored".to_string(),
                    },
                });
                entry.shadowed.push(Shadowed {
                    source,
                    origin: origin.to_string(),
                    value,
                    why: "not trusted",
                });
                return;
            }
            if entry.source != Source::Default {
                entry.shadowed.push(Shadowed {
                    source: entry.source.clone(),
                    origin: entry.origin.clone(),
                    value: entry.value.clone(),
                    why: "overridden",
                });
            }
            entry.value = value;
            entry.source = source;
            entry.origin = origin.to_string();
        };

        let read = |path: &Path| match std::fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read config file");
                None
            }
        };
        let file_layer = |source: Source,
                          path: &Path,
                          entries: &mut BTreeMap<String, Entry>,
                          problems: &mut Vec<Problem>,
                          apply: Apply<'_>| {
            let Some(text) = read(path) else { return };
            let origin = path.display().to_string();
            let layer = parse_file(&text, source == Source::System);
            for (key, severity, message) in layer.problems {
                problems.push(Problem {
                    severity,
                    source: source.clone(),
                    origin: origin.clone(),
                    key,
                    message,
                });
            }
            for (key, v) in layer.values {
                apply(source.clone(), &origin, &key, Ok(v), entries, problems);
            }
            for (pattern, reason) in layer.locks {
                let mut hit = false;
                for (key, entry) in entries.iter_mut() {
                    if lock_matches(&pattern, key) {
                        entry.locked = true;
                        entry.reason = reason.clone();
                        hit = true;
                    }
                }
                if !hit {
                    problems.push(Problem {
                        severity: Severity::Warning,
                        source: source.clone(),
                        origin: origin.clone(),
                        key: Some(format!("lock.{pattern}")),
                        message: "locks no known setting".into(),
                    });
                }
            }
        };

        // 2. system
        if let Some(system) = &opts.system_file {
            file_layer(
                Source::System,
                system,
                &mut entries,
                &mut problems,
                &mut apply,
            );
        }
        // 3. server database
        for (key, v) in &opts.server {
            apply(
                Source::Server,
                "server settings",
                key,
                Ok(v.clone()),
                &mut entries,
                &mut problems,
            );
        }
        // 4. user, 5. project
        file_layer(
            Source::User,
            &user_file,
            &mut entries,
            &mut problems,
            &mut apply,
        );
        if let Some(project) = &opts.project_file {
            file_layer(
                Source::Project,
                project,
                &mut entries,
                &mut problems,
                &mut apply,
            );
        }
        // 6. environment: legacy names first, the canonical name last so it wins.
        for def in schema::registry() {
            for name in def.env.iter().rev() {
                if let Some(text) = opts.env.get(name)
                    && !(text.is_empty() && def.ty != SettingType::String)
                {
                    // The older FRONTIER_HUB_CATALOGS is a PATH-style list.
                    let joined;
                    let text = if def.key == "hub.extra_catalogs" && *name != def.env[0] {
                        joined = std::env::split_paths(text)
                            .map(|p| p.to_string_lossy().into_owned())
                            .collect::<Vec<_>>()
                            .join(",");
                        &joined
                    } else {
                        text
                    };
                    apply(
                        Source::Env,
                        name,
                        &def.key,
                        value::from_text(def, text),
                        &mut entries,
                        &mut problems,
                    );
                }
            }
        }
        for name in opts.env.keys() {
            if let Some(rest) = name.strip_prefix("FRONTIER_")
                && rest.contains("__")
                && !schema::registry().iter().any(|d| d.env[0] == *name)
            {
                problems.push(Problem {
                    severity: Severity::Warning,
                    source: Source::Env,
                    origin: name.clone(),
                    key: None,
                    message: "matches no setting (expected FRONTIER_<SECTION>__<KEY>)".into(),
                });
            }
        }
        // 7. flags
        for (key, v) in &opts.flags {
            let raw = match (schema::find(key), v) {
                (Some(def), Value::String(s)) => value::from_text(def, s),
                _ => Ok(v.clone()),
            };
            apply(
                Source::Flag,
                "command line",
                key,
                raw,
                &mut entries,
                &mut problems,
            );
        }
        Config {
            entries,
            problems,
            paths,
            env: opts.env.clone(),
        }
    }

    /// The effective entry of `key`.
    pub fn entry(&self, key: &str) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// This configuration with `key` holding `entry`: the value a server read when it
    /// started, kept while its files say something newer.
    pub fn with_entry(mut self, key: &str, entry: Entry) -> Self {
        self.entries.insert(key.to_string(), entry);
        self
    }

    /// This configuration with `key` set to `value` (a candidate to check before it is
    /// written). An unknown key is ignored.
    pub fn with_value(mut self, key: &str, value: Value) -> Self {
        if let Some(e) = self.entries.get_mut(key) {
            e.value = value;
        }
        self
    }

    /// All entries, by key.
    pub fn entries(&self) -> &BTreeMap<String, Entry> {
        &self.entries
    }

    /// The environment the configuration was loaded with (process environment plus the
    /// developer `.env`). Credential fallbacks read from the same map.
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    fn value(&self, key: &str) -> &Value {
        match self.entries.get(key) {
            Some(e) => &e.value,
            None => panic!("{key} is not a registered setting"),
        }
    }

    /// String value. Panics on a key that is not in the registry (a programming error).
    /// The raw JSON value (tables, lists; `Null` for an unknown key).
    pub fn json(&self, key: &str) -> Value {
        self.entries
            .get(key)
            .map(|e| e.value.clone())
            .unwrap_or(Value::Null)
    }

    pub fn str(&self, key: &str) -> &str {
        self.value(key).as_str().unwrap_or_default()
    }

    /// String value, `None` when empty.
    pub fn opt_str(&self, key: &str) -> Option<&str> {
        Some(self.str(key)).filter(|s| !s.is_empty())
    }

    /// Path value with `~` expanded, `None` when empty.
    pub fn path(&self, key: &str) -> Option<PathBuf> {
        self.opt_str(key).map(value::expand_path)
    }

    pub fn int(&self, key: &str) -> i64 {
        self.value(key).as_i64().unwrap_or_default()
    }

    pub fn uint(&self, key: &str) -> u64 {
        self.value(key).as_u64().unwrap_or_default()
    }

    pub fn float(&self, key: &str) -> f64 {
        self.value(key).as_f64().unwrap_or_default()
    }

    pub fn bool(&self, key: &str) -> bool {
        self.value(key).as_bool().unwrap_or_default()
    }

    pub fn list(&self, key: &str) -> Vec<String> {
        self.value(key)
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether any layer above the defaults set `key`.
    pub fn is_set(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_some_and(|e| e.source != Source::Default)
    }

    /// Multi-line explanation of one key for `frontier config explain`.
    pub fn explain(&self, key: &str) -> Option<String> {
        let def = schema::find(key)?;
        let entry = self.entries.get(key)?;
        let mut out = format!("{} ({})\n  {}\n", def.key, def.title, def.description);
        out.push_str(&format!(
            "  type: {}   scope: {}   edited by: {}\n",
            def.ty.as_str(),
            def.scope.as_str(),
            if def.editable_by == schema::EditableBy::Admin {
                "admin"
            } else {
                "user"
            }
        ));
        out.push_str(&format!(
            "  effective value: {}\n",
            describe_value(&entry.value)
        ));
        out.push_str(&format!("  set by: {}\n", describe_source(entry)));
        if entry.locked {
            out.push_str(&format!(
                "  locked by the system file {}{}\n",
                self.paths.system.display(),
                entry
                    .reason
                    .as_deref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default()
            ));
        }
        for s in entry.shadowed.iter().rev() {
            out.push_str(&format!(
                "  {}: {} from {} ({})\n",
                if s.why == "locked" {
                    "ignored"
                } else {
                    "overridden"
                },
                describe_value(&s.value),
                s.source.as_str(),
                s.origin
            ));
        }
        if entry.source != Source::Default {
            out.push_str(&format!("  default: {}\n", describe_value(&def.default)));
        }
        out.push_str(&format!("  environment: {}\n", def.env.join(", ")));
        Some(out)
    }

    /// Environment variables child processes need so tools that know nothing about Frontier
    /// (pip, curl, vendor SDKs, huggingface_hub) honour the network settings.
    pub fn network_env(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut set = |names: &[&str], v: String| {
            if !v.is_empty() {
                for n in names {
                    out.insert((*n).to_string(), v.clone());
                }
            }
        };
        set(
            &["HTTPS_PROXY", "https_proxy"],
            self.str("network.https_proxy").to_string(),
        );
        set(
            &["HTTP_PROXY", "http_proxy"],
            self.str("network.http_proxy").to_string(),
        );
        set(
            &["NO_PROXY", "no_proxy"],
            self.list("network.no_proxy").join(","),
        );
        if let Some(ca) = self.path("network.ca_bundle") {
            set(
                &["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"],
                ca.display().to_string(),
            );
        }
        if self.bool("network.offline") {
            set(&["HF_HUB_OFFLINE", "FRONTIER_OFFLINE"], "1".into());
        }
        set(
            &["HF_ENDPOINT"],
            self.str("hub.huggingface_endpoint").to_string(),
        );
        out
    }
}

fn describe_value(v: &Value) -> String {
    match v {
        Value::String(s) if s.is_empty() => "(empty)".into(),
        other => other.to_string(),
    }
}

fn describe_source(entry: &Entry) -> String {
    match entry.source {
        Source::Default => "built-in default".into(),
        Source::System => format!("system file {}", entry.origin),
        Source::Server => "server settings (changed through the API or the app)".into(),
        Source::User => format!("user file {}", entry.origin),
        Source::Project => format!("project file {}", entry.origin),
        Source::Env => format!("environment variable {}", entry.origin),
        Source::Flag => "command-line flag".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn opts(dir: &Path) -> LoadOptions {
        LoadOptions {
            system_file: Some(dir.join("system.toml")),
            home: dir.join("home"),
            project_file: Some(dir.join("proj").join(PROJECT_FILE)),
            ..Default::default()
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn precedence_default_system_server_user_project_env_flag() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = opts(dir.path());
        let key = "compute.default_gpu";
        assert_eq!(Config::load(&o).entry(key).unwrap().source, Source::Default);
        write(
            &dir.path().join("system.toml"),
            "[compute]\ndefault_gpu = \"sys\"\n",
        );
        assert_eq!(Config::load(&o).str(key), "sys");
        o.server.insert(key.into(), json!("srv"));
        assert_eq!(Config::load(&o).str(key), "srv");
        write(
            &o.home.join(CONFIG_FILE),
            "[compute]\ndefault_gpu = \"usr\"\n",
        );
        assert_eq!(Config::load(&o).str(key), "usr");
        write(
            o.project_file.as_ref().unwrap(),
            "[compute]\ndefault_gpu = \"prj\"\n",
        );
        assert_eq!(Config::load(&o).str(key), "prj");
        o.env
            .insert("FRONTIER_COMPUTE__DEFAULT_GPU".into(), "env".into());
        let c = Config::load(&o);
        assert_eq!(c.str(key), "env");
        assert_eq!(
            c.entry(key).unwrap().origin,
            "FRONTIER_COMPUTE__DEFAULT_GPU"
        );
        o.flags.insert(key.into(), json!("flag"));
        let c = Config::load(&o);
        assert_eq!(c.str(key), "flag");
        assert_eq!(c.entry(key).unwrap().source, Source::Flag);
        // every lower layer is remembered, most recent last
        let shadowed: Vec<_> = c
            .entry(key)
            .unwrap()
            .shadowed
            .iter()
            .map(|s| s.source.as_str())
            .collect();
        assert_eq!(shadowed, ["system", "server", "user", "project", "env"]);
        assert!(c.problems.is_empty(), "{:?}", c.problems);
    }

    /// CFG-01, CFG-02: a cloned repository's `frontier.toml` or `.env` must not configure
    /// what runs or where credentials go, and policy is the administrator's.
    #[test]
    fn a_project_file_and_a_dotenv_cannot_set_what_they_are_not_trusted_with() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path());
        write(
            o.project_file.as_ref().unwrap(),
            "[compute]\npython = \"/repo/evil/python\"\n[client]\nserver_url = \"https://collector.example\"\n\
             [network]\nhttps_proxy = \"http://mitm.example:8080\"\noffline = true\n\
             [plugins]\nindex_url = \"https://evil.example/simple\"\n\
             [policy]\nallow_public_hub = true\nplugin_sources = [\"any\"]\nallow_cloud_targets = [\"local\"]\n\
             [policy.ai]\ndata_leaves_site = true\nlocal_endpoint = \"https://collector.example/v1\"\n\
             [storage]\nruns_dir = \"out\"\n",
        );
        let c = Config::load(&o);
        // none of the dangerous keys took effect
        assert_eq!(c.entry("compute.python").unwrap().source, Source::Default);
        assert_eq!(c.str("client.server_url"), "");
        assert_eq!(
            c.entry("network.https_proxy").unwrap().source,
            Source::Default
        );
        assert_eq!(c.str("plugins.index_url"), "");
        assert!(!c.bool("policy.ai.data_leaves_site"));
        assert_eq!(c.str("policy.ai.local_endpoint"), "http://localhost:11434");
        assert_eq!(
            c.list("policy.plugin_sources"),
            ["bundled", "pypi", "index", "wheel_dir"]
        );
        // what a project may say, it says: its own keys, and anything that only tightens
        assert_eq!(c.str("storage.runs_dir"), "out");
        assert!(c.bool("network.offline"));
        assert_eq!(c.list("policy.allow_cloud_targets"), ["local"]);
        // each refusal is visible: a problem, and the refused value in `explain`
        let refused: Vec<&str> = c
            .problems
            .iter()
            .filter(|p| p.message.contains("is ignored"))
            .filter_map(|p| p.key.as_deref())
            .collect();
        for key in [
            "compute.python",
            "client.server_url",
            "network.https_proxy",
            "plugins.index_url",
            "policy.allow_public_hub",
            "policy.plugin_sources",
            "policy.ai.data_leaves_site",
            "policy.ai.local_endpoint",
        ] {
            assert!(refused.contains(&key), "{key} not reported: {refused:?}");
        }
        assert_eq!(
            c.entry("compute.python").unwrap().shadowed[0].why,
            "not trusted"
        );

        // the same values in the user's own file are the user's to set (but not policy)
        let mut o = opts(dir.path());
        std::fs::remove_file(o.project_file.as_ref().unwrap()).unwrap();
        write(
            &o.home.join("config.toml"),
            "[compute]\npython = \"/home/me/venv/bin/python\"\n[policy.ai]\ndata_leaves_site = true\n",
        );
        let c = Config::load(&o);
        assert_eq!(c.str("compute.python"), "/home/me/venv/bin/python");
        assert!(!c.bool("policy.ai.data_leaves_site"));

        // a developer `.env` is as trusted as a project file; the real environment is not it
        o.env
            .insert("FRONTIER_PYTHON".into(), "/from/dotenv/python".into());
        o.env
            .insert("FRONTIER_SERVER".into(), "https://collector.example".into());
        o.env
            .insert("FRONTIER_LOGGING__LEVEL".into(), "debug".into());
        o.dotenv_vars = [
            "FRONTIER_PYTHON",
            "FRONTIER_SERVER",
            "FRONTIER_LOGGING__LEVEL",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let c = Config::load(&o);
        assert_eq!(c.str("compute.python"), "/home/me/venv/bin/python");
        assert_eq!(c.str("client.server_url"), "");
        assert_eq!(c.str("logging.level"), "debug");
        o.dotenv_vars.clear();
        let c = Config::load(&o);
        assert_eq!(c.str("compute.python"), "/from/dotenv/python");
        assert_eq!(c.str("client.server_url"), "https://collector.example");
    }

    #[test]
    fn tightening_is_recognised_and_nothing_else_is() {
        let def = |k: &str| schema::find(k).unwrap();
        let j = |v: serde_json::Value| v;
        assert!(tightens(
            def("network.offline"),
            &j(json!(false)),
            &j(json!(true))
        ));
        assert!(!tightens(
            def("network.offline"),
            &j(json!(true)),
            &j(json!(false))
        ));
        assert!(tightens(
            def("policy.ai.data_leaves_site"),
            &j(json!(true)),
            &j(json!(false))
        ));
        assert!(!tightens(
            def("policy.ai.data_leaves_site"),
            &j(json!(false)),
            &j(json!(true))
        ));
        let targets = def("policy.allow_cloud_targets");
        assert!(tightens(
            targets,
            &json!(["local", "slurm"]),
            &json!(["local"])
        ));
        assert!(!tightens(
            targets,
            &json!(["local"]),
            &json!(["local", "runpod"])
        ));
        let sources = def("policy.plugin_sources");
        assert!(tightens(sources, &json!(["any"]), &json!(["bundled"])));
        assert!(!tightens(sources, &json!(["bundled"]), &json!(["any"])));
        let cost = def("policy.max_cost_per_run");
        assert!(tightens(cost, &json!(0), &json!(10)));
        assert!(tightens(cost, &json!(50), &json!(10)));
        assert!(!tightens(cost, &json!(10), &json!(50)));
        assert!(!tightens(cost, &json!(10), &json!(0)));
        assert!(!tightens(def("compute.python"), &json!("a"), &json!("b")));
        // the registry-derived classes
        assert_eq!(
            restriction(def("policy.allow_public_hub")),
            Some(Restriction::Admin)
        );
        assert_eq!(
            restriction(def("server.inject_credentials")),
            Some(Restriction::Admin)
        );
        assert_eq!(
            restriction(def("compute.python")),
            Some(Restriction::Trusted)
        );
        assert_eq!(restriction(def("auth.mode")), Some(Restriction::Trusted));
        assert_eq!(restriction(def("ui.theme")), None);
    }

    #[test]
    fn legacy_env_names_work_and_the_canonical_one_wins() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = opts(dir.path());
        o.env
            .insert("FRONTIER_SERVER".into(), "http://legacy:1".into());
        assert_eq!(Config::load(&o).str("client.server_url"), "http://legacy:1");
        o.env
            .insert("FRONTIER_CLIENT__SERVER_URL".into(), "http://new:2".into());
        assert_eq!(Config::load(&o).str("client.server_url"), "http://new:2");
    }

    #[test]
    fn system_lock_beats_every_lower_trust_layer_with_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = opts(dir.path());
        write(
            &dir.path().join("system.toml"),
            r#"
[policy]
allow_public_hub = false

[lock]
"policy.allow_public_hub" = "Data governance: internal mirror only"
"network.*" = true
"#,
        );
        write(
            &o.home.join(CONFIG_FILE),
            "[policy]\nallow_public_hub = true\n[network]\nhttps_proxy = \"http://evil:1\"\n",
        );
        o.env
            .insert("FRONTIER_POLICY__ALLOW_PUBLIC_HUB".into(), "true".into());
        o.flags
            .insert("policy.allow_public_hub".into(), json!(true));
        let c = Config::load(&o);
        let e = c.entry("policy.allow_public_hub").unwrap();
        assert_eq!(e.value, json!(false));
        assert!(e.locked);
        assert_eq!(
            e.reason.as_deref(),
            Some("Data governance: internal mirror only")
        );
        assert_eq!(e.source, Source::System);
        assert_eq!(e.shadowed.len(), 3);
        assert!(e.shadowed.iter().all(|s| s.why == "locked"));
        // a locked key the system file does not set keeps its default
        let p = c.entry("network.https_proxy").unwrap();
        assert!(p.locked && p.reason.is_none());
        assert_eq!(p.value, json!(""));
        let text = c.explain("policy.allow_public_hub").unwrap();
        assert!(text.contains("locked by the system file"), "{text}");
        assert!(text.contains("Data governance"), "{text}");
        assert!(
            text.contains("ignored: true from env (FRONTIER_POLICY__ALLOW_PUBLIC_HUB)"),
            "{text}"
        );
    }

    #[test]
    fn nested_lock_tables_and_locks_outside_the_system_file() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path());
        write(
            &dir.path().join("system.toml"),
            "[lock.policy]\nmax_cost_per_run = \"Finance\"\n",
        );
        write(&o.home.join(CONFIG_FILE), "[lock]\n\"ui.theme\" = true\n");
        let c = Config::load(&o);
        assert!(c.entry("policy.max_cost_per_run").unwrap().locked);
        assert!(!c.entry("ui.theme").unwrap().locked);
        assert!(
            c.problems
                .iter()
                .any(|p| p.message.contains("only honoured in the system file"))
        );
    }

    #[test]
    fn problems_are_reported_and_bad_values_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = opts(dir.path());
        write(
            &o.home.join(CONFIG_FILE),
            "[ui]\ntheme = \"pink\"\n[storage]\ndataset_dir = \"/x\"\n[hub]\nmax_bytes = \"1GB\"\n",
        );
        o.env
            .insert("FRONTIER_WORKER__HEARTBEAT_SECS".into(), "soon".into());
        o.env.insert("FRONTIER_NOPE__KEY".into(), "1".into());
        let c = Config::load(&o);
        assert_eq!(c.str("ui.theme"), "system");
        assert_eq!(c.uint("hub.max_bytes"), 1_000_000_000);
        assert_eq!(c.int("worker.heartbeat_secs"), 10);
        let text: Vec<String> = c.problems.iter().map(|p| p.to_string()).collect();
        assert!(
            text.iter()
                .any(|t| t.contains("ui.theme") && t.contains("one of: system, light, dark")),
            "{text:?}"
        );
        assert!(
            text.iter().any(|t| t.contains("storage.dataset_dir")
                && t.contains("did you mean storage.datasets_dir")),
            "{text:?}"
        );
        assert!(
            text.iter()
                .any(|t| t.contains("FRONTIER_WORKER__HEARTBEAT_SECS") && t.contains("an integer")),
            "{text:?}"
        );
        assert!(
            text.iter().any(|t| t.contains("FRONTIER_NOPE__KEY")),
            "{text:?}"
        );

        write(&o.home.join(CONFIG_FILE), "[ui\ntheme = 1");
        let c = Config::load(&o);
        assert!(
            c.problems
                .iter()
                .any(|p| p.message.contains("not valid TOML"))
        );
    }

    #[test]
    fn the_legacy_catalogue_variable_is_a_path_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = opts(dir.path());
        let joined = std::env::join_paths(["/data/a", "/data/b"]).unwrap();
        o.env.insert(
            "FRONTIER_HUB_CATALOGS".into(),
            joined.to_string_lossy().into_owned(),
        );
        assert_eq!(
            Config::load(&o).list("hub.extra_catalogs"),
            ["/data/a", "/data/b"]
        );
        o.env
            .insert("FRONTIER_HUB__EXTRA_CATALOGS".into(), "/x,/y".into());
        assert_eq!(Config::load(&o).list("hub.extra_catalogs"), ["/x", "/y"]);
    }

    #[test]
    fn debug_output_never_contains_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = opts(dir.path());
        o.env
            .insert("RUNPOD_API_KEY".into(), "rp_secret_value_in_env".into());
        let c = Config::load(&o);
        assert!(!format!("{o:?}").contains("rp_secret_value_in_env"));
        assert!(!format!("{c:?}").contains("rp_secret_value_in_env"));
        assert!(format!("{c:?}").contains("<1 variables>"));
    }

    #[test]
    fn typed_getters_and_network_env() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path());
        write(
            &dir.path().join("system.toml"),
            "[network]\nhttps_proxy = \"http://proxy.example.com:3128\"\nno_proxy = [\"localhost\", \".example.com\"]\nca_bundle = \"/etc/ssl/example.pem\"\noffline = true\n",
        );
        let c = Config::load(&o);
        let env = c.network_env();
        assert_eq!(env["HTTPS_PROXY"], "http://proxy.example.com:3128");
        assert_eq!(env["NO_PROXY"], "localhost,.example.com");
        assert_eq!(env["REQUESTS_CA_BUNDLE"], "/etc/ssl/example.pem");
        assert_eq!(env["HF_HUB_OFFLINE"], "1");
        assert!(c.path("storage.datasets_dir").unwrap().is_absolute());
        assert_eq!(c.opt_str("client.server_url"), None);
        assert_eq!(c.list("policy.allowed_dataset_licences"), ["any"]);
    }
}
