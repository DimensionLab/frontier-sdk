// SPDX-License-Identifier: Apache-2.0
//! Organisation policy: a small API every enforcement point calls (the CLI before it sends
//! a run or pulls a dataset, the control plane before it queues a job, the plugin manager
//! before it installs). Policies are ordinary settings in the `policy` section; an
//! administrator sets and locks them in the system file.
//!
//! ```no_run
//! use frontier_config::{Config, policy::Policy};
//! let policy = Policy::from_config(Config::global());
//! policy.check_target("runpod")?;
//! # Ok::<(), frontier_config::policy::Violation>(())
//! ```

use crate::loader::{Config, Source};
use serde::Serialize;

pub const ALLOW_CLOUD_TARGETS: &str = "policy.allow_cloud_targets";
pub const ALLOW_PUBLIC_HUB: &str = "policy.allow_public_hub";
pub const ALLOWED_DATASET_LICENCES: &str = "policy.allowed_dataset_licences";
pub const MAX_COST_PER_RUN: &str = "policy.max_cost_per_run";
pub const PLUGIN_SOURCES: &str = "policy.plugin_sources";
pub const ALLOW_PLUGIN_CHANGES: &str = "policy.allow_plugin_changes";
pub const COMPUTE_ALLOWED_POOLS: &str = "policy.compute_allowed_pools";
pub const COMPUTE_MAX_GPUS_PER_RUN: &str = "policy.compute_max_gpus_per_run";
pub const AI_ALLOWED_PROVIDERS: &str = "policy.ai.allowed_providers";
pub const AI_DATA_LEAVES_SITE: &str = "policy.ai.data_leaves_site";
pub const AI_AUTONOMOUS_OP_CLASSES: &str = "policy.ai.autonomous_op_classes";
pub const INFERENCE_WEBHOOKS: &str = "policy.inference.webhooks";
pub const INFERENCE_WEBHOOK_HOSTS: &str = "policy.inference.webhook_hosts";

/// A refused action: which policy, a message for the user, and where the policy was set.
#[derive(Debug, Clone, PartialEq, Serialize, thiserror::Error)]
#[error("{message} (policy {policy}, {origin})")]
pub struct Violation {
    /// The setting key, for example `policy.allow_public_hub`.
    pub policy: String,
    pub message: String,
    /// Where the policy value comes from, in words.
    pub origin: String,
    pub locked: bool,
    pub reason: Option<String>,
}

/// What a hub pull is about to download.
#[derive(Debug, Clone, Default)]
pub struct DatasetAccess<'a> {
    pub id: &'a str,
    /// SPDX identifier of the dataset licence (`CC-BY-4.0`, `LicenseRef-...`).
    pub spdx: &'a str,
    /// Whether the licence permits commercial use (false when unclear).
    pub commercial_use: bool,
    /// Whether the files come from a public host (anything but a local path).
    pub public: bool,
}

/// Where a plugin would be installed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginSource {
    /// Shipped with the product (the bundled catalogue / workspace packages).
    Bundled,
    /// The public Python package index.
    Pypi,
    /// The configured `plugins.wheel_dir`.
    WheelDir,
    /// The configured `plugins.index_url`.
    Index,
    /// An explicit path or URL given on the command line.
    Location(String),
}

impl PluginSource {
    fn label(&self) -> String {
        match self {
            Self::Bundled => "bundled".into(),
            Self::Pypi => "pypi".into(),
            Self::WheelDir => "wheel_dir".into(),
            Self::Index => "index".into(),
            Self::Location(l) => l.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct Origin {
    text: String,
    locked: bool,
    reason: Option<String>,
}

/// The policy values in effect.
#[derive(Debug, Clone)]
pub struct Policy {
    pub allow_cloud_targets: Vec<String>,
    pub allow_public_hub: bool,
    pub allowed_dataset_licences: Vec<String>,
    /// 0 = no organisation-wide ceiling.
    pub max_cost_per_run: f64,
    pub plugin_sources: Vec<String>,
    /// Whether plugins may be installed, removed, enabled, disabled or have exporters deployed.
    pub allow_plugin_changes: bool,
    /// `any`, or pool names a run may ask for.
    pub compute_allowed_pools: Vec<String>,
    /// 0 = no organisation-wide ceiling.
    pub compute_max_gpus_per_run: u32,
    /// Model providers an agent session or a judge may use (`local`, `anthropic`, ..., `any`).
    pub ai_allowed_providers: Vec<String>,
    /// Whether hosted model providers may see plan/preview summaries at all.
    pub ai_data_leaves_site: bool,
    /// Op classes (`prep.fields`, `all`) an agent may run without a person's approval.
    pub ai_autonomous_op_classes: Vec<String>,
    /// Whether an inference may notify a URL when its predictions are ready.
    pub inference_webhooks: bool,
    /// Hosts such a URL may name (`any`, or host names; empty = any).
    pub inference_webhook_hosts: Vec<String>,
    origins: std::collections::BTreeMap<&'static str, Origin>,
}

impl Policy {
    pub fn from_config(config: &Config) -> Self {
        let origin = |key: &'static str| {
            let e = config.entry(key);
            let text = match e.map(|e| (&e.source, e.origin.as_str())) {
                Some((Source::Default, _)) | None => "built-in default".to_string(),
                Some((Source::System, path)) => format!("set by your administrator in {path}"),
                Some((Source::Server, _)) => "set by your administrator on the server".to_string(),
                Some((source, origin)) => format!("set in {} {origin}", source.as_str()),
            };
            (
                key,
                Origin {
                    text,
                    locked: e.is_some_and(|e| e.locked),
                    reason: e.and_then(|e| e.reason.clone()),
                },
            )
        };
        Self {
            allow_cloud_targets: config.list(ALLOW_CLOUD_TARGETS),
            allow_public_hub: config.bool(ALLOW_PUBLIC_HUB),
            allowed_dataset_licences: config.list(ALLOWED_DATASET_LICENCES),
            max_cost_per_run: config.float(MAX_COST_PER_RUN),
            plugin_sources: config.list(PLUGIN_SOURCES),
            allow_plugin_changes: config.bool(ALLOW_PLUGIN_CHANGES),
            compute_allowed_pools: config.list(COMPUTE_ALLOWED_POOLS),
            compute_max_gpus_per_run: config.int(COMPUTE_MAX_GPUS_PER_RUN).max(0) as u32,
            ai_allowed_providers: config.list(AI_ALLOWED_PROVIDERS),
            ai_data_leaves_site: config.bool(AI_DATA_LEAVES_SITE),
            ai_autonomous_op_classes: config.list(AI_AUTONOMOUS_OP_CLASSES),
            inference_webhooks: config.bool(INFERENCE_WEBHOOKS),
            inference_webhook_hosts: config.list(INFERENCE_WEBHOOK_HOSTS),
            origins: [
                origin(ALLOW_CLOUD_TARGETS),
                origin(ALLOW_PUBLIC_HUB),
                origin(ALLOWED_DATASET_LICENCES),
                origin(MAX_COST_PER_RUN),
                origin(PLUGIN_SOURCES),
                origin(ALLOW_PLUGIN_CHANGES),
                origin(COMPUTE_ALLOWED_POOLS),
                origin(COMPUTE_MAX_GPUS_PER_RUN),
                origin(AI_ALLOWED_PROVIDERS),
                origin(AI_DATA_LEAVES_SITE),
                origin(AI_AUTONOMOUS_OP_CLASSES),
                origin(INFERENCE_WEBHOOKS),
                origin(INFERENCE_WEBHOOK_HOSTS),
            ]
            .into_iter()
            .collect(),
        }
    }

    fn violation(&self, key: &'static str, message: String) -> Violation {
        let o = self.origins.get(key);
        let mut origin = o.map(|o| o.text.clone()).unwrap_or_default();
        if let Some(reason) = o.and_then(|o| o.reason.as_deref()) {
            origin.push_str(&format!(": {reason}"));
        }
        Violation {
            policy: key.to_string(),
            message,
            origin,
            locked: o.is_some_and(|o| o.locked),
            reason: o.and_then(|o| o.reason.clone()),
        }
    }

    /// May an inference notify `url` when its predictions are ready? Off unless an
    /// administrator turns `policy.inference.webhooks` on; then the URL must be http(s) and,
    /// when `policy.inference.webhook_hosts` names hosts, its host must be one of them.
    pub fn check_webhook(&self, url: &str) -> Result<(), Violation> {
        if !self.inference_webhooks {
            return Err(self.violation(
                INFERENCE_WEBHOOKS,
                "notifying a URL when predictions are ready is turned off here".to_string(),
            ));
        }
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"));
        let host = rest
            .map(|r| r.split(['/', '?', '#']).next().unwrap_or(""))
            .map(|authority| authority.rsplit('@').next().unwrap_or(""))
            .map(|hp| match hp.strip_prefix('[') {
                Some(v6) => v6.split(']').next().unwrap_or(""),
                None => hp.split(':').next().unwrap_or(""),
            })
            .filter(|h| !h.is_empty());
        let Some(host) = host else {
            return Err(self.violation(
                INFERENCE_WEBHOOKS,
                "the notify URL must start with http:// or https:// and name a host".to_string(),
            ));
        };
        let hosts = &self.inference_webhook_hosts;
        if hosts.is_empty()
            || hosts
                .iter()
                .any(|h| h == "any" || h.eq_ignore_ascii_case(host))
        {
            return Ok(());
        }
        Err(self.violation(
            INFERENCE_WEBHOOK_HOSTS,
            format!(
                "host `{host}` may not be notified; allowed hosts: {}",
                hosts.join(", ")
            ),
        ))
    }

    /// May a run or job be sent to `target` (`local`, `ssh`, `slurm`, `k8s`, `runpod`,
    /// `anyscale`)? Server job backends use the same names.
    pub fn check_target(&self, target: &str) -> Result<(), Violation> {
        if self.allow_cloud_targets.iter().any(|t| t == target) {
            return Ok(());
        }
        Err(self.violation(
            ALLOW_CLOUD_TARGETS,
            format!(
                "target `{target}` is not allowed here; allowed targets: {}",
                if self.allow_cloud_targets.is_empty() {
                    "none".to_string()
                } else {
                    self.allow_cloud_targets.join(", ")
                }
            ),
        ))
    }

    /// May this dataset be pulled?
    pub fn check_hub_pull(&self, dataset: &DatasetAccess<'_>) -> Result<(), Violation> {
        if dataset.public && !self.allow_public_hub {
            return Err(self.violation(
                ALLOW_PUBLIC_HUB,
                format!(
                    "downloading `{}` from a public host is not allowed here",
                    dataset.id
                ),
            ));
        }
        let ok = self.allowed_dataset_licences.iter().any(|allowed| {
            match allowed.to_ascii_lowercase().as_str() {
                "any" | "*" => true,
                "commercial" => dataset.commercial_use,
                spdx => spdx == dataset.spdx.to_ascii_lowercase(),
            }
        });
        if ok {
            return Ok(());
        }
        Err(self.violation(
            ALLOWED_DATASET_LICENCES,
            format!(
                "dataset `{}` is licensed {}{}, which is not among the allowed licences ({})",
                dataset.id,
                if dataset.spdx.is_empty() {
                    "under unknown terms"
                } else {
                    dataset.spdx
                },
                if dataset.commercial_use {
                    ""
                } else {
                    " (no commercial use)"
                },
                self.allowed_dataset_licences.join(", ")
            ),
        ))
    }

    /// May a cloud run use `requested` (USD) as its cost ceiling? 0 means "no ceiling".
    pub fn check_cost(&self, requested: f64) -> Result<(), Violation> {
        if self.max_cost_per_run <= 0.0 {
            return Ok(());
        }
        if requested <= 0.0 {
            return Err(self.violation(
                MAX_COST_PER_RUN,
                format!(
                    "a run without a cost ceiling is not allowed here; the ceiling is ${:.2} per run",
                    self.max_cost_per_run
                ),
            ));
        }
        if requested > self.max_cost_per_run + 1e-9 {
            return Err(self.violation(
                MAX_COST_PER_RUN,
                format!(
                    "a cost ceiling of ${requested:.2} exceeds the allowed ${:.2} per run",
                    self.max_cost_per_run
                ),
            ));
        }
        Ok(())
    }

    /// May the set of plugins change at all? `action` is what is being attempted
    /// (`install`, `uninstall`, `enable`, `disable`, `install-exporter`, ...), `plugin` its
    /// target; both only shape the message. Installs additionally go through
    /// [`Policy::check_plugin_source`].
    pub fn check_plugin_change(&self, action: &str, plugin: &str) -> Result<(), Violation> {
        if self.allow_plugin_changes {
            return Ok(());
        }
        Err(self.violation(
            ALLOW_PLUGIN_CHANGES,
            format!(
                "plugins are managed by your administrator; `{action} {plugin}` is not allowed here"
            ),
        ))
    }

    /// May a plugin be installed from `source`?
    pub fn check_plugin_source(&self, source: &PluginSource) -> Result<(), Violation> {
        let label = source.label();
        let ok = self
            .plugin_sources
            .iter()
            .any(|allowed| match allowed.as_str() {
                "any" | "*" => true,
                "bundled" => *source == PluginSource::Bundled,
                "pypi" => *source == PluginSource::Pypi,
                "wheel_dir" => *source == PluginSource::WheelDir,
                "index" => *source == PluginSource::Index,
                prefix => matches!(source, PluginSource::Location(l) if l.starts_with(prefix)),
            });
        if ok {
            return Ok(());
        }
        Err(self.violation(
            PLUGIN_SOURCES,
            format!(
                "installing plugins from `{label}` is not allowed here; allowed sources: {}",
                if self.plugin_sources.is_empty() {
                    "none".to_string()
                } else {
                    self.plugin_sources.join(", ")
                }
            ),
        ))
    }

    /// May a run ask for `pool`? `auto` (or none) is always allowed: the allocator then
    /// chooses inside the allowed pools.
    pub fn check_pool(&self, pool: Option<&str>) -> Result<(), Violation> {
        let Some(pool) = pool.filter(|p| !p.is_empty() && *p != "auto") else {
            return Ok(());
        };
        if self.pool_allowed(pool) {
            return Ok(());
        }
        Err(self.violation(
            COMPUTE_ALLOWED_POOLS,
            format!(
                "pool `{pool}` is not allowed here; allowed pools: {}",
                if self.compute_allowed_pools.is_empty() {
                    "none".to_string()
                } else {
                    self.compute_allowed_pools.join(", ")
                }
            ),
        ))
    }

    /// Whether `pool` is inside `policy.compute_allowed_pools` (for `auto` to filter by).
    pub fn pool_allowed(&self, pool: &str) -> bool {
        self.compute_allowed_pools
            .iter()
            .any(|p| p == "any" || p == "*" || p == pool)
    }

    /// May one run hold `gpus` devices over all of its nodes?
    pub fn check_gpus(&self, gpus: u32) -> Result<(), Violation> {
        if self.compute_max_gpus_per_run == 0 || gpus <= self.compute_max_gpus_per_run {
            return Ok(());
        }
        Err(self.violation(
            COMPUTE_MAX_GPUS_PER_RUN,
            format!(
                "{gpus} GPUs exceed the allowed {} per run",
                self.compute_max_gpus_per_run
            ),
        ))
    }

    /// A machine-readable summary (no secrets, safe to show anywhere).
    /// May an agent session or a judge use the model provider `provider` (`local`,
    /// `ollama`, `anthropic`, `typesafe`, ...)? A hosted provider is refused first by
    /// `policy.ai.data_leaves_site`, then by `policy.ai.allowed_providers`.
    pub fn check_ai_provider(&self, provider: &str) -> Result<(), Violation> {
        let p = provider.trim().to_ascii_lowercase();
        let hosted = crate::schema::HOSTED_AI_PROVIDERS.contains(&p.as_str());
        if hosted && !self.ai_data_leaves_site {
            return Err(self.violation(
                AI_DATA_LEAVES_SITE,
                format!(
                    "the hosted provider `{p}` would send dataset content off-site, and data_leaves_site is false; use a local model or have an administrator allow it"
                ),
            ));
        }
        let allowed = self.ai_allowed_providers.iter().any(|a| a == "any")
            || self.ai_allowed_providers.contains(&p)
            || (crate::schema::LOCAL_AI_PROVIDERS.contains(&p.as_str())
                && self.ai_allowed_providers.iter().any(|a| a == "local"));
        if allowed {
            Ok(())
        } else {
            Err(self.violation(
                AI_ALLOWED_PROVIDERS,
                format!(
                    "the provider `{p}` is not in allowed_providers ({})",
                    self.ai_allowed_providers.join(", ")
                ),
            ))
        }
    }

    /// Whether ops of this class may run without an approval (`prep.fields.rename` matches
    /// `prep.fields`, `prep.fields.*` and `all`).
    pub fn ai_autonomous(&self, op_id: &str) -> bool {
        self.ai_autonomous_op_classes.iter().any(|class| {
            let c = class.trim_end_matches('*').trim_end_matches('.');
            c == "all" || op_id == c || op_id.starts_with(&format!("{c}."))
        })
    }

    /// An agent (or an API client without a reviewer) wants to `run` `op_id` with no
    /// approval: allowed only when policy grants autonomy for its class.
    pub fn check_autonomous_run(&self, op_id: &str) -> Result<(), Violation> {
        if self.ai_autonomous(op_id) {
            return Ok(());
        }
        Err(self.violation(
            AI_AUTONOMOUS_OP_CLASSES,
            format!(
                "`{op_id}` needs a person's approval before it runs: pass an approval (reviewer and plan id), or have an administrator add its class to autonomous_op_classes"
            ),
        ))
    }

    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "compute_allowed_pools": self.compute_allowed_pools,
            "compute_max_gpus_per_run": self.compute_max_gpus_per_run,
            "allow_cloud_targets": self.allow_cloud_targets,
            "allow_public_hub": self.allow_public_hub,
            "allowed_dataset_licences": self.allowed_dataset_licences,
            "max_cost_per_run": self.max_cost_per_run,
            "plugin_sources": self.plugin_sources,
            "allow_plugin_changes": self.allow_plugin_changes,
            "ai": {
                "allowed_providers": self.ai_allowed_providers,
                "data_leaves_site": self.ai_data_leaves_site,
                "autonomous_op_classes": self.ai_autonomous_op_classes,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::LoadOptions;

    fn policy(system: &str) -> Policy {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.toml");
        std::fs::write(&path, system).unwrap();
        Policy::from_config(&Config::load(&LoadOptions {
            system_file: Some(path),
            home: dir.path().join("home"),
            ..Default::default()
        }))
    }

    #[test]
    fn defaults_allow_everything() {
        let p = policy("");
        for t in crate::schema::TARGETS {
            p.check_target(t).unwrap();
        }
        p.check_hub_pull(&DatasetAccess {
            id: "x",
            spdx: "CC-BY-NC-4.0",
            commercial_use: false,
            public: true,
        })
        .unwrap();
        p.check_cost(0.0).unwrap();
        p.check_cost(1e6).unwrap();
        // plugins: the official index and what an administrator configured, by default;
        // an arbitrary URL or path is code from anywhere and needs listing
        for source in [
            PluginSource::Bundled,
            PluginSource::Pypi,
            PluginSource::Index,
            PluginSource::WheelDir,
        ] {
            p.check_plugin_source(&source).unwrap();
        }
        assert!(
            p.check_plugin_source(&PluginSource::Location("https://x/y.whl".into()))
                .is_err()
        );
    }

    #[test]
    fn targets() {
        let p = policy(
            "[policy]\nallow_cloud_targets = [\"local\", \"slurm\"]\n[lock]\n\"policy.allow_cloud_targets\" = \"ITAR programme\"\n",
        );
        p.check_target("slurm").unwrap();
        let v = p.check_target("runpod").unwrap_err();
        assert_eq!(v.policy, ALLOW_CLOUD_TARGETS);
        assert!(v.locked);
        let text = v.to_string();
        assert!(
            text.contains("target `runpod` is not allowed here; allowed targets: local, slurm"),
            "{text}"
        );
        assert!(
            text.contains("set by your administrator") && text.contains("ITAR programme"),
            "{text}"
        );
    }

    #[test]
    fn hub_and_licences() {
        let p = policy("[policy]\nallow_public_hub = false\n");
        let public = DatasetAccess {
            id: "ahmedml",
            spdx: "CC-BY-SA-4.0",
            commercial_use: true,
            public: true,
        };
        assert_eq!(
            p.check_hub_pull(&public).unwrap_err().policy,
            ALLOW_PUBLIC_HUB
        );
        p.check_hub_pull(&DatasetAccess {
            public: false,
            ..public.clone()
        })
        .unwrap();

        let p = policy("[policy]\nallowed_dataset_licences = [\"commercial\", \"CC-BY-NC-4.0\"]\n");
        p.check_hub_pull(&public).unwrap();
        p.check_hub_pull(&DatasetAccess {
            id: "nc",
            spdx: "cc-by-nc-4.0",
            commercial_use: false,
            public: true,
        })
        .unwrap();
        let v = p
            .check_hub_pull(&DatasetAccess {
                id: "drivaernet",
                spdx: "CC-BY-NC-SA-4.0",
                commercial_use: false,
                public: true,
            })
            .unwrap_err();
        assert_eq!(v.policy, ALLOWED_DATASET_LICENCES);
        assert!(
            v.message.contains("CC-BY-NC-SA-4.0 (no commercial use)"),
            "{}",
            v.message
        );
    }

    #[test]
    fn cost_ceiling() {
        let p = policy("[policy]\nmax_cost_per_run = 5.0\n");
        p.check_cost(5.0).unwrap();
        p.check_cost(0.5).unwrap();
        assert!(
            p.check_cost(5.01)
                .unwrap_err()
                .message
                .contains("exceeds the allowed $5.00")
        );
        assert!(
            p.check_cost(0.0)
                .unwrap_err()
                .message
                .contains("without a cost ceiling")
        );
    }

    #[test]
    fn plugin_changes_can_be_frozen() {
        policy("")
            .check_plugin_change("uninstall", "fluent")
            .unwrap();
        let p = policy(
            "[policy]\nallow_plugin_changes = false\n[lock]\n\"policy.allow_plugin_changes\" = \"Validated toolchain\"\n",
        );
        for action in [
            "install",
            "uninstall",
            "enable",
            "disable",
            "install-exporter",
        ] {
            let v = p.check_plugin_change(action, "fluent").unwrap_err();
            assert_eq!(v.policy, ALLOW_PLUGIN_CHANGES);
            assert!(v.locked && v.to_string().contains("Validated toolchain"));
            assert!(
                v.message
                    .contains(&format!("`{action} fluent` is not allowed")),
                "{}",
                v.message
            );
        }
    }

    #[test]
    fn plugin_sources() {
        let p = policy(
            "[policy]\nplugin_sources = [\"bundled\", \"wheel_dir\", \"https://pkgs.example.com/\"]\n",
        );
        p.check_plugin_source(&PluginSource::Bundled).unwrap();
        p.check_plugin_source(&PluginSource::WheelDir).unwrap();
        p.check_plugin_source(&PluginSource::Location(
            "https://pkgs.example.com/simple/x.whl".into(),
        ))
        .unwrap();
        let v = p.check_plugin_source(&PluginSource::Pypi).unwrap_err();
        assert!(
            v.message.contains("from `pypi` is not allowed"),
            "{}",
            v.message
        );
        assert!(
            p.check_plugin_source(&PluginSource::Location("/tmp/evil.whl".into()))
                .is_err()
        );
    }

    #[test]
    fn ai_policy_defaults_keep_data_on_site() {
        let p = policy("");
        p.check_ai_provider("local").unwrap();
        p.check_ai_provider("ollama").unwrap();
        let v = p.check_ai_provider("anthropic").unwrap_err();
        assert_eq!(v.policy, AI_DATA_LEAVES_SITE);
        assert!(v.message.contains("off-site"));
        assert!(!p.ai_autonomous("prep.fields.rename"));
        assert_eq!(
            p.check_autonomous_run("prep.fields.rename")
                .unwrap_err()
                .policy,
            AI_AUTONOMOUS_OP_CLASSES
        );
    }

    #[test]
    fn ai_policy_reads_the_nested_table_and_locks() {
        let p = policy(
            "[policy.ai]\ndata_leaves_site = true\nallowed_providers = [\"local\", \"anthropic\"]\nautonomous_op_classes = [\"prep.fields\"]\n[lock]\n\"policy.ai.*\" = \"export control\"\n",
        );
        p.check_ai_provider("anthropic").unwrap();
        let v = p.check_ai_provider("typesafe").unwrap_err();
        assert_eq!(v.policy, AI_ALLOWED_PROVIDERS);
        assert!(v.locked, "{v:?}");
        assert_eq!(v.reason.as_deref(), Some("export control"));
        assert!(p.ai_autonomous("prep.fields.rename"));
        assert!(!p.ai_autonomous("prep.mesh.repair"));
        p.check_autonomous_run("prep.fields.map").unwrap();
    }

    #[test]
    fn ai_policy_from_the_environment_and_the_editor() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("home").join("config.toml");
        crate::edit::set_in_file(
            &user,
            "policy.ai.local_model",
            &serde_json::json!("qwen3:8b"),
        )
        .unwrap();
        let text = std::fs::read_to_string(&user).unwrap();
        assert!(text.contains("[policy.ai]"), "{text}");
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "FRONTIER_POLICY__AI_ALLOWED_PROVIDERS".to_string(),
            "local,openai".to_string(),
        );
        env.insert(
            "FRONTIER_POLICY__AI_DATA_LEAVES_SITE".to_string(),
            "true".to_string(),
        );
        // Organisation policy is not the environment's to loosen (CFG-01): the variables
        // are ignored, with a problem that says so ...
        let config = Config::load(&LoadOptions {
            system_file: Some(dir.path().join("none.toml")),
            home: dir.path().join("home"),
            env: env.clone(),
            ..Default::default()
        });
        assert_eq!(config.str("policy.ai.local_model"), "qwen3:8b");
        assert_eq!(config.list("policy.ai.allowed_providers"), vec!["local"]);
        assert!(!config.bool("policy.ai.data_leaves_site"));
        assert!(
            Policy::from_config(&config)
                .check_ai_provider("openai")
                .is_err()
        );
        assert!(
            config
                .problems
                .iter()
                .any(|p| p.key.as_deref() == Some("policy.ai.allowed_providers")
                    && p.message.contains("organisation policy")),
            "{:?}",
            config.problems
        );
        // ... while the system file sets it, and the environment may then only narrow it
        std::fs::write(
            dir.path().join("system.toml"),
            "[policy.ai]\nallowed_providers = [\"local\", \"openai\", \"anthropic\"]\ndata_leaves_site = true\n",
        )
        .unwrap();
        let config = Config::load(&LoadOptions {
            system_file: Some(dir.path().join("system.toml")),
            home: dir.path().join("home"),
            env,
            ..Default::default()
        });
        assert_eq!(
            config.list("policy.ai.allowed_providers"),
            vec!["local", "openai"]
        );
        Policy::from_config(&config)
            .check_ai_provider("openai")
            .unwrap();
        assert!(
            Policy::from_config(&config)
                .check_ai_provider("anthropic")
                .is_err()
        );
        assert!(crate::edit::unset_in_file(&user, "policy.ai.local_model").unwrap());
        let text = std::fs::read_to_string(&user).unwrap();
        assert!(!text.contains("local_model"), "{text}");
    }
}
