// SPDX-License-Identifier: Apache-2.0
//! The settings registry: the single source of truth for every user- or admin-editable
//! setting. The JSON export ([`flat_json`], [`json_schema`]) is committed to the Python SDK
//! (`packages/frontier/src/frontier/config_schema.json`) and the settings reference is
//! generated from it ([`markdown_reference`]); tests fail when either drifts.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::LazyLock;

/// Value type of a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingType {
    String,
    /// A filesystem path; a leading `~` expands to the user's home directory.
    Path,
    Url,
    Int,
    Float,
    Bool,
    /// List of strings (TOML array; in the environment a comma-separated list or a JSON array).
    List,
    /// A byte count: an integer, or a string such as `"2GiB"` / `"500MB"`.
    Bytes,
    /// A TOML table (JSON object) with its own documented shape, for example the compute
    /// pools; in the environment a JSON object.
    Table,
}

impl SettingType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Path => "path",
            Self::Url => "url",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::List => "list",
            Self::Bytes => "bytes",
            Self::Table => "table",
        }
    }
}

/// Where a setting naturally lives. A higher-trust layer may always set a lower-scope key
/// (the system file can set anything). `scope` says which file `frontier config set` writes
/// to by default: `user` and `project` keys go to those files; `server` keys are organisation
/// wide (the control plane keeps them in its database, a machine without one sets them in
/// the system file); `system` keys are start-up values of a process and live in the system
/// file only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    User,
    Project,
    System,
    Server,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::System => "system",
            Self::Server => "server",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditableBy {
    User,
    Admin,
}

/// One setting. The serialised shape is the public settings schema (plus `env`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingDef {
    pub key: String,
    #[serde(rename = "type")]
    pub ty: SettingType,
    pub default: Value,
    pub title: String,
    pub description: String,
    pub section: String,
    pub scope: Scope,
    /// Always `false`: secrets are credentials, never settings.
    pub secret: bool,
    pub restart_required: bool,
    #[serde(rename = "enum")]
    pub choices: Option<Vec<String>>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub editable_by: EditableBy,
    pub since: String,
    /// Environment variables that set this key: the canonical `FRONTIER_<SECTION>__<KEY>`
    /// first, then accepted legacy names.
    pub env: Vec<String>,
}

impl SettingDef {
    fn new(key: &str, ty: SettingType, default: Value, title: &str, description: &str) -> Self {
        let section_id = key.split('.').next().unwrap_or_default();
        Self {
            key: key.to_string(),
            ty,
            default,
            title: title.to_string(),
            description: description.to_string(),
            section: section_title(section_id).to_string(),
            scope: Scope::User,
            secret: false,
            restart_required: false,
            choices: None,
            min: None,
            max: None,
            editable_by: EditableBy::User,
            since: "0.2".to_string(),
            env: vec![canonical_env(key)],
        }
    }
    fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        if matches!(scope, Scope::System | Scope::Server) {
            self.editable_by = EditableBy::Admin;
        }
        self
    }
    fn admin(mut self) -> Self {
        self.editable_by = EditableBy::Admin;
        self
    }
    fn restart(mut self) -> Self {
        self.restart_required = true;
        self
    }
    fn choices(mut self, values: &[&str]) -> Self {
        self.choices = Some(values.iter().map(|s| s.to_string()).collect());
        self
    }
    fn range(mut self, min: f64, max: f64) -> Self {
        self.min = Some(min);
        self.max = Some(max);
        self
    }
    fn min(mut self, min: f64) -> Self {
        self.min = Some(min);
        self
    }
    fn alias(mut self, names: &[&str]) -> Self {
        self.env.extend(names.iter().map(|s| s.to_string()));
        self
    }

    /// The section id (`storage` in `storage.datasets_dir`).
    pub fn section_id(&self) -> &str {
        self.key.split('.').next().unwrap_or_default()
    }

    /// The key inside its section (`datasets_dir`).
    pub fn name(&self) -> &str {
        self.key
            .split_once('.')
            .map(|(_, n)| n)
            .unwrap_or(&self.key)
    }
}

/// `storage.datasets_dir` -> `FRONTIER_STORAGE__DATASETS_DIR`; a nested key
/// (`policy.ai.allowed_providers`, the `[policy.ai]` table) -> `FRONTIER_POLICY__AI_ALLOWED_PROVIDERS`.
pub fn canonical_env(key: &str) -> String {
    let (section, name) = key.split_once('.').unwrap_or(("", key));
    format!(
        "FRONTIER_{}__{}",
        section.to_uppercase(),
        name.to_uppercase().replace('.', "_")
    )
}

/// Whether any registered key lives in the sub-table `section.sub` (`policy.ai`), which the
/// loader then flattens one level deeper than `section.key`.
pub fn is_subtable(section: &str, sub: &str) -> bool {
    let prefix = format!("{section}.{sub}.");
    registry().iter().any(|d| d.key.starts_with(&prefix))
}

/// Model providers whose use sends dataset content off-site (`policy.ai.data_leaves_site`).
pub const HOSTED_AI_PROVIDERS: &[&str] = &["anthropic", "openai", "typesafe"];
/// Model providers that keep data on the machine or inside the site's network.
pub const LOCAL_AI_PROVIDERS: &[&str] = &["local", "ollama", "vllm", "llamacpp", "rules", "nli"];
/// Every value `policy.ai.allowed_providers` accepts.
pub const AI_PROVIDERS: &[&str] = &[
    "local",
    "ollama",
    "vllm",
    "llamacpp",
    "rules",
    "nli",
    "anthropic",
    "openai",
    "typesafe",
    "any",
];

/// Sections in display order: `(id, title, one-line description)`.
pub const SECTIONS: &[(&str, &str, &str)] = &[
    (
        "client",
        "Connection",
        "How the CLI, the TUI, the SDK and the trainer reach the control plane.",
    ),
    (
        "storage",
        "Storage",
        "Where datasets, raw downloads, caches and run records are kept.",
    ),
    (
        "hub",
        "Datasets hub",
        "The catalogue of public datasets and how much may be downloaded unasked.",
    ),
    (
        "compute",
        "Compute",
        "Defaults for `frontier run`, `frontier sweep` and `frontier cloud`.",
    ),
    (
        "slurm",
        "SLURM",
        "Defaults for SLURM targets; per-cluster details live in site profiles.",
    ),
    (
        "plugins",
        "Plugins",
        "Where connector plugins are installed from (an internal index or a wheel directory when air-gapped).",
    ),
    (
        "network",
        "Network",
        "Proxy, certificate authority and offline mode for every outbound connection.",
    ),
    (
        "secrets",
        "Secrets",
        "Which secret store holds credentials. Credentials themselves are never settings.",
    ),
    (
        "logging",
        "Logging and telemetry",
        "Log verbosity and format. Frontier sends no usage telemetry.",
    ),
    (
        "ui",
        "Interface",
        "Presentation preferences of the app and the TUI.",
    ),
    (
        "viewer",
        "Viewer",
        "How the 3D and 2D views of the app respond to the mouse.",
    ),
    (
        "editor",
        "Editor",
        "How the editor in board nodes and on pages looks and types.",
    ),
    (
        "notifications",
        "Notifications",
        "Which events the app tells you about, and where and how long its toasts show.",
    ),
    (
        "server",
        "Server",
        "The control plane process (`frontier-server`).",
    ),
    (
        "auth",
        "Authentication",
        "Who may call the control plane: single-user, API tokens or OIDC sign-in; sessions and the audit log.",
    ),
    (
        "worker",
        "Worker",
        "The worker process (`frontier-worker`) on a compute node.",
    ),
    (
        "limits",
        "Limits",
        "Size limits enforced by the control plane.",
    ),
    (
        "policy",
        "Policy",
        "Organisation policy. Meant to be set and locked in the system file by an administrator.",
    ),
];

fn section_title(id: &str) -> &'static str {
    SECTIONS
        .iter()
        .find(|(sid, _, _)| *sid == id)
        .map(|(_, title, _)| *title)
        .unwrap_or("Other")
}

/// Compute targets a run can be sent to (`policy.allow_cloud_targets` entries).
pub const TARGETS: &[&str] = &["local", "ssh", "slurm", "k8s", "runpod", "anyscale"];

/// Repository name of the training image built from the Frontier distribution.
pub const TRAINER_IMAGE_NAME: &str = "frontier-trainer";
/// Repository name of the server and worker image.
pub const WORKER_IMAGE_NAME: &str = "frontier";
/// What to tell someone whose command needs a container image when none is configured.
pub const NO_IMAGE_HINT: &str = "No container image is set. Run `frontier config set compute.registry <registry>` or pass --image.";

/// `<registry>/<name>:<version of this build>`; `None` when `registry` is empty.
pub fn image_ref(registry: &str, name: &str) -> Option<String> {
    let registry = registry.trim().trim_end_matches('/');
    (!registry.is_empty()).then(|| format!("{registry}/{name}:{}", env!("CARGO_PKG_VERSION")))
}

/// The image a run uses: `compute.image` when set, else the training image of this version
/// in `compute.registry`. `None` when neither is set.
pub fn trainer_image(config: &crate::Config) -> Option<String> {
    config
        .opt_str("compute.image")
        .map(str::to_string)
        .or_else(|| image_ref(config.str("compute.registry"), TRAINER_IMAGE_NAME))
}

/// The image `frontier cloud up` starts: `compute.worker_image` when set, else the server
/// and worker image of this version in `compute.registry`. `None` when neither is set.
pub fn worker_image(config: &crate::Config) -> Option<String> {
    config
        .opt_str("compute.worker_image")
        .map(str::to_string)
        .or_else(|| image_ref(config.str("compute.registry"), WORKER_IMAGE_NAME))
}

fn build() -> Vec<SettingDef> {
    use SettingType::*;
    let d = SettingDef::new;
    vec![
        // -- client ---------------------------------------------------------------------------
        d("client.server_url", Url, json!(""),
          "Control plane URL",
          "Base URL of the Frontier server (for example https://frontier.example.com). Empty means offline: runs are recorded locally and synced later.")
            .alias(&["FRONTIER_SERVER"]),
        d("client.offline_dir", Path, json!(".frontier"),
          "Offline run directory",
          "Where the SDK writes run records when no server is reachable. Relative paths are relative to the working directory.")
            .scope(Scope::Project)
            .alias(&["FRONTIER_DIR"]),
        d("client.request_timeout_secs", Int, json!(30),
          "Request timeout (seconds)",
          "Timeout of one request to the control plane.")
            .range(1.0, 3600.0),
        // -- storage --------------------------------------------------------------------------
        d("storage.datasets_dir", Path, json!("~/frontier/datasets"),
          "Datasets directory",
          "Where converted frontier-datasets go. On a server, when set: cases converted on the Connectors page (`<dir>/converted/<name>`) and hub pulls (`<dir>/hub/<id>`) are written here instead of the server's data directory.")
            .alias(&["FRONTIER_DATASETS_DIR"]),
        d("storage.raw_dir", Path, json!("datasets/raw"),
          "Raw downloads directory",
          "Where `frontier hub pull` stores files as published, one sub-directory per dataset. Relative paths are relative to the working directory.")
            .alias(&["FRONTIER_RAW_DIR"]),
        d("storage.cache_dir", Path, json!("~/.cache/frontier"),
          "Cache directory",
          "Downloads that can be fetched again (cloud-solver results, plugin wheels).")
            .alias(&["FRONTIER_CONNECTORS_CACHE"]),
        d("storage.runs_dir", Path, json!("runs"),
          "Run output directory",
          "Where local runs write checkpoints, logs and reports. Relative paths are relative to the working directory.")
            .scope(Scope::Project),
        d("storage.import_roots", List, json!([]),
          "Directories the server may read on request",
          "Directories under which a request may name a path for the server to read or write (registering a dataset, trying a connector, a hub pull target). The data directory and `storage.datasets_dir` always count. Empty: no further restriction in single-user mode; with authentication on, only those two.")
            .scope(Scope::System),
        // -- hub ------------------------------------------------------------------------------
        d("hub.max_bytes", Bytes, json!(2_147_483_648u64),
          "Download size limit",
          "Largest pull that starts without --yes or an explicit --max-bytes.")
            .min(1.0),
        d("hub.catalog_path", Path, json!(""),
          "Catalogue file",
          "Replaces the built-in hub catalogue (a catalog.json exported by `frontier hub export`). Empty uses the built-in one.")
            .scope(Scope::System)
            .alias(&["FRONTIER_HUB_CATALOG"]),
        d("hub.extra_catalogs", List, json!([]),
          "Additional catalogues",
          "Directories or files with more catalogue entries (an organisation's internal datasets).")
            .alias(&["FRONTIER_HUB_CATALOGS"]),
        d("hub.mirrors", List, json!([]),
          "Organisation mirrors",
          "Where your organisation keeps raw files of hub entries: items `<entry id or pattern>=<location>`, first match wins, for example `shift-*=s3://company-datasets/restricted` and `*=/mnt/datasets/hub`. A location is a directory or an object-store prefix (s3://, r2://, gs://, az://). Credentials for it come from the secret store (providers `s3`, `gcs`, `azure`), never from the location.")
            .admin(),
        d("hub.huggingface_endpoint", Url, json!(""),
          "Hugging Face endpoint",
          "Base URL of a Hugging Face mirror (HF_ENDPOINT). Empty uses https://huggingface.co.")
            .admin()
            .alias(&["HF_ENDPOINT"]),
        // -- compute --------------------------------------------------------------------------
        d("compute.default_target", String, json!("local"),
          "Default target",
          "Where `frontier run` sends a run when --on is not given.")
            .choices(TARGETS),
        d("compute.default_provider", String, json!("runpod"),
          "Default cloud provider",
          "Provider used by `frontier cloud up` and `frontier cloud offers` when --provider is not given.")
            .choices(&["runpod", "anyscale", "local", "slurm"]),
        d("compute.default_gpu", String, json!("NVIDIA GeForce RTX 4090"),
          "Default GPU type",
          "GPU type `frontier cloud up` rents when --gpu is not given."),
        d("compute.default_tier", String, json!("secure"),
          "Default cloud tier",
          "RunPod capacity tier: `secure` (datacentre) or `community` (cheaper, interruptible hosts).")
            .choices(&["secure", "community"]),
        d("compute.max_cost_per_run", Float, json!(0.0),
          "Cost ceiling per run (USD)",
          "A cloud run is stopped when its accumulated cost reaches this amount, unless --max-cost says otherwise. 0 means no ceiling of your own; `policy.max_cost_per_run` caps it organisation-wide.")
            .min(0.0),
        d("compute.registry", String, json!("docker.io/michaltakac"),
          "Container registry",
          "Registry and path the Frontier images are pulled from. The training image is `<registry>/frontier-trainer:<version>` and the server and worker image `<registry>/frontier:<version>`.")
            .admin()
            .alias(&["FRONTIER_REGISTRY"]),
        d("compute.image", String, json!(""),
          "Training image",
          "Container image a run uses on cloud, SLURM and Kubernetes targets. Empty uses `<compute.registry>/frontier-trainer:<version>`.")
            .admin()
            .alias(&["FRONTIER_IMAGE"]),
        d("compute.worker_image", String, json!(""),
          "Worker image",
          "Container image `frontier cloud up` starts on a rented instance. Empty uses `<compute.registry>/frontier:<version>`.")
            .admin(),
        d("compute.python", String, json!(""),
          "Python interpreter",
          "Python interpreter (or command prefix) that has the Frontier Python packages. Empty uses `.venv` in the project directory, then `uv run python`.")
            .alias(&["FRONTIER_PYTHON"]),
        d("compute.pools", Table, json!({}),
          "Compute pools",
          "Named sets of devices with a role mask, `[compute.pools.<name>]` with `nodes`, `gpus`, `roles` (training, inference, rendering, prep, any), `quota` (`{gpus, jobs}`), `priority`, `shared` and `description`. Every device not named by a pool belongs to the built-in `auto` pool with all roles.")
            .scope(Scope::Server),
        d("compute.rendering_pool", String, json!(""),
          "Rendering pool",
          "Pool the control plane's render workers (thumbnails, render-to-image, frame preparation) take their device from. Empty = any pool that serves the `rendering` role, `auto` included.")
            .scope(Scope::Server),
        d("compute.allocation_policy", String, json!("topology"),
          "Allocation policy",
          "How devices are picked for a job inside a pool: `topology` (same node first, NVLink islands for multi-GPU jobs, then least loaded), `least_loaded` (lowest utilisation and memory use first) or `memory_fit` (the smallest device that fits the request).")
            .scope(Scope::Server).choices(&["topology", "least_loaded", "memory_fit"]),
        d("compute.local_executor", Bool, json!(true),
          "Built-in local worker",
          "Start a `frontier-worker` for the `local` backend next to the control plane, so a single-machine install runs jobs without starting a worker by hand. Turn it off on shared servers where workers run on other machines.")
            .scope(Scope::System).restart(),
        d("compute.local_worker_jobs", Int, json!(2),
          "Jobs of the built-in worker",
          "How many jobs the built-in local worker runs at the same time. Two lets an inference predict while a model trains on the same machine; 1 runs them one after the other.")
            .scope(Scope::System).restart().min(1.0),
        d("server.inference_keep_per_node", Int, json!(20),
          "Automatic predictions kept per node",
          "How many predictions made by an automatic rule (a new checkpoint, a schedule) are kept for one Inference node; older ones are removed with their files. Predictions a person asked for are never removed. 0 keeps all.")
            .scope(Scope::Server).min(0.0),
        d("server.service_warm", Int, json!(1),
          "Requests a service answers at once",
          "How many requests the runtime of a served board answers at the same time; the rest wait. A service can set its own.")
            .scope(Scope::Server).min(1.0),
        d("server.service_idle_release_min", Int, json!(0),
          "Release an idle service after (minutes)",
          "A running service that took no request for this long is stopped and its worker released; the next call starts it again and waits for it. 0 keeps services running.")
            .scope(Scope::Server).min(0.0),
        d("server.service_rate_per_min", Int, json!(600),
          "Requests per minute per service",
          "At most this many calls per minute to one service; more are refused with 429. A service can set its own.")
            .scope(Scope::Server).min(0.0),
        d("server.service_max_request_mb", Int, json!(64),
          "Largest request to a service (MB)",
          "A call with a larger body is refused with 413. A service can set its own.")
            .scope(Scope::Server).range(1.0, 4096.0),
        d("compute.lease_secs", Int, json!(90),
          "Allocation lease (seconds)",
          "An allocation is released when no heartbeat from its worker renews it for this long, and its job is marked failed (`worker lost`).")
            .scope(Scope::Server).range(15.0, 3600.0),
        // -- slurm ----------------------------------------------------------------------------
        d("slurm.default_site", String, json!(""),
          "Default site profile",
          "Site profile (a file in the `sites` directory of the Frontier home) used by --on slurm / --on ssh when neither --site nor --host is given."),
        d("slurm.partition", String, json!(""),
          "Partition",
          "Partition for generated batch scripts when the site profile does not set one.")
            .alias(&["SLURM_PARTITION"]),
        d("slurm.account", String, json!(""),
          "Account",
          "Accounting project for generated batch scripts when the site profile does not set one.")
            .alias(&["SLURM_ACCOUNT"]),
        d("slurm.time_limit", String, json!("08:00:00"),
          "Time limit",
          "Wall-clock limit (HH:MM:SS) of a generated worker allocation.")
            .alias(&["SLURM_TIME"]),
        // -- plugins --------------------------------------------------------------------------
        d("plugins.index_url", Url, json!(""),
          "Package index",
          "Python package index plugins are installed from. Empty uses the installer's default (PyPI). Set it to an internal mirror in restricted networks.")
            .admin()
            .alias(&["FRONTIER_PLUGIN_INDEX"]),
        d("plugins.wheel_dir", Path, json!(""),
          "Wheel directory",
          "Directory of plugin wheels to install from instead of an index (air-gapped installations). When set, no index is contacted.")
            .admin()
            .alias(&["FRONTIER_PLUGIN_WHEELS"]),
        d("plugins.installer", String, json!("auto"),
          "Installer",
          "Tool that installs plugin wheels: uv when available, else pip.")
            .choices(&["auto", "uv", "pip"])
            .alias(&["FRONTIER_PLUGIN_INSTALLER"]),
        // -- network --------------------------------------------------------------------------
        d("network.https_proxy", Url, json!(""),
          "HTTPS proxy",
          "Proxy for outbound HTTPS (exported to child processes as HTTPS_PROXY).")
            .admin()
            .alias(&["HTTPS_PROXY", "https_proxy"]),
        d("network.http_proxy", Url, json!(""),
          "HTTP proxy",
          "Proxy for outbound HTTP (exported as HTTP_PROXY).")
            .admin()
            .alias(&["HTTP_PROXY", "http_proxy"]),
        d("network.no_proxy", List, json!([]),
          "Proxy exceptions",
          "Hosts and domains reached directly (exported as NO_PROXY).")
            .admin()
            .alias(&["NO_PROXY", "no_proxy"]),
        d("network.ca_bundle", Path, json!(""),
          "CA bundle",
          "PEM file with the certificate authorities to trust, for TLS-inspecting proxies and internal services (exported as SSL_CERT_FILE, REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE).")
            .admin()
            .alias(&["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"]),
        d("network.offline", Bool, json!(false),
          "Offline mode",
          "Never open a connection to the public internet: hub pulls, plugin index lookups, price lists and update checks fail fast with an explanation instead of timing out.")
            .alias(&["FRONTIER_OFFLINE"]),
        d("network.offline_allow_hosts", List, json!([]),
          "Hosts reachable in offline mode",
          "Host names inside your network that stay reachable with `network.offline` on, besides this machine, private address ranges and the control plane (`client.server_url`): a secret manager, an identity provider, an internal package index.")
            .admin(),
        // -- secrets --------------------------------------------------------------------------
        d("secrets.backend", String, json!("auto"),
          "Secret store",
          "Where credentials are kept on this machine: the OS keychain, a 0600 file (`credentials.toml` in the state directory, for headless nodes), the environment only, or your organisation's secret manager: `vault` (HashiCorp Vault KV v2, `secrets.vault.*`), `aws` (AWS Secrets Manager, `secrets.aws.*`), `azure` (Azure Key Vault, `secrets.azure.*`) or `gcp` (Google Secret Manager, `secrets.gcp.*`). `auto` uses the keychain when one is available, else the file.")
            .choices(&["auto", "keychain", "file", "env", "vault", "aws", "azure", "gcp"]),
        d("secrets.server_backend", String, json!("db"),
          "Control plane credential store",
          "Where the control plane keeps the credentials people store on it: `db` (its own database, each value encrypted with the server key), `vault` (HashiCorp Vault, `secrets.vault.*`) or `aws` (AWS Secrets Manager, `secrets.aws.*`). New and changed credentials go to this store; `POST /api/v1/secrets/backend/migrate` moves the existing ones.")
            .scope(Scope::System).restart().choices(&["db", "vault", "aws", "azure", "gcp"]),
        d("secrets.server_key", String, json!("file"),
          "Control plane key protection",
          "How the key that encrypts the `db` credential store is kept: `file` (the key itself in `secrets.key_file`, or `FRONTIER_SECRET_KEY`) or `aws-kms` (envelope encryption: the file holds a data key wrapped by the KMS key `secrets.aws.kms_key_id`, unwrapped at start-up).")
            .scope(Scope::System).restart().choices(&["file", "aws-kms"]),
        d("secrets.vault.addr", Url, json!(""),
          "Vault address",
          "Address of the HashiCorp Vault server, for example https://vault.example.com:8200.")
            .admin().alias(&["VAULT_ADDR"]),
        d("secrets.vault.mount", String, json!("secret"),
          "Vault KV mount",
          "Mount point of the KV version 2 secrets engine.")
            .admin(),
        d("secrets.vault.prefix", String, json!("frontier"),
          "Vault path prefix",
          "Path under the mount; one secret per credential provider is kept at `<prefix>/<provider>`, with one key per field.")
            .admin(),
        d("secrets.vault.namespace", String, json!(""),
          "Vault namespace",
          "Vault Enterprise / HCP namespace; empty for none.")
            .admin().alias(&["VAULT_NAMESPACE"]),
        d("secrets.vault.auth", String, json!("token"),
          "Vault authentication",
          "`token` (from `VAULT_TOKEN` or the credential file), `approle` (role id in `secrets.vault.role`, secret id from `FRONTIER_VAULT_SECRET_ID` or the credential file) or `kubernetes` (the pod's service-account token; role in `secrets.vault.role`).")
            .admin().choices(&["token", "approle", "kubernetes"]),
        d("secrets.vault.role", String, json!(""),
          "Vault role",
          "AppRole role id, or the role name of the Kubernetes auth method.")
            .admin(),
        d("secrets.vault.auth_mount", String, json!(""),
          "Vault auth mount",
          "Mount point of the auth method when it is not the default (`approle`, `kubernetes`).")
            .admin(),
        d("secrets.vault.credential_file", Path, json!(""),
          "Vault credential file",
          "File holding the Vault token or the AppRole secret id (or, for `kubernetes`, the service-account token when it is not at the standard path). Never put the value itself in a setting.")
            .admin(),
        d("secrets.azure.vault_url", Url, json!(""),
          "Azure Key Vault URL",
          "Address of the key vault, for example https://frontier-prod.vault.azure.net.")
            .admin(),
        d("secrets.azure.prefix", String, json!("frontier"),
          "Azure secret name prefix",
          "One secret per credential provider is kept as `<prefix>-<provider>` (Key Vault names allow letters, digits and dashes), a JSON object with one key per field.")
            .admin(),
        d("secrets.azure.auth", String, json!("managed_identity"),
          "Azure authentication",
          "`managed_identity` (the identity of the VM, container or AKS pod) or `client_secret` (an app registration: `secrets.azure.tenant_id`, `secrets.azure.client_id`, and the secret from `AZURE_CLIENT_SECRET` or `secrets.azure.credential_file`).")
            .admin().choices(&["managed_identity", "client_secret"]),
        d("secrets.azure.tenant_id", String, json!(""),
          "Azure tenant",
          "Directory (tenant) id for `client_secret` authentication; empty uses `AZURE_TENANT_ID`.")
            .admin(),
        d("secrets.azure.client_id", String, json!(""),
          "Azure client id",
          "Application (client) id for `client_secret` authentication, or the client id of a user-assigned managed identity; empty uses `AZURE_CLIENT_ID`.")
            .admin(),
        d("secrets.azure.credential_file", Path, json!(""),
          "Azure credential file",
          "File holding the client secret. Never put the value itself in a setting.")
            .admin(),
        d("secrets.azure.authority", Url, json!(""),
          "Azure authority override",
          "Token endpoint host when it is not https://login.microsoftonline.com (sovereign clouds, or an emulator in tests).")
            .admin(),
        d("secrets.gcp.project", String, json!(""),
          "Google Cloud project",
          "Project id that holds the secrets; empty uses `GOOGLE_CLOUD_PROJECT`.")
            .admin(),
        d("secrets.gcp.prefix", String, json!("frontier"),
          "Google secret id prefix",
          "One secret per credential provider is kept as `<prefix>-<provider>`, a JSON object with one key per field.")
            .admin(),
        d("secrets.gcp.auth", String, json!("metadata"),
          "Google authentication",
          "`metadata` (the service account of the VM, Cloud Run service or GKE workload identity) or `service_account` (a key file: `secrets.gcp.credential_file`, or `GOOGLE_APPLICATION_CREDENTIALS`).")
            .admin().choices(&["metadata", "service_account"]),
        d("secrets.gcp.credential_file", Path, json!(""),
          "Google service-account key file",
          "JSON key file of the service account for `service_account` authentication.")
            .admin(),
        d("secrets.gcp.endpoint", Url, json!(""),
          "Google Secret Manager endpoint override",
          "Endpoint when it is not https://secretmanager.googleapis.com (Private Service Connect, or an emulator in tests).")
            .admin(),
        d("secrets.aws.region", String, json!(""),
          "AWS region",
          "Region of AWS Secrets Manager; empty uses `AWS_REGION`. Credentials come from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (/ `AWS_SESSION_TOKEN`) in the environment.")
            .admin(),
        d("secrets.aws.prefix", String, json!("frontier"),
          "AWS secret name prefix",
          "One secret per credential provider is kept as `<prefix>/<provider>`, a JSON object with one key per field.")
            .admin(),
        d("secrets.aws.kms_key_id", String, json!(""),
          "AWS KMS key",
          "KMS key id, ARN or alias that new secrets are encrypted under; empty uses the account's default key for Secrets Manager.")
            .admin(),
        d("secrets.aws.kms_endpoint", Url, json!(""),
          "AWS KMS endpoint override",
          "Endpoint of KMS when it is not the public one: a VPC endpoint, or an emulator in tests.")
            .admin(),
        d("secrets.aws.endpoint", Url, json!(""),
          "AWS endpoint override",
          "Endpoint of Secrets Manager when it is not the public one: a VPC endpoint, or an emulator in tests.")
            .admin(),
        d("secrets.key_file", Path, json!(""),
          "Server encryption key file",
          "File with the 32-byte key (hex or base64) that encrypts credentials stored by the server. FRONTIER_SECRET_KEY takes precedence. Empty uses `secret.key` in the server data directory, created on first start.")
            .scope(Scope::System).restart(),
        // -- logging --------------------------------------------------------------------------
        d("logging.level", String, json!("info"),
          "Log level",
          "Verbosity of every Frontier process. RUST_LOG, when set, still wins for the Rust binaries.")
            .choices(&["error", "warn", "info", "debug", "trace"])
            .alias(&["FRONTIER_LOG"]),
        d("logging.format", String, json!("text"),
          "Log format",
          "`json` writes one JSON object per line for log collectors.")
            .choices(&["text", "json"]),
        // -- ui -------------------------------------------------------------------------------
        d("ui.theme", String, json!("system"),
          "Theme",
          "Colour theme of the app and the TUI.")
            .choices(&["system", "light", "dark"]),
        d("ui.units", String, json!("si"),
          "Units",
          "Unit system used when displaying physical quantities.")
            .choices(&["si", "imperial"]),
        d("ui.colormap", String, json!("viridis"),
          "Default colour map",
          "Colour map applied to a scalar field when none was chosen.")
            .choices(&["viridis", "plasma", "inferno", "magma", "cividis", "turbo", "coolwarm", "grayscale"]),
        d("ui.refresh_ms", Int, json!(1000),
          "Refresh interval (ms)",
          "How often the TUI and live views poll for new data.")
            .range(100.0, 60000.0),
        // -- viewer ---------------------------------------------------------------------------
        d("viewer.navigation", String, json!("follow"),
          "Navigation style",
          "`follow`: the object follows the hand when you drag, and rolling the wheel away from you zooms in, as in ParaView. `camera`: drags move the camera instead. `custom`: the three switches below.")
            .choices(&["follow", "camera", "custom"]),
        d("viewer.invert_orbit_x", Bool, json!(false),
          "Invert horizontal orbit",
          "With navigation style `custom`: a drag to the left turns the object to the right."),
        d("viewer.invert_orbit_y", Bool, json!(false),
          "Invert vertical orbit",
          "With navigation style `custom`: a drag down turns the object up."),
        d("viewer.invert_zoom", Bool, json!(false),
          "Invert zoom",
          "With navigation style `custom`: rolling the wheel away from you zooms out."),
        d("viewer.probe_cursor", String, json!("crosshair"),
          "Probe cursor",
          "Pointer shown over a 3D or 2D view while it reads the value under it. Dragging always shows the grabbing hand.")
            .choices(&["crosshair", "arrow", "cell", "hand"]),
        // -- editor ---------------------------------------------------------------------------
        d("editor.theme", String, json!("follow"),
          "Editor theme",
          "`follow`: light or dark with the app. `light` or `dark`: always that one.")
            .choices(&["follow", "light", "dark"]),
        d("editor.syntax", String, json!("default"),
          "Syntax colours",
          "`default`: the app's palette. `vivid`: stronger colours. `quiet`: keys and strings only; everything else in the text colour.")
            .choices(&["default", "vivid", "quiet"]),
        d("editor.font_size", Int, json!(13),
          "Font size (px)",
          "Size of the editor's text at 100% zoom.")
            .range(9.0, 28.0),
        d("editor.line_height", Float, json!(1.45),
          "Line height",
          "Height of a row as a multiple of the font size.")
            .range(1.1, 2.2),
        d("editor.tab_size", Int, json!(2),
          "Tab size",
          "Cells a tab stop spans, and spaces one press of Tab inserts.")
            .range(1.0, 8.0),
        d("editor.insert_spaces", Bool, json!(true),
          "Indent with spaces",
          "Tab inserts spaces up to the next tab stop. Off: a tab character."),
        d("editor.wrap", Bool, json!(true),
          "Wrap lines",
          "Long lines continue on the next row instead of scrolling sideways. A node's own Wrap lines setting wins."),
        d("editor.line_numbers", Bool, json!(true),
          "Line numbers",
          "Show the number of each line beside it."),
        d("editor.minimap", Bool, json!(true),
          "Minimap",
          "An outline of the whole file beside the scrollbar, when the editor is wide enough for it."),
        d("editor.current_line", Bool, json!(true),
          "Highlight the current line",
          "Tint the row the caret is on."),
        d("editor.cursor_style", String, json!("bar"),
          "Cursor",
          "Shape of the caret.")
            .choices(&["bar", "block", "underline"]),
        d("editor.cursor_blink", Bool, json!(true),
          "Blinking cursor",
          "Off: the caret is always shown."),
        d("editor.auto_close", Bool, json!(true),
          "Close brackets and quotes",
          "Typing an opening bracket or quote inserts its pair."),
        d("editor.format_on_save", Bool, json!(false),
          "Format on save",
          "Saving a JSON, YAML or TOML file formats it first. Comments and values are kept; a file with a syntax error is saved as it is."),
        // -- notifications --------------------------------------------------------------------
        d("notifications.position", String, json!("top-right"),
          "Toast position",
          "Corner of the window where toasts appear. They never cover the top bar or a board's toolbar.")
            .choices(&["top-right", "top-left", "bottom-right", "bottom-left", "top-centre"]),
        d("notifications.duration_secs", Int, json!(6),
          "Toast duration (s)",
          "How long an information or success toast stays. Warnings and errors stay until dismissed.")
            .range(2.0, 60.0),
        d("notifications.max_visible", Int, json!(4),
          "Toasts shown at once",
          "More than this collapse into a count that opens the notification centre.")
            .range(1.0, 8.0),
        d("notifications.sound", Bool, json!(false),
          "Sound",
          "Play a short sound with a warning or an error toast."),
        d("notifications.do_not_disturb", Bool, json!(false),
          "Do not disturb",
          "Show no toasts; everything still arrives in the notification centre."),
        d("notifications.scope", String, json!("projects"),
          "Whose events",
          "`mine`: only what you started. `projects`: everything in the projects you may read.")
            .choices(&["mine", "projects"]),
        d("notifications.os", Bool, json!(false),
          "System notifications",
          "Also show a notification of the operating system (the browser asks for permission) while the window is not in front."),
        d("notifications.types.runs", String, json!("toast"),
          "Runs",
          "A pipeline run or a training run finished or failed. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.steps", String, json!("toast"),
          "Pipeline steps",
          "A step of a pipeline run failed. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.jobs", String, json!("toast"),
          "Jobs",
          "A job failed, or has been queued for a long time. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.datasets", String, json!("toast"),
          "Datasets",
          "A dataset import or a data-preparation step finished. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.evaluations", String, json!("toast"),
          "Evaluations and reports",
          "An evaluation finished, a report is ready, or a quality gate refused a model. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.models", String, json!("toast"),
          "Models",
          "A model version changed stage or was deployed. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.approvals", String, json!("toast"),
          "Approvals",
          "A data-preparation step or an AI agent's plan waits for a decision, or was approved or refused. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.compute", String, json!("toast"),
          "Compute",
          "A worker went offline, a pool has no capacity, or a cloud pod is about to be released. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.cost", String, json!("toast"),
          "Cost",
          "Spending reached a threshold. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.credentials", String, json!("toast"),
          "Credentials",
          "A credential expires soon or failed its test. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.connection", String, json!("toast"),
          "Connection",
          "The app lost its server or reached it again. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        d("notifications.types.updates", String, json!("toast"),
          "Updates",
          "A newer version of Frontier is available. `toast`: a toast and an entry in the notification centre. `centre`: the entry only. `off`: nothing.")
            .choices(&["toast", "centre", "off"]),
        // -- server ---------------------------------------------------------------------------
        d("server.bind", String, json!("127.0.0.1:8787"),
          "Listen address",
          "Address and port the control plane listens on.")
            .scope(Scope::System).restart().alias(&["FRONTIER_BIND"]),
        d("server.db_path", Path, json!("./frontier.db"),
          "Database file",
          "SQLite database of the control plane.")
            .scope(Scope::System).restart().alias(&["FRONTIER_DB"]),
        d("server.data_dir", Path, json!("./frontier-data"),
          "Data directory",
          "Artifacts, job logs and hub pulls of the control plane.")
            .scope(Scope::System).restart().alias(&["FRONTIER_DATA_DIR"]),
        d("server.cors_origins", List, json!([]),
          "Additional browser origins",
          "Origins allowed to call the API besides localhost and the desktop app (for example https://frontier.example.com).")
            .scope(Scope::System).restart(),
        d("server.allowed_hosts", List, json!([]),
          "Accepted Host names",
          "Host names this server answers to besides localhost and the hosts of `server.cors_origins` (the public DNS name behind a proxy, a pod's proxy host). Requests with another `Host` are refused, which is what stops DNS rebinding. `*` accepts any host: only with authentication on.")
            .scope(Scope::System).restart().alias(&["FRONTIER_ALLOWED_HOSTS"]),
        d("server.inject_credentials", Bool, json!(true),
          "Give credentials to jobs",
          "Hand credentials stored on the server to the jobs that ask for them when a worker claims the job. When off, jobs only see what the worker's own environment provides.")
            .scope(Scope::Server),
        // -- auth -----------------------------------------------------------------------------
        d("auth.mode", String, json!("none"),
          "Authentication mode",
          "`none`: single-user, every request acts as the local administrator (only on a loopback address). `token`: API tokens. `oidc`: people sign in through an OpenID Connect provider; the CLI, workers and CI use API tokens.")
            .scope(Scope::System).restart().choices(&["none", "token", "oidc"]),
        d("auth.allow_insecure", Bool, json!(false),
          "Allow single-user mode on the network",
          "Let the server start with `auth.mode = \"none\"` on an address other machines can reach. Everyone who can connect is then an administrator.")
            .scope(Scope::System).restart(),
        d("auth.local_token", Bool, json!(true),
          "Require the local token in single-user mode",
          "With `auth.mode = \"none\"`, every request that changes something or touches credentials must carry the token the server writes at start-up to `<data dir>/local-token` and `~/.frontier/servers/<port>.token` (owner-readable only). The CLI, the SDK and workers on this machine read it by themselves; the browser app obtains it from `POST /api/v1/auth/local-session`. Turning it off lets every local process and every allowed web origin act as administrator.")
            .scope(Scope::System).restart(),
        d("auth.allow_plain_http", Bool, json!(false),
          "Allow a network address without TLS",
          "Let the server listen on an address other machines can reach although `auth.public_url` is not an https URL. Set it when TLS ends at a reverse proxy you have not described in `auth.public_url`, or on a network you trust with tokens in clear.")
            .scope(Scope::System).restart(),
        d("auth.allow_self_approval", Bool, json!(false),
          "Allow approving one's own plans",
          "Let the person who submitted a data-preparation run or started an agent session also approve it. Off: an approval is a second person's decision (four-eyes); on, for teams with a single reviewer.")
            .scope(Scope::Server),
        d("auth.session_ttl_hours", Int, json!(12),
          "Session lifetime (hours)",
          "How long a browser session stays valid after sign-in.")
            .scope(Scope::System).range(1.0, 720.0),
        d("auth.token_ttl_days", Int, json!(90),
          "Default API token lifetime (days)",
          "Lifetime of a new API token when none is asked for; 0 means it does not expire.")
            .scope(Scope::System).range(0.0, 3650.0),
        d("auth.token_max_ttl_days", Int, json!(0),
          "Longest API token lifetime (days)",
          "Upper bound for the lifetime of tokens people create for themselves; 0 means no bound. Service-account tokens issued by an administrator are not bound by it.")
            .scope(Scope::System).range(0.0, 3650.0),
        d("auth.public_url", Url, json!(""),
          "Public URL of the control plane",
          "The address browsers reach the server at (for example https://frontier.example.com); the OIDC redirect URI is `<public_url>/api/v1/auth/oidc/callback`. Empty: derived from the listen address.")
            .scope(Scope::System).restart(),
        d("auth.trust_forwarded_for", Bool, json!(false),
          "Trust X-Forwarded-For",
          "Record the client address a reverse proxy reports instead of the proxy's own. Enable only behind a proxy that overwrites the header.")
            .scope(Scope::System).restart(),
        d("auth.audit_retention_days", Int, json!(0),
          "Audit log retention (days)",
          "Audit records older than this are removed at start-up and daily; the chain stays verifiable from a recorded anchor. 0 keeps everything.")
            .scope(Scope::System).min(0.0),
        d("auth.oidc.issuer", Url, json!(""),
          "OIDC issuer",
          "Issuer URL of the identity provider; `<issuer>/.well-known/openid-configuration` must exist.")
            .scope(Scope::System).restart(),
        d("auth.oidc.client_id", String, json!(""),
          "OIDC client id",
          "Client id registered for Frontier at the provider. The client secret, if the provider issues one, is the credential `frontier-oidc` (or `FRONTIER_OIDC_CLIENT_SECRET`), never a setting.")
            .scope(Scope::System).restart(),
        d("auth.oidc.scopes", List, json!(["openid", "profile", "email"]),
          "OIDC scopes",
          "Scopes requested at sign-in; add the one that makes the provider include groups (often `groups`).")
            .scope(Scope::System).restart(),
        d("auth.oidc.username_claim", String, json!("preferred_username"),
          "Login name claim",
          "Claim used as the Frontier login name; falls back to `email`, then `sub`.")
            .scope(Scope::System).restart(),
        d("auth.oidc.groups_claim", String, json!("groups"),
          "Groups claim",
          "Claim listing the user's groups (an array or a space-separated string; dots descend, as in `realm_access.roles`).")
            .scope(Scope::System).restart(),
        d("auth.oidc.role_mapping", Table, json!({}),
          "Group to role mapping",
          "Group name to `admin`, `maintainer`, `member`, `viewer` or `auditor` (organisation role), or `project:<project name>:<role>`. The highest matching role applies and is re-evaluated at every sign-in.")
            .scope(Scope::System).restart(),
        d("auth.oidc.default_role", String, json!(""),
          "Role without a mapped group",
          "Organisation role of a user none of whose groups is mapped; empty refuses the sign-in.")
            .scope(Scope::System).restart().choices(&["", "viewer", "member", "maintainer", "admin", "auditor"]),
        // -- worker ----------------------------------------------------------------------------
        d("worker.backend", String, json!("local"),
          "Backend",
          "Which jobs this worker claims.")
            .scope(Scope::System).alias(&["FRONTIER_BACKEND"]),
        d("worker.labels", List, json!([]),
          "Labels",
          "Labels this worker advertises (`gpu=h100`, `site=eu`); a job is claimed only by a worker with all of its labels.")
            .scope(Scope::System).alias(&["FRONTIER_LABELS"]),
        d("worker.heartbeat_secs", Int, json!(10),
          "Heartbeat interval (seconds)",
          "How often the worker reports to the control plane and asks for work.")
            .scope(Scope::System).range(1.0, 3600.0).alias(&["FRONTIER_HEARTBEAT"]),
        d("worker.workdir", Path, json!("."),
          "Working directory",
          "Directory jobs run in when they do not name one.")
            .scope(Scope::System).alias(&["FRONTIER_WORKDIR"]),
        d("worker.use_docker", Bool, json!(false),
          "Run jobs in containers",
          "Run a job's image with Docker instead of as a bare process.")
            .scope(Scope::System).alias(&["FRONTIER_USE_DOCKER"]),
        d("worker.job_env_passthrough", List, json!([]),
          "Worker variables jobs may see",
          "Names of environment variables of the worker process that jobs inherit, besides the basic ones (PATH, HOME, locale, temporary directory, CUDA/NVIDIA, Python and proxy variables). A job never inherits the worker's token or any other variable by default: what it needs comes with the job.")
            .scope(Scope::System),
        d("worker.job_user", String, json!(""),
          "User that jobs run as",
          "Operating-system user jobs are started as when the worker runs as root (containers, system services), so a job cannot read the worker's files or signal it. Empty runs jobs as the worker's own user.")
            .scope(Scope::System),
        d("worker.term_grace_secs", Int, json!(300),
          "Termination grace (seconds)",
          "Time a cancelled job gets between SIGTERM and SIGKILL. The job uses it to stop its step and to pack and upload what it produced (checkpoints, metrics, evaluation files).")
            .scope(Scope::System).range(0.0, 86400.0).alias(&["FRONTIER_TERM_GRACE"]),
        // -- limits ---------------------------------------------------------------------------
        d("limits.max_request_bytes", Bytes, json!(268_435_456u64),
          "Request size limit",
          "Largest JSON request (metric batches, job logs) the control plane accepts. Artifact uploads are streamed and not limited by this.")
            .scope(Scope::System).restart().min(1024.0),
        d("limits.max_artifact_bytes", Bytes, json!(53_687_091_200u64),
          "Largest artifact upload",
          "Upper bound on one uploaded run artifact (checkpoints, prediction stores, model packages). A larger upload is cut off and removed.")
            .scope(Scope::System).restart().min(1024.0),
        d("limits.max_run_artifact_bytes", Bytes, json!(536_870_912_000u64),
          "Artifact space per run",
          "Upper bound on the total size of one run's artifacts; an upload that would exceed it is refused. 0 means no bound.")
            .scope(Scope::System).restart().min(0.0),
        d("limits.min_free_disk_bytes", Bytes, json!(1_073_741_824u64),
          "Free disk space to keep",
          "Uploads are refused while the data directory's file system has less free space than this, so the database and job logs can still be written. 0 turns the check off.")
            .scope(Scope::System).restart().min(0.0),
        d("limits.request_timeout_secs", Int, json!(300),
          "Request timeout (seconds)",
          "A request whose handler has not answered after this long is ended with 504. Event streams and downloads are not cut (they answer at once and then stream); artifact uploads are exempt. 0 means no timeout.")
            .scope(Scope::System).restart().min(0.0),
        d("limits.max_event_streams_per_client", Int, json!(32),
          "Event streams per client",
          "Live event streams (run events, agent sessions, model events) one caller may hold open at a time; further ones are refused with 429. 0 means no bound.")
            .scope(Scope::System).restart().min(0.0),
        d("limits.max_concurrent_requests", Int, json!(512),
          "Concurrent requests",
          "Requests the control plane works on at once, open event streams included; further ones wait.")
            .scope(Scope::System).restart().range(8.0, 65536.0),
        d("limits.failed_auth_per_minute", Int, json!(30),
          "Rejected sign-ins per minute and address",
          "After this many rejected tokens, sessions or sign-ins from one address within a minute, further rejected attempts from it are answered 429 and no longer written to the audit log until the minute has passed. Valid credentials keep working. 0 turns the limit off.")
            .scope(Scope::System).restart().min(0.0),
        d("limits.max_array_bytes", Bytes, json!(4_294_967_296u64),
          "Largest array read at once",
          "Upper bound on the memory one read of a dataset or prediction array may need. A store whose metadata declares more is refused instead of loaded, so a hostile or corrupt upload cannot exhaust the server's memory.")
            .scope(Scope::System).restart().min(1_048_576.0),
        // -- policy ---------------------------------------------------------------------------
        d("policy.allow_cloud_targets", List, json!(TARGETS),
          "Allowed compute targets",
          "Targets runs may be sent to. Remove `runpod` and `anyscale` to keep every run on your own machines.")
            .scope(Scope::Server).choices(TARGETS),
        d("policy.allow_public_hub", Bool, json!(true),
          "Allow public dataset downloads",
          "When off, `frontier hub pull` and the app refuse to download from public hosts; only catalogue entries served from `hub.extra_catalogs` on local paths remain available.")
            .scope(Scope::Server),
        d("policy.allowed_dataset_licences", List, json!(["any"]),
          "Allowed dataset licences",
          "Which hub datasets may be pulled: `any`, `commercial` (licences that permit commercial use), or SPDX identifiers (for example CC-BY-4.0). A dataset must match at least one entry.")
            .scope(Scope::Server),
        d("policy.max_cost_per_run", Float, json!(0.0),
          "Cost ceiling per run (USD)",
          "Upper bound for the cost ceiling of any cloud run or sweep. 0 means no organisation-wide ceiling.")
            .scope(Scope::Server).min(0.0),
        d("policy.allow_plugin_changes", Bool, json!(true),
          "Allow plugin changes",
          "When off, the set of plugins is frozen: nobody can install, uninstall, enable or disable a plugin or deploy an exporter from the CLI or the app. Administrators change plugins by changing the installation.")
            .scope(Scope::Server),
        d("policy.plugin_sources", List, json!(["bundled", "pypi", "index", "wheel_dir"]),
          "Allowed plugin sources",
          "Where plugins may be installed from: `bundled` (shipped with the product), `pypi` (the official index), `index` (the configured `plugins.index_url`), `wheel_dir` (the configured wheel directory), a URL or path prefix, or `any`. The default is the official index plus what an administrator configured; a path, wheel or URL named on a command line needs its prefix listed here (or `any`).")
            .scope(Scope::Server),
        d("policy.compute_allowed_pools", List, json!(["any"]),
          "Allowed compute pools",
          "Pools a run or job may ask for: `any`, or pool names. A job that names another pool is refused; `auto` always resolves inside the allowed pools.")
            .scope(Scope::Server),
        d("policy.compute_max_gpus_per_run", Int, json!(0),
          "GPUs per run (ceiling)",
          "Largest number of GPUs (over all nodes) one run or job may hold. 0 means no organisation-wide ceiling.")
            .scope(Scope::Server).min(0.0),
        // -- policy.ai: the agent harness and the judge (`[policy.ai]`, frontier_agent.policy) --
        d("policy.ai.allowed_providers", List, json!(["local"]),
          "Allowed model providers",
          "Provider ids an agent session or a judge may use: `local` (covers `ollama`, `vllm`, `llamacpp`, `rules`, `nli`), `anthropic`, `openai`, `typesafe`, or `any`.")
            .scope(Scope::Server).choices(AI_PROVIDERS),
        d("policy.ai.data_leaves_site", Bool, json!(false),
          "Allow data to leave the site",
          "When off, every hosted model provider (anthropic, openai, typesafe) is refused whatever `allowed_providers` says: plan and preview summaries would be sent off-site.")
            .scope(Scope::Server),
        d("policy.ai.autonomous_op_classes", List, json!([]),
          "Op classes an agent may run unattended",
          "Operation classes (`prep.fields`, `prep.samples.drop`, `all`) an agent may `run` without a person's approval. Empty means every run needs an approval.")
            .scope(Scope::Server),
        // -- policy.settings: who may change what the server reads when it starts --
        d("policy.settings.edit_startup", String, json!("local"),
          "Start-up settings from the app",
          "Who may change the settings a server reads when it starts (listen address, sign-in mode, limits, the secret store) through the API, the app and `frontier config set --on-server`, and restart it from there. `local`: only in single-user mode from this machine, written to the server's own config file. `admin`: any administrator who is signed in. `off`: only by editing the config file.")
            .scope(Scope::Server).choices(&["local", "admin", "off"]),
        // -- policy.inference: what an inference may tell other software --
        d("policy.inference.webhooks", Bool, json!(false),
          "Allow inference webhooks",
          "When on, an inference may send a signed POST to a URL when its predictions are ready (`notify` in the API, \"Notify URL\" on an Inference node). The request carries ids and links, never arrays.")
            .scope(Scope::Server),
        d("policy.inference.webhook_hosts", List, json!([]),
          "Hosts an inference may notify",
          "Host names a notify URL may point at. Empty means any host, once webhooks are allowed.")
            .scope(Scope::Server),
        d("policy.ai.judge_backend", String, json!("auto"),
          "Judge backend",
          "`auto` picks TypeSafe when allowed and configured, else the local model when its endpoint answers, else rules; or name one of `local`, `rules`, `nli`, `typesafe`.")
            .scope(Scope::User).choices(&["auto", "local", "rules", "nli", "typesafe"]),
        d("policy.ai.local_endpoint", Url, json!("http://localhost:11434"),
          "Local model endpoint",
          "The local model server (Ollama native API; an endpoint ending in `/v1` is treated as OpenAI-compatible: vLLM, llama.cpp server).")
            .scope(Scope::User),
        d("policy.ai.local_endpoints", List, json!([]),
          "Hosts that count as local model servers",
          "Host names (or `host:port`) besides this machine that the provider `local` may reach: a model server inside the site's network. Anything else is treated as data leaving the site. Read from the system file and the control plane only.")
            .scope(Scope::Server),
        d("policy.ai.local_model", String, json!(""),
          "Local model",
          "Model tag on the local endpoint used for judgments and local agent sessions.")
            .scope(Scope::User),
        d("policy.ai.hosted_provider", String, json!("anthropic"),
          "Hosted provider",
          "The hosted provider for `--hosted` sessions (needs `data_leaves_site` and a credential: `frontier auth login anthropic`).")
            .scope(Scope::User).choices(HOSTED_AI_PROVIDERS),
        d("policy.ai.hosted_model", String, json!(""),
          "Hosted model",
          "Model id at the hosted provider for `--hosted` sessions.")
            .scope(Scope::User),
        d("policy.ai.max_tool_calls", Int, json!(40),
          "Tool calls per session",
          "Budget of tool calls one agent session may make.")
            .scope(Scope::User).range(1.0, 10_000.0),
        d("policy.ai.session_dir", Path, json!("~/.frontier/agent-sessions"),
          "Session record directory",
          "Where session records (`<id>.jsonl`: every tool call, preview, judgment and approval) are written.")
            .scope(Scope::User),
    ]
}

static REGISTRY: LazyLock<Vec<SettingDef>> = LazyLock::new(build);

/// Every setting, in display order.
pub fn registry() -> &'static [SettingDef] {
    &REGISTRY
}

/// Look a setting up by key.
pub fn find(key: &str) -> Option<&'static SettingDef> {
    REGISTRY.iter().find(|d| d.key == key)
}

fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Keys closest to `key` (for "did you mean" in error messages).
pub fn suggest(key: &str) -> Vec<&'static str> {
    let name = key.rsplit('.').next().unwrap_or(key);
    let mut scored: Vec<(usize, &'static str)> = REGISTRY
        .iter()
        .filter_map(|d| {
            let whole = distance(key, &d.key);
            let by_name = distance(name, d.name());
            // `policy.allow_hub` -> `policy.allow_public_hub`: same section, words all present
            let words = d
                .key
                .starts_with(&format!("{}.", key.split('.').next().unwrap_or("")))
                && name.split('_').all(|w| d.name().split('_').any(|c| c == w));
            let score = whole
                .min(by_name + 1)
                .min(if words { 2 } else { usize::MAX });
            (score <= 3 || d.key.starts_with(key)).then_some((score, d.key.as_str()))
        })
        .collect();
    scored.sort();
    scored.into_iter().take(3).map(|(_, k)| k).collect()
}

/// `value` with every object's keys in sorted order, so exported files are byte-identical
/// whatever `serde_json` features the build enables.
pub fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|k| (k.clone(), canonical(&map[k])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// The flat list export (`{"version": 1, "sections": [...], "settings": [...]}`).
pub fn flat_json() -> Value {
    json!({
        "version": 1,
        "sections": SECTIONS.iter().map(|(id, title, description)| json!({
            "id": id, "title": title, "description": description,
        })).collect::<Vec<_>>(),
        "settings": registry(),
    })
}

/// JSON Schema (draft 2020-12) of a config file: one object per section.
pub fn json_schema() -> Value {
    let mut sections = serde_json::Map::new();
    for (id, title, description) in SECTIONS {
        let mut props = serde_json::Map::new();
        for def in registry().iter().filter(|d| d.section_id() == *id) {
            let mut p = match def.ty {
                SettingType::String | SettingType::Path | SettingType::Url => {
                    json!({"type": "string"})
                }
                SettingType::Int => json!({"type": "integer"}),
                SettingType::Float => json!({"type": "number"}),
                SettingType::Bool => json!({"type": "boolean"}),
                SettingType::List => json!({"type": "array", "items": {"type": "string"}}),
                SettingType::Bytes => json!({"type": ["integer", "string"]}),
                SettingType::Table => json!({"type": "object"}),
            };
            let obj = p.as_object_mut().expect("object literal");
            obj.insert("title".into(), json!(def.title));
            obj.insert("description".into(), json!(def.description));
            obj.insert("default".into(), def.default.clone());
            if let Some(choices) = &def.choices {
                if def.ty == SettingType::List {
                    obj.insert("items".into(), json!({"type": "string", "enum": choices}));
                } else {
                    obj.insert("enum".into(), json!(choices));
                }
            }
            if let Some(min) = def.min {
                obj.insert("minimum".into(), json!(min));
            }
            if let Some(max) = def.max {
                obj.insert("maximum".into(), json!(max));
            }
            match def.name().split_once('.') {
                // `policy.ai.allowed_providers`: an object property `ai` of the section
                Some((sub, leaf)) => {
                    let entry = props.entry(sub.to_string()).or_insert_with(|| {
                        json!({"type": "object", "additionalProperties": false, "properties": {}})
                    });
                    if let Some(inner) = entry
                        .get_mut("properties")
                        .and_then(serde_json::Value::as_object_mut)
                    {
                        inner.insert(leaf.to_string(), p);
                    }
                }
                None => {
                    props.insert(def.name().to_string(), p);
                }
            }
        }
        sections.insert(
            (*id).to_string(),
            json!({
                "type": "object", "title": title, "description": description,
                "additionalProperties": false, "properties": props,
            }),
        );
    }
    sections.insert(
        "lock".into(),
        json!({
            "type": "object",
            "title": "Locks",
            "description": "System file only: keys lower-trust layers may not override. `\"section.key\" = \"reason\"`, `\"section.*\"` for a whole section.",
        }),
    );
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://dimensionlab.org/schemas/frontier-config.schema.json",
        "title": "Frontier configuration file",
        "type": "object",
        "additionalProperties": false,
        "properties": sections,
    })
}

fn md_value(v: &Value) -> String {
    match v {
        Value::String(s) if s.is_empty() => "(empty)".into(),
        Value::String(s) => format!("`{s}`"),
        Value::Array(a) if a.is_empty() => "`[]`".into(),
        other => format!("`{other}`"),
    }
}

/// The generated settings reference (part 2 of the configuration guide).
pub fn markdown_reference() -> String {
    let mut out = String::new();
    for (id, title, description) in SECTIONS {
        let defs: Vec<&SettingDef> = registry()
            .iter()
            .filter(|d| d.section_id() == *id)
            .collect();
        if defs.is_empty() {
            continue;
        }
        out.push_str(&format!("### {title} (`[{id}]`)\n\n{description}\n\n"));
        out.push_str("| Key | Type | Default | Scope | Edited by | Environment | Description |\n");
        out.push_str("|-----|------|---------|-------|-----------|-------------|-------------|\n");
        for def in defs {
            let mut ty = def.ty.as_str().to_string();
            if let Some(choices) = &def.choices {
                ty.push_str(&format!(": {}", choices.join(" \\| ")));
            }
            let mut desc = def.description.replace('|', "\\|");
            if def.restart_required {
                desc.push_str(" Needs a restart.");
            }
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                def.key,
                ty,
                md_value(&def.default),
                def.scope.as_str(),
                match def.editable_by {
                    EditableBy::User => "user",
                    EditableBy::Admin => "admin",
                },
                def.env
                    .iter()
                    .map(|e| format!("`{e}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                desc,
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn keys_are_unique_two_level_and_in_a_known_section() {
        let mut seen = BTreeSet::new();
        for def in registry() {
            assert!(seen.insert(&def.key), "duplicate key {}", def.key);
            assert!(
                matches!(def.key.matches('.').count(), 1 | 2),
                "{} is not section.key or section.sub.key",
                def.key
            );
            if let Some((sub, _)) = def.name().split_once('.') {
                // a sub-table name must not collide with a plain key of the section
                assert!(
                    !registry()
                        .iter()
                        .any(|d| d.key == format!("{}.{sub}", def.section_id())),
                    "{}: `{sub}` is both a key and a sub-table",
                    def.key
                );
            }
            assert_ne!(def.section, "Other", "{} has no section", def.key);
            assert!(!def.secret, "{}: secrets are credentials", def.key);
            assert!(!def.title.is_empty() && !def.description.is_empty());
        }
    }

    #[test]
    fn env_names_do_not_collide() {
        let mut seen = BTreeSet::new();
        for def in registry() {
            for env in &def.env {
                assert!(seen.insert(env.clone()), "{env} sets two settings");
            }
        }
        assert_eq!(
            canonical_env("storage.datasets_dir"),
            "FRONTIER_STORAGE__DATASETS_DIR"
        );
    }

    #[test]
    fn defaults_validate_against_their_own_definition() {
        for def in registry() {
            crate::value::coerce(def, &def.default)
                .unwrap_or_else(|e| panic!("default of {}: {e}", def.key));
        }
    }

    #[test]
    fn schema_exports_cover_every_setting() {
        let flat = flat_json();
        assert_eq!(flat["settings"].as_array().unwrap().len(), registry().len());
        let first = &flat["settings"][0];
        for field in [
            "key",
            "type",
            "default",
            "title",
            "description",
            "section",
            "scope",
            "secret",
            "restart_required",
            "enum",
            "min",
            "max",
            "editable_by",
            "since",
        ] {
            assert!(first.get(field).is_some(), "missing {field}");
        }
        let schema = json_schema();
        assert_eq!(
            schema["properties"]["policy"]["properties"]["allow_public_hub"]["type"],
            "boolean"
        );
        assert!(markdown_reference().contains("`policy.allowed_dataset_licences`"));
    }
}
