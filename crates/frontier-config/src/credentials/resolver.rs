// SPDX-License-Identifier: Apache-2.0
//! Finding a credential when it is needed.
//!
//! Resolution order per field:
//!
//! 1. **job binding**: the launcher (the control plane at job-claim time, or the CLI when it
//!    starts a tool) put the value into this process's environment and listed the provider
//!    in `FRONTIER_CREDENTIALS_BOUND`;
//! 2. the **local secret store** selected by `secrets.backend` (keychain or file);
//! 3. the provider's **environment fallbacks** (`HF_TOKEN`, ...), for CI and headless use.
//!
//! The control plane's own store sits between 1 and 2 conceptually, but its values never
//! travel to a client: the server resolves them itself and hands them to jobs (step 1).

use super::store::{self, EnvStore, SecretStore};
use super::{AuthField, AuthKind, AuthProvider, Registry};
use crate::loader::Config;
use crate::{Error, Result, edit};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Variable listing the provider ids whose values were injected into the environment.
pub const BOUND_ENV: &str = "FRONTIER_CREDENTIALS_BOUND";
/// File in the Frontier home with the result of the last test per provider (no secrets).
pub const STATE_FILE: &str = "auth-state.json";

/// A resolved value and where it came from. `Debug` never shows the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Resolved {
    pub value: String,
    /// `job`, `keychain`, `file`, `memory` or `env:<VARIABLE>`.
    pub source: String,
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Resolved {{ value: ***, source: {:?} }}", self.source)
    }
}

/// Outcome of the last `test` of a provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestRecord {
    pub at: DateTime<Utc>,
    pub ok: bool,
    #[serde(default)]
    pub detail: String,
}

/// `last_test` of a [`CredentialStatus`] on the wire.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LastTest {
    pub at: DateTime<Utc>,
    pub ok: bool,
    /// Who the provider says the credential belongs to, when the test learned it.
    pub identity: Option<String>,
    pub detail: String,
}

/// `"keychain"` / `"env:HF_TOKEN"` as `{store, detail}`; `None` as `null`.
pub fn source_json(source: Option<&str>) -> serde_json::Value {
    match source {
        None => serde_json::Value::Null,
        Some(s) => match s.split_once(':') {
            Some((store, detail)) => serde_json::json!({ "store": store, "detail": detail }),
            None => serde_json::json!({ "store": s, "detail": null }),
        },
    }
}

fn source_wire<S: serde::Serializer>(
    source: &Option<String>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serde::Serialize::serialize(&source_json(source.as_deref()), serializer)
}

/// What `frontier auth status`, `doctor` and the credentials API report. Never a value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CredentialStatus {
    pub id: String,
    pub title: String,
    pub category: String,
    pub kind: AuthKind,
    pub fields: Vec<FieldStatus>,
    /// Every required field has a value.
    pub configured: bool,
    /// Where the primary field's value comes from (`keychain`, `file`, `env:HF_TOKEN`, `job`).
    /// Serialised as `null | {store, detail}` (`{"store": "env", "detail": "HF_TOKEN"}`),
    /// the shape the credentials API uses.
    #[serde(serialize_with = "source_wire")]
    pub source: Option<String>,
    /// The last connection test as one object (`{at, ok, identity, detail}`), as in the
    /// credentials API. The flat fields below say the same and stay for older readers.
    pub last_test: Option<LastTest>,
    pub last_tested: Option<DateTime<Utc>>,
    pub last_test_ok: Option<bool>,
    pub last_test_detail: Option<String>,
    pub env: Vec<String>,
    pub help_url: Option<String>,
    pub scopes_hint: Option<String>,
    pub testable: bool,
    pub declared_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldStatus {
    pub name: String,
    pub title: String,
    pub secret: bool,
    pub required: bool,
    pub configured: bool,
    #[serde(serialize_with = "source_wire")]
    pub source: Option<String>,
    pub env: Vec<String>,
    /// The value of a non-secret field (a user name, a region); always `None` for secrets.
    pub value: Option<String>,
}

pub struct Resolver {
    registry: Registry,
    store: Box<dyn SecretStore>,
    env: BTreeMap<String, String>,
    bound: BTreeSet<String>,
    state_path: Option<PathBuf>,
}

impl Resolver {
    /// The resolver for this process: registry from the Frontier home, store from
    /// `secrets.backend`, environment from the loaded configuration.
    pub fn from_config(config: &Config) -> Result<Self> {
        let registry = Registry::load(&config.paths.home);
        let store = store::open(config, &registry)?;
        Ok(Self::new(registry, store, config.env().clone())
            .with_state_file(config.paths.home.join(STATE_FILE)))
    }

    pub fn new(
        registry: Registry,
        store: Box<dyn SecretStore>,
        env: BTreeMap<String, String>,
    ) -> Self {
        let bound = env
            .get(BOUND_ENV)
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            registry,
            store,
            env,
            bound,
            state_path: None,
        }
    }

    pub fn with_state_file(mut self, path: PathBuf) -> Self {
        self.state_path = Some(path);
        self
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn store(&self) -> &dyn SecretStore {
        self.store.as_ref()
    }

    fn provider(&self, id: &str) -> Result<&AuthProvider> {
        self.registry.get(id).ok_or_else(|| Error::UnknownProvider {
            id: id.to_string(),
            known: self.registry.ids().iter().map(|s| s.to_string()).collect(),
        })
    }

    fn env_value<'a>(&'a self, field: &'a AuthField) -> Option<(&'a str, &'a str)> {
        field.env.iter().find_map(|name| {
            let v = self.env.get(name)?.trim();
            (!v.is_empty()).then_some((name.as_str(), v))
        })
    }

    fn resolve_field(&self, provider: &AuthProvider, field: &AuthField) -> Option<Resolved> {
        if self.bound.contains(&provider.id)
            && let Some((_, v)) = self.env_value(field)
        {
            return Some(Resolved {
                value: v.to_string(),
                source: "job".into(),
            });
        }
        if self.store.name() != "env" {
            match self.store.get(&provider.id, &field.name) {
                Ok(Some(v)) if !v.trim().is_empty() => {
                    return Some(Resolved {
                        value: v.trim().to_string(),
                        source: self.store.name().to_string(),
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    // once per process: a status listing asks for dozens of fields
                    static WARNED: std::sync::Once = std::sync::Once::new();
                    WARNED.call_once(|| {
                        tracing::warn!(store = self.store.name(), error = %e, "secret store unavailable; using environment fallbacks only")
                    });
                }
            }
        }
        self.env_value(field).map(|(name, v)| Resolved {
            value: v.to_string(),
            source: format!("env:{name}"),
        })
    }

    /// The value of `provider/field`, if any source has one.
    pub fn get(&self, provider: &str, field: &str) -> Result<Option<Resolved>> {
        let p = self.provider(provider)?;
        let f = p.field(field).ok_or_else(|| {
            Error::Store(format!("credential `{provider}` has no field `{field}`"))
        })?;
        Ok(self.resolve_field(p, f))
    }

    /// The primary secret of `provider` (its token or API key), or an error that tells the
    /// user how to provide it.
    pub fn require(&self, provider: &str) -> Result<String> {
        let p = self.provider(provider)?;
        let f = p
            .primary()
            .ok_or_else(|| Error::Store(format!("credential `{provider}` declares no field")))?;
        match self.resolve_field(p, f) {
            Some(r) => Ok(r.value),
            None => Err(self.missing(p)),
        }
    }

    /// The error for a credential that is needed and absent.
    pub fn missing(&self, p: &AuthProvider) -> Error {
        Error::MissingCredential {
            id: p.id.clone(),
            title: p.title.clone(),
            env: p.primary().map(|f| f.env.clone()).unwrap_or_default(),
            help_url: p.help_url.clone(),
        }
    }

    /// Every field of `provider` that has a value.
    pub fn values(&self, provider: &str) -> Result<BTreeMap<String, Resolved>> {
        let p = self.provider(provider)?;
        Ok(p.fields
            .iter()
            .filter_map(|f| Some((f.name.clone(), self.resolve_field(p, f)?)))
            .collect())
    }

    /// Store `values` (field -> value) for `provider`. Unknown fields are rejected, required
    /// fields must end up with a value.
    pub fn login(&self, provider: &str, values: &BTreeMap<String, String>) -> Result<()> {
        let p = self.provider(provider)?;
        for name in values.keys() {
            if p.field(name).is_none() {
                return Err(Error::Store(format!(
                    "credential `{provider}` has no field `{name}` (fields: {})",
                    p.fields
                        .iter()
                        .map(|f| f.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        for f in &p.fields {
            let given = values.get(&f.name).map(|v| v.trim()).unwrap_or_default();
            if f.required && given.is_empty() && self.resolve_field(p, f).is_none() {
                return Err(Error::Store(format!(
                    "{} needs a value for `{}` ({})",
                    p.title, f.name, f.title
                )));
            }
        }
        for (name, value) in values {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            self.store.set(&p.id, name, value)?;
        }
        self.forget_test(&p.id);
        Ok(())
    }

    /// Remove every stored field of `provider`. Returns how many entries were removed.
    pub fn logout(&self, provider: &str) -> Result<usize> {
        let p = self.provider(provider)?;
        let mut n = 0;
        for f in &p.fields {
            if self.store.delete(&p.id, &f.name)? {
                n += 1;
            }
        }
        self.forget_test(&p.id);
        Ok(n)
    }

    fn state(&self) -> BTreeMap<String, TestRecord> {
        self.state_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, state: &BTreeMap<String, TestRecord>) {
        if let Some(path) = &self.state_path
            && let Ok(text) = serde_json::to_string_pretty(state)
            && let Err(e) = edit::atomic_write(path, &text, None)
        {
            tracing::debug!(error = %e, "could not record credential test result");
        }
    }

    fn forget_test(&self, id: &str) {
        let mut state = self.state();
        if state.remove(id).is_some() {
            self.save_state(&state);
        }
    }

    /// Remember the outcome of a test (`detail` must not contain a secret; it is redacted
    /// against the provider's values regardless).
    pub fn record_test(&self, id: &str, ok: bool, detail: &str) {
        let redactor = crate::redact::Redactor::new(
            self.values(id)
                .map(|v| v.into_values().map(|r| r.value).collect::<Vec<_>>())
                .unwrap_or_default(),
        );
        let mut state = self.state();
        state.insert(
            id.to_string(),
            TestRecord {
                at: Utc::now(),
                ok,
                detail: redactor.redact(detail),
            },
        );
        self.save_state(&state);
    }

    pub fn status(&self, id: &str) -> Result<CredentialStatus> {
        let p = self.provider(id)?;
        Ok(self.status_of(p, &self.state()))
    }

    pub fn statuses(&self) -> Vec<CredentialStatus> {
        let state = self.state();
        self.registry
            .iter()
            .map(|p| self.status_of(p, &state))
            .collect()
    }

    fn status_of(
        &self,
        p: &AuthProvider,
        state: &BTreeMap<String, TestRecord>,
    ) -> CredentialStatus {
        let fields: Vec<FieldStatus> = p
            .fields
            .iter()
            .map(|f| {
                let r = self.resolve_field(p, f);
                FieldStatus {
                    name: f.name.clone(),
                    title: f.title.clone(),
                    secret: f.secret,
                    required: f.required,
                    configured: r.is_some(),
                    source: r.as_ref().map(|r| r.source.clone()),
                    env: f.env.clone(),
                    value: r.filter(|_| !f.secret).map(|r| r.value),
                }
            })
            .collect();
        let configured = !fields.is_empty() && fields.iter().all(|f| f.configured || !f.required);
        let primary = p.primary().map(|f| f.name.as_str()).unwrap_or_default();
        let source = fields
            .iter()
            .find(|f| f.name == primary)
            .and_then(|f| f.source.clone());
        let test = state.get(&p.id);
        CredentialStatus {
            id: p.id.clone(),
            title: p.title.clone(),
            category: p.category.clone(),
            kind: p.kind,
            configured,
            source,
            last_test: test.map(|t| LastTest {
                at: t.at,
                ok: t.ok,
                identity: t
                    .ok
                    .then(|| t.detail.strip_prefix("signed in as ").map(str::to_string))
                    .flatten(),
                detail: t.detail.clone(),
            }),
            last_tested: test.map(|t| t.at),
            last_test_ok: test.map(|t| t.ok),
            last_test_detail: test.map(|t| t.detail.clone()),
            env: p.fields.iter().flat_map(|f| f.env.clone()).collect(),
            help_url: p.help_url.clone(),
            scopes_hint: p.scopes_hint.clone(),
            testable: p.test_http.is_some(),
            declared_by: p.declared_by.clone(),
            fields,
        }
    }

    /// Environment for a child process that needs the given providers: each field under its
    /// first fallback variable, plus `FRONTIER_CREDENTIALS_BOUND`. Providers without a value
    /// are skipped.
    pub fn env_for<'a>(&self, ids: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut bound = Vec::new();
        for id in ids {
            let Some(p) = self.registry.get(id) else {
                continue;
            };
            let mut any = false;
            for f in &p.fields {
                if let (Some(name), Some(r)) = (f.env.first(), self.resolve_field(p, f)) {
                    out.insert(name.clone(), r.value);
                    any = true;
                }
            }
            if any {
                bound.push(id.to_string());
            }
        }
        if !bound.is_empty() {
            out.insert(BOUND_ENV.to_string(), bound.join(","));
        }
        out
    }

    /// Every secret value this resolver can see, for redacting logs.
    pub fn secrets(&self) -> Vec<String> {
        self.registry
            .iter()
            .flat_map(|p| {
                p.fields
                    .iter()
                    .filter(|f| f.secret)
                    .filter_map(|f| self.resolve_field(p, f).map(|r| r.value))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Variables in the environment that are credentials but not in the local store yet
    /// (what `frontier init` offers to import): `(provider id, field, variable)`.
    pub fn importable_from_env(&self) -> Vec<(String, String, String)> {
        let env_store = EnvStore::new(self.env.clone(), self.registry.clone());
        let mut out = Vec::new();
        for p in self.registry.iter() {
            for f in &p.fields {
                let Some((var, _)) = env_store.variable(&p.id, &f.name) else {
                    continue;
                };
                let stored = self.store.name() != "env"
                    && matches!(self.store.get(&p.id, &f.name), Ok(Some(_)));
                if !stored {
                    out.push((p.id.clone(), f.name.clone(), var.to_string()));
                }
            }
        }
        out
    }

    /// Copy the given environment variables into the local store.
    pub fn import_from_env(&self, items: &[(String, String, String)]) -> Result<usize> {
        let mut n = 0;
        for (id, field, var) in items {
            if let Some(v) = self
                .env
                .get(var)
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
            {
                self.store.set(id, field, v)?;
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::store::{FileStore, MemoryStore};

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn resolver(pairs: &[(&str, &str)]) -> Resolver {
        Resolver::new(
            Registry::builtin(),
            Box::new(MemoryStore::default()),
            env(pairs),
        )
    }

    #[test]
    fn order_is_binding_then_store_then_env() {
        // env only
        let r = resolver(&[("HF_TOKEN", "hf_env_value")]);
        let got = r.get("huggingface", "token").unwrap().unwrap();
        assert_eq!(
            (got.value.as_str(), got.source.as_str()),
            ("hf_env_value", "env:HF_TOKEN")
        );
        // the store wins over env
        r.login(
            "huggingface",
            &[("token".to_string(), "hf_store_value".to_string())].into(),
        )
        .unwrap();
        let got = r.get("huggingface", "token").unwrap().unwrap();
        assert_eq!(
            (got.value.as_str(), got.source.as_str()),
            ("hf_store_value", "memory")
        );
        // a job binding wins over the store
        let r2 = Resolver::new(
            Registry::builtin(),
            Box::new(MemoryStore::default()),
            env(&[("HF_TOKEN", "hf_job_value"), (BOUND_ENV, "huggingface")]),
        );
        r2.store
            .set("huggingface", "token", "hf_store_value")
            .unwrap();
        let got = r2.get("huggingface", "token").unwrap().unwrap();
        assert_eq!(
            (got.value.as_str(), got.source.as_str()),
            ("hf_job_value", "job")
        );
        assert_eq!(
            format!("{got:?}"),
            "Resolved { value: ***, source: \"job\" }"
        );
    }

    #[test]
    fn missing_credential_error_guides_the_user_without_values() {
        let r = resolver(&[]);
        let err = r.require("runpod").unwrap_err().to_string();
        assert!(err.contains("frontier auth login runpod"), "{err}");
        assert!(err.contains("RUNPOD_API_KEY"), "{err}");
        assert!(
            err.contains("https://www.runpod.io/console/user/settings"),
            "{err}"
        );
        let err = r.require("nope").unwrap_err().to_string();
        assert!(
            err.contains("unknown credential provider `nope`") && err.contains("huggingface"),
            "{err}"
        );
    }

    #[test]
    fn status_never_contains_secret_values() {
        let r = resolver(&[("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")]);
        r.login(
            "s3",
            &[(
                "secret_access_key".to_string(),
                "super-secret-value".to_string(),
            )]
            .into(),
        )
        .unwrap();
        r.record_test("s3", false, "HTTP 403 for key super-secret-value");
        let st = r.status("s3").unwrap();
        assert!(st.configured);
        assert_eq!(st.source.as_deref(), Some("memory"));
        let json = serde_json::to_string(&r.statuses()).unwrap();
        assert!(!json.contains("super-secret-value"), "{json}");
        assert!(json.contains("AKIAEXAMPLE"), "non-secret fields are shown");
        let hf = r.status("huggingface").unwrap();
        assert!(!hf.configured && hf.source.is_none() && hf.testable);
    }

    #[test]
    fn login_validates_and_logout_removes() {
        let dir = tempfile::tempdir().unwrap();
        let r = Resolver::new(
            Registry::builtin(),
            Box::new(FileStore::in_home(dir.path())),
            env(&[]),
        )
        .with_state_file(dir.path().join(STATE_FILE));
        let err = r
            .login(
                "s3",
                &[("access_key_id".to_string(), "AKIA".to_string())].into(),
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("needs a value for `secret_access_key`"),
            "{err}"
        );
        let err = r
            .login("runpod", &[("tokn".to_string(), "x".to_string())].into())
            .unwrap_err();
        assert!(err.to_string().contains("no field `tokn`"), "{err}");
        r.login(
            "runpod",
            &[("api_key".to_string(), "rp_value_123".to_string())].into(),
        )
        .unwrap();
        r.record_test("runpod", true, "3 pods");
        let st = r.status("runpod").unwrap();
        assert_eq!(
            (st.configured, st.source.as_deref(), st.last_test_ok),
            (true, Some("file"), Some(true))
        );
        assert_eq!(r.logout("runpod").unwrap(), 1);
        let st = r.status("runpod").unwrap();
        assert!(!st.configured && st.last_tested.is_none());
    }

    #[test]
    fn env_for_children_and_redaction_and_import() {
        let r = resolver(&[
            ("ANYSCALE_API_KEY", "as_value_123"),
            ("ANYSCALE_CLOUD_ID", "cld_1"),
        ]);
        r.login(
            "huggingface",
            &[("token".to_string(), "hf_store_value".to_string())].into(),
        )
        .unwrap();
        let child = r.env_for(["huggingface", "runpod", "anyscale"]);
        assert_eq!(child["HF_TOKEN"], "hf_store_value");
        assert_eq!(child["ANYSCALE_API_KEY"], "as_value_123");
        assert_eq!(child[BOUND_ENV], "huggingface,anyscale");
        assert!(!child.contains_key("RUNPOD_API_KEY"));
        let mut secrets = r.secrets();
        secrets.sort();
        assert_eq!(secrets, ["as_value_123", "hf_store_value"]);
        let items = r.importable_from_env();
        assert_eq!(items.len(), 2);
        assert_eq!(r.import_from_env(&items).unwrap(), 2);
        assert!(r.importable_from_env().is_empty());
        assert_eq!(
            r.get("anyscale", "api_key").unwrap().unwrap().source,
            "memory"
        );
    }
}
