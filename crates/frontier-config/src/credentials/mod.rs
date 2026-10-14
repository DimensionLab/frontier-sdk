// SPDX-License-Identifier: Apache-2.0
//! Credentials: who needs which secret ([`AuthProvider`], declared with `[[auth]]`), where
//! secrets are kept ([`store`]) and how one is found when it is needed ([`Resolver`]).
//!
//! Nothing else in the codebase reads a token from the environment directly. Values never
//! appear in `Debug` output, logs, config files or API responses.

pub mod check;
pub mod oauth;
#[cfg(feature = "http")]
pub mod remote;
#[cfg(feature = "http")]
pub mod remote_cloud;
pub mod resolver;
pub mod store;

pub use resolver::{CredentialStatus, Resolved, Resolver, TestRecord};
pub use store::{EnvStore, FileStore, MemoryStore, SecretStore};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

/// `token | api_key | basic | oauth_device | oauth_pkce | file | none`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    #[default]
    Token,
    ApiKey,
    Basic,
    OauthDevice,
    OauthPkce,
    File,
    None,
}

fn yes() -> bool {
    true
}

/// One value a provider needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthField {
    pub name: String,
    #[serde(default)]
    pub title: String,
    /// Secret fields are write-only everywhere; non-secret ones (a user name, a region, a
    /// file path) are still kept in the secret store so one login is one unit.
    #[serde(default = "yes")]
    pub secret: bool,
    #[serde(default = "yes")]
    pub required: bool,
    /// Environment variables accepted as a fallback for this field.
    #[serde(default)]
    pub env: Vec<String>,
}

/// A declarative HTTP check: `GET url` with the credential, success on 2xx.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HttpTest {
    pub url: String,
    /// A setting whose value (when not empty) replaces the URL's origin, joined with `url_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_setting: Option<String>,
    /// A credential field whose value (when set) replaces the URL's origin, joined with `url_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_path: Option<String>,
    /// `bearer`, `basic`, or `header:<Name>[:<value prefix>]`.
    #[serde(default)]
    pub auth: String,
    /// JSON pointer to the account identity in the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// JSON pointer to an array whose length is reported (`""` = the response itself).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<String>,
}

/// OAuth 2.0 parameters of a provider (`[auth.oauth]`). Public clients only: there is no
/// client secret, the authorization-code flow always uses PKCE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OAuthConfig {
    /// Authorization endpoint (authorization-code flow with PKCE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    pub token_url: String,
    /// Device authorization endpoint (device flow).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_code_url: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Fixed loopback port for the desktop redirect (`http://127.0.0.1:<port>/callback`);
    /// an ephemeral port when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

fn secure_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
}

/// A credential provider, as declared by `[[auth]]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthProvider {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub kind: AuthKind,
    #[serde(default)]
    pub fields: Vec<AuthField>,
    /// Fallback variables of the first secret field (the common single-token case).
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_url: Option<String>,
    /// Python callable `module:function` that tests the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_http: Option<HttpTest>,
    /// Present on providers that can sign in with OAuth (kinds `oauth_device`, `oauth_pkce`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
    /// Plugins that declared this provider (empty for built-in ones).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_by: Vec<String>,
}

impl AuthProvider {
    /// Normalise a parsed declaration: default field, titles, provider-level `env` moved onto
    /// the first secret field.
    pub fn normalised(mut self) -> Self {
        if self.is_oauth() {
            // the stored token set of an OAuth sign-in
            let has_secret = self.fields.iter().any(|f| f.secret);
            let mut add = |name: &str, title: &str, secret: bool, required: bool| {
                if !self.fields.iter().any(|f| f.name == name) {
                    self.fields.push(AuthField {
                        name: name.into(),
                        title: title.into(),
                        secret,
                        required,
                        env: Vec::new(),
                    });
                }
            };
            // The access token goes into the provider's primary secret field (so a pasted
            // token, the environment fallback and an OAuth sign-in are interchangeable).
            if !has_secret {
                add(oauth::ACCESS_TOKEN, "Access token", true, true);
            }
            add(oauth::REFRESH_TOKEN, "Refresh token", true, false);
            add(oauth::EXPIRES_AT, "Expires at", false, false);
        }
        if self.fields.is_empty() && self.kind != AuthKind::None {
            self.fields.push(AuthField {
                name: match self.kind {
                    AuthKind::ApiKey => "api_key".into(),
                    _ => "token".into(),
                },
                title: String::new(),
                secret: true,
                required: true,
                env: Vec::new(),
            });
        }
        let primary = self
            .fields
            .iter()
            .position(|f| f.secret && f.name != oauth::REFRESH_TOKEN)
            .unwrap_or_default();
        for (i, f) in self.fields.iter_mut().enumerate() {
            if f.title.is_empty() {
                f.title = f.name.replace('_', " ");
            }
            if i == primary {
                for e in &self.env {
                    if !f.env.contains(e) {
                        f.env.push(e.clone());
                    }
                }
            }
        }
        self
    }

    /// Signs in with an OAuth flow (the token set is stored, refreshed and expires).
    pub fn is_oauth(&self) -> bool {
        matches!(self.kind, AuthKind::OauthDevice | AuthKind::OauthPkce)
    }

    /// Problems of the declaration (empty when it is usable).
    pub fn validate(&self) -> Result<(), String> {
        if !Self::valid_id(&self.id) {
            return Err(format!(
                "auth id {:?}: use lower-case letters, digits, `-` and `_`",
                self.id
            ));
        }
        if !self.is_oauth() {
            return Ok(());
        }
        let o = self.oauth.as_ref().ok_or_else(|| {
            format!(
                "auth `{}`: kind {:?} needs an [auth.oauth] table",
                self.id, self.kind
            )
        })?;
        if o.client_id.trim().is_empty() {
            return Err(format!("auth `{}`: oauth.client_id is empty", self.id));
        }
        let mut urls = vec![("token_url", Some(&o.token_url))];
        match self.kind {
            AuthKind::OauthDevice => urls.push(("device_code_url", o.device_code_url.as_ref())),
            _ => urls.push(("authorize_url", o.authorize_url.as_ref())),
        }
        for (name, url) in urls {
            match url {
                Some(u) if secure_url(u) => {}
                Some(u) => {
                    return Err(format!(
                        "auth `{}`: oauth.{name} must be https ({u})",
                        self.id
                    ));
                }
                None => {
                    return Err(format!(
                        "auth `{}`: oauth.{name} is required for {:?}",
                        self.id, self.kind
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn field(&self, name: &str) -> Option<&AuthField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// The first secret field (the token of single-token providers).
    pub fn primary(&self) -> Option<&AuthField> {
        self.fields
            .iter()
            .find(|f| f.secret && f.name != oauth::REFRESH_TOKEN)
            .or(self.fields.first())
    }

    /// Check an id for use in file names, keychain accounts and URLs.
    pub fn valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 64
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    }
}

#[derive(Debug, Deserialize)]
struct Declarations {
    #[serde(default)]
    auth: Vec<AuthProvider>,
}

/// Parse the `[[auth]]` tables of a TOML document (a plugin.toml or the built-in list).
pub fn parse_declarations(text: &str) -> Result<Vec<AuthProvider>, String> {
    let d: Declarations = toml::from_str(text).map_err(|e| e.to_string())?;
    for p in &d.auth {
        p.validate()?;
    }
    Ok(d.auth.into_iter().map(AuthProvider::normalised).collect())
}

static BUILTIN: LazyLock<Vec<AuthProvider>> = LazyLock::new(|| {
    parse_declarations(include_str!("providers.toml")).expect("built-in providers.toml is valid")
});

/// Providers that ship with Frontier.
pub fn builtin() -> &'static [AuthProvider] {
    &BUILTIN
}

/// File in the Frontier home where the plugin manager records the `[[auth]]` declarations of
/// installed plugins, so the CLI and the server know them without importing Python.
pub const PLUGIN_PROVIDERS_FILE: &str = "auth-providers.json";

/// The provider registry: built-in providers plus plugin declarations.
#[derive(Debug, Clone)]
pub struct Registry {
    providers: BTreeMap<String, AuthProvider>,
    order: Vec<String>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Registry {
    pub fn builtin() -> Self {
        let mut r = Self {
            providers: BTreeMap::new(),
            order: Vec::new(),
        };
        for p in builtin() {
            r.add(p.clone());
        }
        r
    }

    /// Built-in providers plus the ones recorded in `<home>/auth-providers.json`.
    pub fn load(home: &Path) -> Self {
        let mut r = Self::builtin();
        let path = home.join(PLUGIN_PROVIDERS_FILE);
        if let Ok(text) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Vec<AuthProvider>>(&text) {
                Ok(list) => {
                    for p in list {
                        match p.validate() {
                            Ok(()) => r.add(p.normalised()),
                            Err(e) => {
                                tracing::warn!(error = %e, "ignoring plugin auth declaration")
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "ignoring unreadable plugin auth declarations")
                }
            }
        }
        r
    }

    /// Add a declaration. A provider that already exists keeps its definition and gains the
    /// new declarer, extra env names and any field it did not have.
    pub fn add(&mut self, p: AuthProvider) {
        match self.providers.get_mut(&p.id) {
            Some(existing) => {
                for d in p.declared_by {
                    if !existing.declared_by.contains(&d) {
                        existing.declared_by.push(d);
                    }
                }
                let has_secret = existing.fields.iter().any(|f| f.secret);
                for f in p.fields {
                    // the existing primary field holds the access token
                    if has_secret && f.name == oauth::ACCESS_TOKEN {
                        continue;
                    }
                    match existing.fields.iter_mut().find(|e| e.name == f.name) {
                        Some(e) => {
                            for v in f.env {
                                if !e.env.contains(&v) {
                                    e.env.push(v);
                                }
                            }
                        }
                        None => existing.fields.push(f),
                    }
                }
                // A later declaration can make a provider OAuth-capable (an organisation
                // registering its own public client, for example).
                if existing.oauth.is_none() && p.oauth.is_some() && p.kind != existing.kind {
                    existing.oauth = p.oauth;
                    existing.kind = p.kind;
                    *existing = existing.clone().normalised();
                }
                if existing.test_http.is_none() {
                    existing.test_http = p.test_http;
                }
                if existing.help_url.is_none() {
                    existing.help_url = p.help_url;
                }
            }
            None => {
                self.order.push(p.id.clone());
                self.providers.insert(p.id.clone(), p);
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<&AuthProvider> {
        self.providers.get(id)
    }

    /// Providers in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = &AuthProvider> {
        self.order.iter().filter_map(|id| self.providers.get(id))
    }

    pub fn ids(&self) -> Vec<&str> {
        self.order.iter().map(String::as_str).collect()
    }

    /// The provider that accepts `var` as a fallback, with the field it fills.
    pub fn by_env(&self, var: &str) -> Option<(&AuthProvider, &AuthField)> {
        self.iter().find_map(|p| {
            p.fields
                .iter()
                .find(|f| f.env.iter().any(|e| e == var))
                .map(|f| (p, f))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_providers_cover_the_contract() {
        let r = Registry::builtin();
        for id in [
            "frontier",
            "huggingface",
            "runpod",
            "anyscale",
            "flow360",
            "luminary",
            "simscale",
            "rescale",
            "s3",
            "gcs",
            "azure",
            "registry",
            "ssh",
        ] {
            let p = r.get(id).unwrap_or_else(|| panic!("missing provider {id}"));
            assert!(!p.title.is_empty() && !p.fields.is_empty(), "{id}");
            assert!(p.fields.iter().all(|f| !f.title.is_empty()), "{id}");
        }
        let hf = r.get("huggingface").unwrap();
        assert_eq!(
            hf.primary().unwrap().env,
            ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"]
        );
        assert_eq!(r.by_env("RUNPOD_API_KEY").unwrap().0.id, "runpod");
        assert_eq!(
            r.by_env("AWS_SECRET_ACCESS_KEY").unwrap().1.name,
            "secret_access_key"
        );
        // no env name is claimed by two providers
        let mut seen = std::collections::BTreeSet::new();
        for p in r.iter() {
            for f in &p.fields {
                for e in &f.env {
                    assert!(seen.insert(e.clone()), "{e} claimed twice");
                }
            }
        }
    }

    #[test]
    fn plugin_declarations_merge_by_id() {
        let decl = parse_declarations(
            r#"
[[auth]]
id = "huggingface"
title = "Hugging Face"
kind = "token"
env = ["HF_API_TOKEN"]

[[auth]]
id = "acme-cloud"
title = "Acme Cloud"
kind = "api_key"
env = ["ACME_KEY"]
help_url = "https://acme.example/keys"
"#,
        )
        .unwrap();
        let mut r = Registry::builtin();
        for mut p in decl {
            p.declared_by.push("acme".into());
            r.add(p);
        }
        let hf = r.get("huggingface").unwrap();
        assert_eq!(
            hf.primary().unwrap().env,
            ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HF_API_TOKEN"]
        );
        assert_eq!(hf.declared_by, ["acme"]);
        let acme = r.get("acme-cloud").unwrap();
        assert_eq!(acme.primary().unwrap().name, "api_key");
        assert_eq!(acme.primary().unwrap().env, ["ACME_KEY"]);
        assert!(parse_declarations("[[auth]]\nid = \"Bad Id\"\ntitle = \"x\"\n").is_err());
    }

    #[test]
    fn registry_reads_plugin_declarations_from_home() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(PLUGIN_PROVIDERS_FILE),
            r#"[{"id":"acme","title":"Acme","kind":"token","env":["ACME_TOKEN"],"declared_by":["acme-plugin"]}]"#,
        )
        .unwrap();
        let r = Registry::load(dir.path());
        assert_eq!(
            r.get("acme").unwrap().primary().unwrap().env,
            ["ACME_TOKEN"]
        );
        assert_eq!(r.ids().last(), Some(&"acme"));
    }
}
