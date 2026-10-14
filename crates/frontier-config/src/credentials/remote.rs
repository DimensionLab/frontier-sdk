// SPDX-License-Identifier: Apache-2.0
//! Secret stores that live in an organisation's own secret manager, spoken to over plain
//! REST (no vendor SDK): HashiCorp Vault KV v2 and AWS Secrets Manager.
//!
//! Both keep one secret per provider (`<prefix>/<provider id>`) whose value is a JSON
//! object `{field: value}`, so an administrator sees `frontier/huggingface` with a `token`
//! key, and access can be granted per provider with the manager's own policies.
//!
//! | backend | settings                         | authentication                               |
//! |---------|----------------------------------|----------------------------------------------|
//! | `vault` | `secrets.vault.*`                | token, AppRole or Kubernetes service account |
//! | `aws`   | `secrets.aws.*`                  | access key from the environment (SigV4)      |
//!
//! The secrets these stores need themselves (a Vault token, an AppRole secret id, an AWS
//! secret key) are never settings: they come from the environment or a file.

use super::store::SecretStore;
use crate::loader::Config;
use crate::{Error, Result};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) fn err(what: impl std::fmt::Display) -> Error {
    Error::Store(what.to_string())
}

/// Run a request to completion from synchronous code, whether or not the caller is inside
/// an async runtime: its own thread, its own small runtime.
pub(super) fn block_on<T: Send>(fut: impl std::future::Future<Output = T> + Send) -> Result<T> {
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map(|rt| rt.block_on(fut))
        })
        .join()
        .map_err(|_| err("secret store request panicked"))?
        .map_err(|e| err(format!("secret store runtime: {e}")))
    })
}

pub(super) fn client(config: &Config) -> Result<reqwest::Client> {
    crate::http::client_builder(config)
        .map_err(err)?
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| err(format!("building http client: {e}")))
}

/// A path segment of a secret name: provider ids and prefixes only.
pub(super) fn safe_segment(s: &str) -> Result<&str> {
    let ok = !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+'));
    if ok {
        Ok(s)
    } else {
        Err(err(format!("`{s}` cannot be part of a secret name")))
    }
}

pub(super) fn clean_prefix(prefix: &str) -> Result<String> {
    let parts: Vec<&str> = prefix.split('/').filter(|p| !p.is_empty()).collect();
    for p in &parts {
        safe_segment(p)?;
    }
    Ok(parts.join("/"))
}

pub(super) fn secret_from_env_or_file(
    config: &Config,
    file_setting: &str,
    env_names: &[&str],
    what: &str,
) -> Result<String> {
    if let Some(path) = config.path(file_setting) {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| err(format!("{file_setting} {}: {e}", path.display())))?;
        let v = text.trim();
        if v.is_empty() {
            return Err(err(format!("{file_setting} {} is empty", path.display())));
        }
        return Ok(v.to_string());
    }
    env_names
        .iter()
        .find_map(|n| config.env().get(*n).map(|v| v.trim()).filter(|v| !v.is_empty()))
        .map(str::to_string)
        .ok_or_else(|| {
            err(format!(
                "{what} is not available: set {} in the environment or {file_setting} to a file that holds it",
                env_names.join(" or ")
            ))
        })
}

// -- HashiCorp Vault, KV version 2 -----------------------------------------------------------

/// How the store logs in to Vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultAuth {
    /// A token (`VAULT_TOKEN`, or `secrets.vault.credential_file`).
    Token(String),
    /// AppRole: `secrets.vault.role` is the role id; the secret id comes from
    /// `FRONTIER_VAULT_SECRET_ID` or the credential file.
    AppRole {
        role_id: String,
        secret_id: String,
        mount: String,
    },
    /// The pod's service-account token, exchanged at the Kubernetes auth method.
    Kubernetes {
        role: String,
        jwt_path: std::path::PathBuf,
        mount: String,
    },
}

pub struct VaultStore {
    http: reqwest::Client,
    addr: String,
    mount: String,
    prefix: String,
    namespace: Option<String>,
    auth: VaultAuth,
    /// A token obtained by logging in, with the time to stop using it.
    session: Mutex<Option<(String, Instant)>>,
}

impl VaultStore {
    pub fn from_config(config: &Config) -> Result<Self> {
        let addr = config
            .str("secrets.vault.addr")
            .trim_end_matches('/')
            .to_string();
        if !(addr.starts_with("https://") || addr.starts_with("http://")) {
            return Err(err(
                "secrets.backend = \"vault\" needs secrets.vault.addr (for example https://vault.example.com:8200)",
            ));
        }
        crate::http::require_online(config, "reaching the Vault secret store", &addr)
            .map_err(err)?;
        let method = config.str("secrets.vault.auth");
        let default_mount = |m: &str| {
            let configured = config.str("secrets.vault.auth_mount").trim_matches('/');
            if configured.is_empty() {
                m.to_string()
            } else {
                configured.to_string()
            }
        };
        let auth = match method {
            "approle" => VaultAuth::AppRole {
                role_id: non_empty(
                    config.str("secrets.vault.role"),
                    "secrets.vault.role (the AppRole role id)",
                )?,
                secret_id: secret_from_env_or_file(
                    config,
                    "secrets.vault.credential_file",
                    &["FRONTIER_VAULT_SECRET_ID"],
                    "the AppRole secret id",
                )?,
                mount: default_mount("approle"),
            },
            "kubernetes" => VaultAuth::Kubernetes {
                role: non_empty(
                    config.str("secrets.vault.role"),
                    "secrets.vault.role (the Kubernetes auth role)",
                )?,
                jwt_path: config
                    .path("secrets.vault.credential_file")
                    .unwrap_or_else(|| {
                        "/var/run/secrets/kubernetes.io/serviceaccount/token".into()
                    }),
                mount: default_mount("kubernetes"),
            },
            _ => VaultAuth::Token(secret_from_env_or_file(
                config,
                "secrets.vault.credential_file",
                &["VAULT_TOKEN"],
                "the Vault token",
            )?),
        };
        Ok(Self {
            http: client(config)?,
            addr,
            mount: safe_segment(config.str("secrets.vault.mount").trim_matches('/'))?.to_string(),
            prefix: clean_prefix(config.str("secrets.vault.prefix"))?,
            namespace: Some(config.str("secrets.vault.namespace").trim().to_string())
                .filter(|n| !n.is_empty()),
            auth,
            session: Mutex::new(None),
        })
    }

    fn path(&self, provider: &str) -> Result<String> {
        let provider = safe_segment(provider)?;
        Ok(if self.prefix.is_empty() {
            provider.to_string()
        } else {
            format!("{}/{provider}", self.prefix)
        })
    }

    fn request(&self, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        req
    }

    async fn token(&self) -> Result<String> {
        let (path, body) = match &self.auth {
            VaultAuth::Token(t) => return Ok(t.clone()),
            VaultAuth::AppRole {
                role_id,
                secret_id,
                mount,
            } => (
                format!("{}/v1/auth/{mount}/login", self.addr),
                json!({"role_id": role_id, "secret_id": secret_id}),
            ),
            VaultAuth::Kubernetes {
                role,
                jwt_path,
                mount,
            } => {
                let jwt = std::fs::read_to_string(jwt_path).map_err(|e| {
                    err(format!("service-account token {}: {e}", jwt_path.display()))
                })?;
                (
                    format!("{}/v1/auth/{mount}/login", self.addr),
                    json!({"role": role, "jwt": jwt.trim()}),
                )
            }
        };
        if let Some((t, until)) = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            && Instant::now() < *until
        {
            return Ok(t.clone());
        }
        let res = self
            .request(reqwest::Method::POST, path)
            .json(&body)
            .send()
            .await
            .map_err(|e| err(format!("Vault login: {e}")))?;
        let status = res.status();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        let token = v["auth"]["client_token"].as_str().ok_or_else(|| {
            err(format!(
                "Vault login refused (HTTP {status}{})",
                vault_errors(&v)
            ))
        })?;
        let lease = v["auth"]["lease_duration"].as_u64().unwrap_or(300);
        // renew a little before it runs out
        let until =
            Instant::now() + Duration::from_secs(lease.saturating_sub(lease / 5 + 5).max(1));
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some((token.to_string(), until));
        Ok(token.to_string())
    }

    async fn read(&self, provider: &str) -> Result<Option<Map<String, Value>>> {
        let url = format!(
            "{}/v1/{}/data/{}",
            self.addr,
            self.mount,
            self.path(provider)?
        );
        let res = self
            .request(reqwest::Method::GET, url)
            .header("X-Vault-Token", self.token().await?)
            .send()
            .await
            .map_err(|e| err(format!("Vault read: {e}")))?;
        let status = res.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(err(format!(
                "Vault read of {provider} refused (HTTP {status}{})",
                vault_errors(&v)
            )));
        }
        // a deleted latest version reads as data: null
        Ok(v["data"]["data"].as_object().cloned())
    }

    async fn write(&self, provider: &str, data: &Map<String, Value>) -> Result<()> {
        let url = format!(
            "{}/v1/{}/data/{}",
            self.addr,
            self.mount,
            self.path(provider)?
        );
        let res = self
            .request(reqwest::Method::POST, url)
            .header("X-Vault-Token", self.token().await?)
            .json(&json!({"data": data}))
            .send()
            .await
            .map_err(|e| err(format!("Vault write: {e}")))?;
        let status = res.status();
        if !status.is_success() {
            let v: Value = res.json().await.unwrap_or(Value::Null);
            return Err(err(format!(
                "Vault write of {provider} refused (HTTP {status}{})",
                vault_errors(&v)
            )));
        }
        Ok(())
    }

    /// Remove the secret with all its versions.
    async fn remove(&self, provider: &str) -> Result<()> {
        let url = format!(
            "{}/v1/{}/metadata/{}",
            self.addr,
            self.mount,
            self.path(provider)?
        );
        let res = self
            .request(reqwest::Method::DELETE, url)
            .header("X-Vault-Token", self.token().await?)
            .send()
            .await
            .map_err(|e| err(format!("Vault delete: {e}")))?;
        if !res.status().is_success() && res.status() != reqwest::StatusCode::NOT_FOUND {
            return Err(err(format!(
                "Vault delete of {provider} refused (HTTP {})",
                res.status()
            )));
        }
        Ok(())
    }

    /// Can the store log in and reach its mount? For `frontier secrets backend test`.
    pub fn check(&self) -> Result<String> {
        block_on(async {
            self.token().await?;
            self.read("frontier-connection-test").await?;
            Ok(self.describe())
        })?
    }
}

pub(super) fn non_empty(value: &str, what: &str) -> Result<String> {
    let v = value.trim();
    if v.is_empty() {
        Err(err(format!("{what} is not set")))
    } else {
        Ok(v.to_string())
    }
}

fn vault_errors(v: &Value) -> String {
    match v["errors"].as_array() {
        Some(e) if !e.is_empty() => format!(
            ": {}",
            e.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        _ => String::new(),
    }
}

impl SecretStore for VaultStore {
    fn name(&self) -> &'static str {
        "vault"
    }
    fn describe(&self) -> String {
        format!(
            "HashiCorp Vault {} (KV v2 mount `{}`, path `{}/<provider>`, auth {})",
            self.addr,
            self.mount,
            self.prefix,
            match self.auth {
                VaultAuth::Token(_) => "token",
                VaultAuth::AppRole { .. } => "approle",
                VaultAuth::Kubernetes { .. } => "kubernetes",
            }
        )
    }
    fn get(&self, provider: &str, field: &str) -> Result<Option<String>> {
        block_on(async {
            Ok(self
                .read(provider)
                .await?
                .and_then(|m| m.get(field).and_then(Value::as_str).map(str::to_string)))
        })?
    }
    fn set(&self, provider: &str, field: &str, value: &str) -> Result<()> {
        block_on(async {
            let mut data = self.read(provider).await?.unwrap_or_default();
            data.insert(field.to_string(), Value::String(value.to_string()));
            self.write(provider, &data).await
        })?
    }
    fn delete(&self, provider: &str, field: &str) -> Result<bool> {
        block_on(async {
            let Some(mut data) = self.read(provider).await? else {
                return Ok(false);
            };
            if data.remove(field).is_none() {
                return Ok(false);
            }
            // Every version goes, so the removed value cannot be read back from the
            // secret's history; what remains is written again as a fresh first version.
            self.remove(provider).await?;
            if !data.is_empty() {
                self.write(provider, &data).await?;
            }
            Ok(true)
        })?
    }
}

// -- AWS Signature Version 4 -----------------------------------------------------------------

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a SigV4 signature is computed over.
pub struct SigV4<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub method: &'a str,
    /// Canonical URI (`/`) and canonical query string (already sorted and encoded).
    pub path: &'a str,
    pub query: &'a str,
    /// Lower-case header names with their values; `host` and `x-amz-date` included.
    pub headers: &'a BTreeMap<String, String>,
    pub body: &'a [u8],
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
}

impl SigV4<'_> {
    /// The value of the `Authorization` header.
    pub fn authorization(&self) -> String {
        let date = &self.amz_date[..8];
        let canonical_headers: String = self
            .headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let signed: String = self.headers.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical = format!(
            "{}\n{}\n{}\n{canonical_headers}\n{signed}\n{}",
            self.method,
            self.path,
            self.query,
            hex(&Sha256::digest(self.body))
        );
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
            self.amz_date,
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let k = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let k = hmac(&k, self.region.as_bytes());
        let k = hmac(&k, self.service.as_bytes());
        let k = hmac(&k, b"aws4_request");
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
            self.access_key,
            hex(&hmac(&k, to_sign.as_bytes()))
        )
    }
}

// -- AWS credentials -------------------------------------------------------------------------

/// A set of AWS keys, with the time to stop using them when they are temporary.
#[derive(Clone)]
pub struct AwsKeys {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    refresh_at: Option<Instant>,
}

/// Where this process gets AWS credentials, in the order the AWS SDKs use:
/// 1. static keys in the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
///    `AWS_SESSION_TOKEN`);
/// 2. web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`): IRSA on EKS, or any
///    OIDC token, exchanged at STS;
/// 3. the container credential endpoint (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or
///    `..._FULL_URI`): ECS, EKS Pod Identity;
/// 4. the instance profile (IMDSv2).
///
/// Temporary credentials are cached and fetched again five minutes before they expire.
pub struct AwsAuth {
    http: reqwest::Client,
    env: BTreeMap<String, String>,
    region: String,
    cached: tokio::sync::Mutex<Option<AwsKeys>>,
}

fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

/// When to stop using credentials that expire at `expiration` (RFC 3339).
fn refresh_time(expiration: Option<&str>) -> Option<Instant> {
    let at = chrono::DateTime::parse_from_rfc3339(expiration?).ok()?;
    let left = (at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
    Some(Instant::now() + Duration::from_secs((left - 300).max(0) as u64))
}

impl AwsAuth {
    pub fn new(http: reqwest::Client, env: BTreeMap<String, String>, region: String) -> Self {
        Self {
            http,
            env,
            region,
            cached: tokio::sync::Mutex::new(None),
        }
    }

    fn var(&self, name: &str) -> Option<String> {
        self.env
            .get(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// The credentials to sign with now.
    pub async fn current(&self) -> Result<AwsKeys> {
        let mut cached = self.cached.lock().await;
        if let Some(k) = cached.as_ref()
            && k.refresh_at.is_none_or(|t| Instant::now() < t)
        {
            return Ok(k.clone());
        }
        let keys = self.fetch().await?;
        *cached = Some(keys.clone());
        Ok(keys)
    }

    async fn fetch(&self) -> Result<AwsKeys> {
        if let (Some(access_key), Some(secret_key)) = (
            self.var("AWS_ACCESS_KEY_ID"),
            self.var("AWS_SECRET_ACCESS_KEY"),
        ) {
            return Ok(AwsKeys {
                access_key,
                secret_key,
                session_token: self.var("AWS_SESSION_TOKEN"),
                refresh_at: None,
            });
        }
        let mut tried =
            vec!["no AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in the environment".to_string()];
        if let (Some(file), Some(role)) = (
            self.var("AWS_WEB_IDENTITY_TOKEN_FILE"),
            self.var("AWS_ROLE_ARN"),
        ) {
            match self.web_identity(&file, &role).await {
                Ok(k) => return Ok(k),
                Err(e) => tried.push(format!("web identity: {e}")),
            }
        }
        let container = self.var("AWS_CONTAINER_CREDENTIALS_FULL_URI").or_else(|| {
            self.var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
                .map(|p| format!("http://169.254.170.2{p}"))
        });
        if let Some(url) = container {
            match self.container(&url).await {
                Ok(k) => return Ok(k),
                Err(e) => tried.push(format!("container credentials: {e}")),
            }
        }
        if self.var("AWS_EC2_METADATA_DISABLED").as_deref() != Some("true") {
            match self.instance_profile().await {
                Ok(k) => return Ok(k),
                Err(e) => tried.push(format!("instance profile: {e}")),
            }
        }
        Err(err(format!(
            "AWS credentials are not available ({}): set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or run where a role is attached (IRSA / web identity, ECS task role, EC2 instance profile)",
            tried.join("; ")
        )))
    }

    fn from_json(v: &Value, token_key: &str) -> Result<AwsKeys> {
        let field = |k: &str| v[k].as_str().filter(|s| !s.is_empty()).map(str::to_string);
        match (field("AccessKeyId"), field("SecretAccessKey")) {
            (Some(access_key), Some(secret_key)) => Ok(AwsKeys {
                access_key,
                secret_key,
                session_token: field(token_key),
                refresh_at: refresh_time(v["Expiration"].as_str()),
            }),
            _ => Err(err("the response carries no credentials")),
        }
    }

    /// STS `AssumeRoleWithWebIdentity` (an unsigned call: the token is the proof).
    async fn web_identity(&self, token_file: &str, role_arn: &str) -> Result<AwsKeys> {
        let token =
            std::fs::read_to_string(token_file).map_err(|e| err(format!("{token_file}: {e}")))?;
        let endpoint = self
            .var("AWS_ENDPOINT_URL_STS")
            .unwrap_or_else(|| format!("https://sts.{}.amazonaws.com", self.region));
        let session = self
            .var("AWS_ROLE_SESSION_NAME")
            .unwrap_or_else(|| "frontier".to_string());
        let res = self
            .http
            .post(format!("{}/", endpoint.trim_end_matches('/')))
            .form(&[
                ("Action", "AssumeRoleWithWebIdentity"),
                ("Version", "2011-06-15"),
                ("RoleArn", role_arn),
                ("RoleSessionName", session.as_str()),
                ("WebIdentityToken", token.trim()),
            ])
            .send()
            .await
            .map_err(|e| err(e.to_string()))?;
        let status = res.status();
        let xml = res.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(err(format!(
                "STS refused (HTTP {status}): {}",
                xml_tag(&xml, "Message").unwrap_or("no message")
            )));
        }
        match (
            xml_tag(&xml, "AccessKeyId"),
            xml_tag(&xml, "SecretAccessKey"),
        ) {
            (Some(a), Some(k)) => Ok(AwsKeys {
                access_key: a.to_string(),
                secret_key: k.to_string(),
                session_token: xml_tag(&xml, "SessionToken").map(str::to_string),
                refresh_at: refresh_time(xml_tag(&xml, "Expiration")),
            }),
            _ => Err(err("STS answered without credentials")),
        }
    }

    /// The ECS / EKS Pod Identity credential endpoint.
    async fn container(&self, url: &str) -> Result<AwsKeys> {
        let mut req = self.http.get(url).timeout(Duration::from_secs(5));
        let token = self.var("AWS_CONTAINER_AUTHORIZATION_TOKEN").or_else(|| {
            self.var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
                .and_then(|f| std::fs::read_to_string(f).ok())
                .map(|t| t.trim().to_string())
        });
        if let Some(t) = token {
            req = req.header("Authorization", t);
        }
        let res = req.send().await.map_err(|e| err(e.to_string()))?;
        if !res.status().is_success() {
            return Err(err(format!("HTTP {}", res.status())));
        }
        Self::from_json(&res.json().await.unwrap_or(Value::Null), "Token")
    }

    /// The EC2 instance metadata service, version 2 (a session token first, then the role).
    async fn instance_profile(&self) -> Result<AwsKeys> {
        let base = self
            .var("AWS_EC2_METADATA_SERVICE_ENDPOINT")
            .unwrap_or_else(|| "http://169.254.169.254".to_string());
        let base = base.trim_end_matches('/');
        let quick = Duration::from_secs(2);
        let token = self
            .http
            .put(format!("{base}/latest/api/token"))
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .timeout(quick)
            .send()
            .await
            .map_err(|_| err("no metadata service"))?;
        if !token.status().is_success() {
            return Err(err(format!("metadata token: HTTP {}", token.status())));
        }
        let token = token.text().await.unwrap_or_default();
        let roles = format!("{base}/latest/meta-data/iam/security-credentials/");
        let role = self
            .http
            .get(&roles)
            .header("X-aws-ec2-metadata-token", &token)
            .timeout(quick)
            .send()
            .await
            .map_err(|e| err(e.to_string()))?;
        if !role.status().is_success() {
            return Err(err("no role is attached to this instance"));
        }
        let role = role.text().await.unwrap_or_default();
        let role = role.lines().next().unwrap_or("").trim();
        if role.is_empty()
            || !role
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
        {
            return Err(err("no role is attached to this instance"));
        }
        let res = self
            .http
            .get(format!("{roles}{role}"))
            .header("X-aws-ec2-metadata-token", &token)
            .timeout(quick)
            .send()
            .await
            .map_err(|e| err(e.to_string()))?;
        if !res.status().is_success() {
            return Err(err(format!("HTTP {}", res.status())));
        }
        Self::from_json(&res.json().await.unwrap_or(Value::Null), "Token")
    }
}

// -- AWS Secrets Manager ---------------------------------------------------------------------

/// A fresh `ClientRequestToken` (a version-4 UUID), required on every write.
fn request_token() -> String {
    let mut b = [0u8; 16];
    // the OS generator failing is not something a credential store can work around
    getrandom::fill(&mut b).expect("operating system random number generator");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

pub struct AwsSecretsManagerStore {
    http: reqwest::Client,
    endpoint: String,
    host: String,
    region: String,
    prefix: String,
    /// Customer KMS key new secrets are encrypted under (`secrets.aws.kms_key_id`); empty
    /// uses the account's default key for Secrets Manager.
    kms_key_id: Option<String>,
    auth: std::sync::Arc<AwsAuth>,
}

impl AwsSecretsManagerStore {
    pub fn from_config(config: &Config) -> Result<Self> {
        let env = config.env();
        let region = [config.str("secrets.aws.region").trim().to_string()]
            .into_iter()
            .chain(
                ["AWS_REGION", "AWS_DEFAULT_REGION"]
                    .iter()
                    .filter_map(|n| env.get(*n).cloned()),
            )
            .find(|r| !r.is_empty())
            .ok_or_else(|| {
                err("secrets.backend = \"aws\" needs secrets.aws.region (or AWS_REGION)")
            })?;
        if !region
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(err(format!("`{region}` is not an AWS region")));
        }
        let endpoint = match config.str("secrets.aws.endpoint").trim_end_matches('/') {
            "" => format!("https://secretsmanager.{region}.amazonaws.com"),
            e => e.to_string(),
        };
        crate::http::require_online(config, "reaching AWS Secrets Manager", &endpoint)
            .map_err(err)?;
        let host = endpoint
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(rest).to_string())
            .ok_or_else(|| err("secrets.aws.endpoint is not a URL"))?;
        let http = client(config)?;
        let auth = std::sync::Arc::new(AwsAuth::new(http.clone(), env.clone(), region.clone()));
        // find out now whether this process has any way to authenticate, not at first use
        block_on(auth.current())??;
        Ok(Self {
            http,
            endpoint,
            host,
            region,
            prefix: clean_prefix(config.str("secrets.aws.prefix"))?,
            kms_key_id: Some(config.str("secrets.aws.kms_key_id").trim().to_string())
                .filter(|k| !k.is_empty()),
            auth,
        })
    }

    fn secret_id(&self, provider: &str) -> Result<String> {
        let provider = safe_segment(provider)?;
        Ok(if self.prefix.is_empty() {
            provider.to_string()
        } else {
            format!("{}/{provider}", self.prefix)
        })
    }

    /// One Secrets Manager action: `(http status, body)`.
    async fn call(&self, action: &str, body: &Value) -> Result<(u16, Value)> {
        let payload = body.to_string();
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut headers = BTreeMap::from([
            (
                "content-type".to_string(),
                "application/x-amz-json-1.1".to_string(),
            ),
            ("host".to_string(), self.host.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
            (
                "x-amz-target".to_string(),
                format!("secretsmanager.{action}"),
            ),
        ]);
        let keys = self.auth.current().await?;
        if let Some(t) = &keys.session_token {
            headers.insert("x-amz-security-token".to_string(), t.clone());
        }
        let authorization = SigV4 {
            access_key: &keys.access_key,
            secret_key: &keys.secret_key,
            region: &self.region,
            service: "secretsmanager",
            method: "POST",
            path: "/",
            query: "",
            headers: &headers,
            body: payload.as_bytes(),
            amz_date: &amz_date,
        }
        .authorization();
        let mut req = self.http.post(format!("{}/", self.endpoint));
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k, v);
            }
        }
        let res = req
            .header("authorization", authorization)
            .body(payload)
            .send()
            .await
            .map_err(|e| err(format!("AWS Secrets Manager {action}: {e}")))?;
        let status = res.status().as_u16();
        Ok((status, res.json().await.unwrap_or(Value::Null)))
    }

    fn failure(action: &str, status: u16, v: &Value) -> Error {
        let kind = v["__type"].as_str().unwrap_or("");
        let message = v["message"]
            .as_str()
            .or_else(|| v["Message"].as_str())
            .unwrap_or("");
        err(format!(
            "AWS Secrets Manager {action} refused (HTTP {status} {kind}): {message}"
        ))
    }

    fn is_missing(v: &Value) -> bool {
        v["__type"]
            .as_str()
            .is_some_and(|t| t.ends_with("ResourceNotFoundException"))
    }

    async fn read(&self, provider: &str) -> Result<Option<Map<String, Value>>> {
        let (status, v) = self
            .call(
                "GetSecretValue",
                &json!({"SecretId": self.secret_id(provider)?}),
            )
            .await?;
        if status == 200 {
            let text = v["SecretString"].as_str().unwrap_or("{}");
            return Ok(Some(
                serde_json::from_str::<Value>(text)
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .unwrap_or_default(),
            ));
        }
        // a secret scheduled for deletion is not readable either
        if Self::is_missing(&v)
            || v["__type"]
                .as_str()
                .is_some_and(|t| t.ends_with("InvalidRequestException"))
        {
            return Ok(None);
        }
        Err(Self::failure("GetSecretValue", status, &v))
    }

    async fn write(&self, provider: &str, data: &Map<String, Value>) -> Result<()> {
        let id = self.secret_id(provider)?;
        let text = Value::Object(data.clone()).to_string();
        let (status, v) = self
            .call(
                "PutSecretValue",
                // raw REST must send the idempotency token the SDKs fill in themselves
                &json!({"SecretId": id, "SecretString": text, "ClientRequestToken": request_token()}),
            )
            .await?;
        if status == 200 {
            return Ok(());
        }
        if !Self::is_missing(&v) {
            return Err(Self::failure("PutSecretValue", status, &v));
        }
        let mut create = json!({
            "Name": id, "SecretString": text,
            "Description": "Managed by DimensionLab Frontier",
            "ClientRequestToken": request_token(),
        });
        if let Some(k) = &self.kms_key_id {
            create["KmsKeyId"] = json!(k);
        }
        let (status, v) = self.call("CreateSecret", &create).await?;
        if status == 200 {
            Ok(())
        } else {
            Err(Self::failure("CreateSecret", status, &v))
        }
    }

    /// Can the store sign a request the service accepts? For `frontier secrets backend test`.
    pub fn check(&self) -> Result<String> {
        block_on(async {
            self.read("frontier-connection-test").await?;
            Ok(self.describe())
        })?
    }
}

/// AWS KMS, for wrapping the master key of the control plane's encrypted credential table
/// (envelope encryption): the key file then holds a data key only KMS can unwrap.
pub struct AwsKms {
    http: reqwest::Client,
    endpoint: String,
    host: String,
    region: String,
    key_id: String,
    auth: std::sync::Arc<AwsAuth>,
}

impl AwsKms {
    pub fn from_config(config: &Config) -> Result<Self> {
        let sm = AwsSecretsManagerStore::from_config(config)?;
        let key_id = sm.kms_key_id.clone().ok_or_else(|| {
            err("wrapping the server key with KMS needs secrets.aws.kms_key_id (a key id, ARN or alias)")
        })?;
        let endpoint = match config.str("secrets.aws.kms_endpoint").trim_end_matches('/') {
            "" => format!("https://kms.{}.amazonaws.com", sm.region),
            e => e.to_string(),
        };
        let host = endpoint
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(rest).to_string())
            .ok_or_else(|| err("secrets.aws.kms_endpoint is not a URL"))?;
        Ok(Self {
            http: sm.http,
            endpoint,
            host,
            region: sm.region,
            key_id,
            auth: sm.auth,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn call(&self, action: &str, body: &Value) -> Result<Value> {
        let payload = body.to_string();
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut headers = BTreeMap::from([
            (
                "content-type".to_string(),
                "application/x-amz-json-1.1".to_string(),
            ),
            ("host".to_string(), self.host.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
            ("x-amz-target".to_string(), format!("TrentService.{action}")),
        ]);
        let keys = self.auth.current().await?;
        if let Some(t) = &keys.session_token {
            headers.insert("x-amz-security-token".to_string(), t.clone());
        }
        let authorization = SigV4 {
            access_key: &keys.access_key,
            secret_key: &keys.secret_key,
            region: &self.region,
            service: "kms",
            method: "POST",
            path: "/",
            query: "",
            headers: &headers,
            body: payload.as_bytes(),
            amz_date: &amz_date,
        }
        .authorization();
        let mut req = self.http.post(format!("{}/", self.endpoint));
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k, v);
            }
        }
        let res = req
            .header("authorization", authorization)
            .body(payload)
            .send()
            .await
            .map_err(|e| err(format!("AWS KMS {action}: {e}")))?;
        let status = res.status().as_u16();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if status != 200 {
            return Err(err(format!(
                "AWS KMS {action} refused (HTTP {status} {}): {}",
                v["__type"].as_str().unwrap_or(""),
                v["message"]
                    .as_str()
                    .or_else(|| v["Message"].as_str())
                    .unwrap_or("")
            )));
        }
        Ok(v)
    }

    /// A new 256-bit data key: `(plaintext key, wrapped key as base64)`. The plaintext is
    /// used in memory; only the wrapped form is written to disk.
    pub fn generate_data_key(&self) -> Result<([u8; 32], String)> {
        use base64::Engine;
        block_on(async {
            let v = self
                .call(
                    "GenerateDataKey",
                    &json!({"KeyId": self.key_id, "KeySpec": "AES_256"}),
                )
                .await?;
            let plain = base64::engine::general_purpose::STANDARD
                .decode(v["Plaintext"].as_str().unwrap_or(""))
                .map_err(|_| err("AWS KMS returned an unreadable data key"))?;
            let key: [u8; 32] = plain
                .try_into()
                .map_err(|_| err("AWS KMS returned a data key that is not 256 bits"))?;
            let wrapped = v["CiphertextBlob"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| err("AWS KMS returned no wrapped key"))?;
            Ok((key, wrapped.to_string()))
        })?
    }

    /// Unwrap a data key written by [`AwsKms::generate_data_key`].
    pub fn decrypt(&self, wrapped_b64: &str) -> Result<[u8; 32]> {
        use base64::Engine;
        block_on(async {
            let v = self
                .call(
                    "Decrypt",
                    &json!({"CiphertextBlob": wrapped_b64.trim(), "KeyId": self.key_id}),
                )
                .await?;
            base64::engine::general_purpose::STANDARD
                .decode(v["Plaintext"].as_str().unwrap_or(""))
                .ok()
                .and_then(|p| <[u8; 32]>::try_from(p).ok())
                .ok_or_else(|| {
                    err("AWS KMS did not return a 256-bit key for the wrapped server key")
                })
        })?
    }
}

/// The remote store named by `backend` (`vault` or `aws`), from the `secrets.*` settings.
pub fn open_remote(config: &Config, backend: &str) -> Result<Box<dyn SecretStore>> {
    match backend {
        "vault" => Ok(Box::new(VaultStore::from_config(config)?)),
        "aws" => Ok(Box::new(AwsSecretsManagerStore::from_config(config)?)),
        "azure" => Ok(Box::new(super::remote_cloud::AzureKeyVaultStore::from_config(config)?)),
        "gcp" => Ok(Box::new(super::remote_cloud::GcpSecretManagerStore::from_config(config)?)),
        other => Err(err(format!(
            "`{other}` is not a remote secret store (vault, aws)"
        ))),
    }
}

impl SecretStore for AwsSecretsManagerStore {
    fn name(&self) -> &'static str {
        "aws"
    }
    fn describe(&self) -> String {
        format!(
            "AWS Secrets Manager {} (names `{}/<provider>`{})",
            self.region,
            self.prefix,
            match &self.kms_key_id {
                Some(k) => format!(", KMS key {k}"),
                None => String::new(),
            }
        )
    }
    fn get(&self, provider: &str, field: &str) -> Result<Option<String>> {
        block_on(async {
            Ok(self
                .read(provider)
                .await?
                .and_then(|m| m.get(field).and_then(Value::as_str).map(str::to_string)))
        })?
    }
    fn set(&self, provider: &str, field: &str, value: &str) -> Result<()> {
        block_on(async {
            let mut data = self.read(provider).await?.unwrap_or_default();
            data.insert(field.to_string(), Value::String(value.to_string()));
            self.write(provider, &data).await
        })?
    }
    fn delete(&self, provider: &str, field: &str) -> Result<bool> {
        block_on(async {
            let Some(mut data) = self.read(provider).await? else {
                return Ok(false);
            };
            if data.remove(field).is_none() {
                return Ok(false);
            }
            if !data.is_empty() {
                // Twice: the version that still held the removed field then carries no
                // staging label (neither AWSCURRENT nor AWSPREVIOUS), so it cannot be read
                // by label any more and Secrets Manager discards it.
                self.write(provider, &data).await?;
                self.write(provider, &data).await?;
                return Ok(true);
            }
            let (status, v) = self
                .call(
                    "DeleteSecret",
                    &json!({"SecretId": self.secret_id(provider)?, "ForceDeleteWithoutRecovery": true}),
                )
                .await?;
            if status == 200 || Self::is_missing(&v) {
                Ok(true)
            } else {
                Err(Self::failure("DeleteSecret", status, &v))
            }
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example of the AWS documentation ("Signature Version 4 signing process",
    /// GET iam ListUsers on 2015-08-30).
    #[test]
    fn sigv4_matches_the_published_example() {
        let headers = BTreeMap::from([
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            ),
            ("host".to_string(), "iam.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ]);
        let auth = SigV4 {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "iam",
            method: "GET",
            path: "/",
            query: "Action=ListUsers&Version=2010-05-08",
            headers: &headers,
            body: b"",
            amz_date: "20150830T123600Z",
        }
        .authorization();
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        // test case 2
        assert_eq!(
            hex(&hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // test case 6: a key longer than the block
        assert_eq!(
            hex(&hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn secret_names_cannot_escape_their_prefix() {
        assert_eq!(clean_prefix("/frontier/prod/").unwrap(), "frontier/prod");
        assert!(clean_prefix("frontier/../other").is_err());
        assert!(safe_segment("hugging/face").is_err());
        assert!(safe_segment("..").is_err());
        assert_eq!(safe_segment("frontier-server").unwrap(), "frontier-server");
    }
}
