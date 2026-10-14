// SPDX-License-Identifier: Apache-2.0
//! Azure Key Vault and Google Secret Manager as secret stores, over plain REST.
//!
//! Like the Vault and AWS stores (`super::remote`), each keeps one secret per credential
//! provider whose value is a JSON object `{field: value}`. Both services restrict secret
//! names to letters, digits and dashes (Google also allows `_`), so the name is
//! `<prefix>-<provider>` with every other character of the provider id written as `-xx-`
//! (its hex code): distinct ids never share a name.
//!
//! **Verification status: contract tests against in-process doubles only.** Neither store
//! has been run against the real service.

use super::remote::{block_on, clean_prefix, client, err, non_empty, secret_from_env_or_file};
use super::store::SecretStore;
use crate::Result;
use crate::loader::Config;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `<prefix>-<provider>` in the alphabet both services accept.
fn cloud_name(prefix: &str, provider: &str, allow_underscore: bool) -> Result<String> {
    if provider.is_empty()
        || provider.len() > 100
        || provider.starts_with('.')
        || provider.contains('/')
    {
        return Err(err(format!("`{provider}` cannot be part of a secret name")));
    }
    let mut out = String::new();
    for part in prefix.split('/').filter(|p| !p.is_empty()) {
        out.push_str(part);
        out.push('-');
    }
    for c in provider.chars() {
        if c.is_ascii_alphanumeric() || (allow_underscore && c == '_') {
            out.push(c);
        } else {
            out.push_str(&format!("-{:02x}-", c as u32));
        }
    }
    let ok = out
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || (allow_underscore && c == '_'));
    if ok && out.len() <= 127 {
        Ok(out)
    } else {
        Err(err(format!(
            "`{out}` is not a usable secret name (check the prefix)"
        )))
    }
}

/// A bearer token with the time to fetch the next one.
#[derive(Default)]
struct TokenCache(Mutex<Option<(String, Instant)>>);

impl TokenCache {
    fn get(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(t, _)| t.clone())
    }
    fn put(&self, token: &str, expires_in: u64) {
        let keep = Duration::from_secs(expires_in.saturating_sub(120).max(1));
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((token.to_string(), Instant::now() + keep));
    }
}

fn parse_map(text: &str) -> Map<String, Value> {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

// -- Azure Key Vault -------------------------------------------------------------------------

const AZURE_API: &str = "api-version=7.4";

enum AzureAuth {
    ManagedIdentity {
        client_id: Option<String>,
        endpoint: String,
    },
    ClientSecret {
        authority: String,
        tenant: String,
        client_id: String,
        secret: String,
    },
}

pub struct AzureKeyVaultStore {
    http: reqwest::Client,
    vault_url: String,
    prefix: String,
    auth: AzureAuth,
    token: TokenCache,
}

impl AzureKeyVaultStore {
    pub fn from_config(config: &Config) -> Result<Self> {
        let vault_url = config
            .str("secrets.azure.vault_url")
            .trim_end_matches('/')
            .to_string();
        if !vault_url.starts_with("https://") && !vault_url.starts_with("http://") {
            return Err(err(
                "secrets.backend = \"azure\" needs secrets.azure.vault_url (for example https://frontier-prod.vault.azure.net)",
            ));
        }
        crate::http::require_online(config, "reaching Azure Key Vault", &vault_url).map_err(err)?;
        let env = config.env();
        let setting_or_env = |key: &str, var: &str| {
            let v = config.str(key).trim().to_string();
            if v.is_empty() {
                env.get(var)
                    .map(|v| v.trim().to_string())
                    .unwrap_or_default()
            } else {
                v
            }
        };
        let client_id = setting_or_env("secrets.azure.client_id", "AZURE_CLIENT_ID");
        let auth = match config.str("secrets.azure.auth") {
            "client_secret" => AzureAuth::ClientSecret {
                authority: match config.str("secrets.azure.authority").trim_end_matches('/') {
                    "" => "https://login.microsoftonline.com".to_string(),
                    a => a.to_string(),
                },
                tenant: non_empty(
                    &setting_or_env("secrets.azure.tenant_id", "AZURE_TENANT_ID"),
                    "secrets.azure.tenant_id (or AZURE_TENANT_ID)",
                )?,
                client_id: non_empty(&client_id, "secrets.azure.client_id (or AZURE_CLIENT_ID)")?,
                secret: secret_from_env_or_file(
                    config,
                    "secrets.azure.credential_file",
                    &["AZURE_CLIENT_SECRET"],
                    "the Azure client secret",
                )?,
            },
            _ => AzureAuth::ManagedIdentity {
                client_id: Some(client_id).filter(|c| !c.is_empty()),
                // the instance metadata service; overridable where a platform provides its own
                endpoint: env
                    .get("FRONTIER_AZURE_IMDS_ENDPOINT")
                    .cloned()
                    .unwrap_or_else(|| "http://169.254.169.254".to_string()),
            },
        };
        Ok(Self {
            http: client(config)?,
            vault_url,
            prefix: clean_prefix(config.str("secrets.azure.prefix"))?,
            auth,
            token: TokenCache::default(),
        })
    }

    async fn bearer(&self) -> Result<String> {
        if let Some(t) = self.token.get() {
            return Ok(t);
        }
        let res = match &self.auth {
            AzureAuth::ClientSecret { authority, tenant, client_id, secret } => self
                .http
                .post(format!("{authority}/{tenant}/oauth2/v2.0/token"))
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id.as_str()),
                    ("client_secret", secret.as_str()),
                    ("scope", "https://vault.azure.net/.default"),
                ])
                .send()
                .await,
            AzureAuth::ManagedIdentity { client_id, endpoint } => {
                let mut url = format!(
                    "{}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net",
                    endpoint.trim_end_matches('/')
                );
                if let Some(id) = client_id {
                    url.push_str(&format!("&client_id={id}"));
                }
                self.http.get(url).header("Metadata", "true").timeout(Duration::from_secs(5)).send().await
            }
        }
        .map_err(|e| err(format!("Azure sign-in: {e}")))?;
        let status = res.status();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        let token = v["access_token"].as_str().ok_or_else(|| {
            err(format!(
                "Azure sign-in refused (HTTP {status}): {}",
                v["error_description"]
                    .as_str()
                    .or(v["error"].as_str())
                    .unwrap_or("no access token")
            ))
        })?;
        let expires = v["expires_in"]
            .as_u64()
            .or_else(|| v["expires_in"].as_str()?.parse().ok())
            .unwrap_or(300);
        self.token.put(token, expires);
        Ok(token.to_string())
    }

    fn name(&self, provider: &str) -> Result<String> {
        cloud_name(&self.prefix, provider, false)
    }

    fn failure(what: &str, status: reqwest::StatusCode, v: &Value) -> crate::Error {
        err(format!(
            "Azure Key Vault {what} refused (HTTP {status} {}): {}",
            v["error"]["code"].as_str().unwrap_or(""),
            v["error"]["message"].as_str().unwrap_or("")
        ))
    }

    async fn read(&self, provider: &str) -> Result<Option<Map<String, Value>>> {
        let url = format!(
            "{}/secrets/{}?{AZURE_API}",
            self.vault_url,
            self.name(provider)?
        );
        let res = self
            .http
            .get(url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await
            .map_err(|e| err(format!("Azure Key Vault read: {e}")))?;
        let status = res.status();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Self::failure("read", status, &v));
        }
        Ok(Some(parse_map(v["value"].as_str().unwrap_or("{}"))))
    }

    async fn write(&self, provider: &str, data: &Map<String, Value>) -> Result<()> {
        let url = format!(
            "{}/secrets/{}?{AZURE_API}",
            self.vault_url,
            self.name(provider)?
        );
        let body = json!({"value": Value::Object(data.clone()).to_string(), "contentType": "application/json", "tags": {"managed-by": "frontier"}});
        let res = self
            .http
            .put(url)
            .bearer_auth(self.bearer().await?)
            .json(&body)
            .send()
            .await
            .map_err(|e| err(format!("Azure Key Vault write: {e}")))?;
        let status = res.status();
        if !status.is_success() {
            return Err(Self::failure(
                "write",
                status,
                &res.json().await.unwrap_or(Value::Null),
            ));
        }
        Ok(())
    }

    /// Delete the secret and, where soft-delete keeps it recoverable, purge it.
    async fn remove(&self, provider: &str) -> Result<()> {
        let name = self.name(provider)?;
        let token = self.bearer().await?;
        let res = self
            .http
            .delete(format!("{}/secrets/{name}?{AZURE_API}", self.vault_url))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| err(format!("Azure Key Vault delete: {e}")))?;
        if !res.status().is_success() && res.status() != reqwest::StatusCode::NOT_FOUND {
            let status = res.status();
            return Err(Self::failure(
                "delete",
                status,
                &res.json().await.unwrap_or(Value::Null),
            ));
        }
        // purge: 204 when purged, 404 when the vault has no soft-delete copy, 409 while the
        // deletion is still in progress (a moment later it can be purged; try a few times)
        for _ in 0..10 {
            let res = self
                .http
                .delete(format!(
                    "{}/deletedsecrets/{name}?{AZURE_API}",
                    self.vault_url
                ))
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| err(format!("Azure Key Vault purge: {e}")))?;
            match res.status().as_u16() {
                200 | 204 | 404 => return Ok(()),
                409 => tokio::time::sleep(Duration::from_millis(500)).await,
                // a vault with purge protection refuses: the value stays recoverable for the
                // retention period, which the caller is told
                403 => {
                    return Err(err(
                        "Azure Key Vault deleted the secret but refused to purge it (purge protection or a missing `purge` permission): it stays recoverable for the vault's retention period",
                    ));
                }
                _ => {
                    let status = res.status();
                    return Err(Self::failure(
                        "purge",
                        status,
                        &res.json().await.unwrap_or(Value::Null),
                    ));
                }
            }
        }
        Err(err(
            "Azure Key Vault is still deleting the secret; it was not purged",
        ))
    }
}

macro_rules! map_store {
    ($ty:ty, $name:literal) => {
        impl SecretStore for $ty {
            fn name(&self) -> &'static str {
                $name
            }
            fn describe(&self) -> String {
                self.describe_store()
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
                    // every version goes; what remains is written again as a fresh secret
                    self.remove(provider).await?;
                    if !data.is_empty() {
                        self.write(provider, &data).await?;
                    }
                    Ok(true)
                })?
            }
        }
    };
}

impl AzureKeyVaultStore {
    fn describe_store(&self) -> String {
        format!(
            "Azure Key Vault {} (names `{}-<provider>`, auth {})",
            self.vault_url,
            self.prefix.replace('/', "-"),
            match self.auth {
                AzureAuth::ManagedIdentity { .. } => "managed identity",
                AzureAuth::ClientSecret { .. } => "client secret",
            }
        )
    }
}
map_store!(AzureKeyVaultStore, "azure");

// -- Google Secret Manager ---------------------------------------------------------------------

enum GcpAuth {
    Metadata {
        endpoint: String,
    },
    ServiceAccount {
        client_email: String,
        private_key_pem: String,
        token_uri: String,
    },
}

pub struct GcpSecretManagerStore {
    http: reqwest::Client,
    endpoint: String,
    project: String,
    prefix: String,
    auth: GcpAuth,
    token: TokenCache,
}

/// A service-account assertion (RFC 7523): an RS256 JWT asking for the cloud-platform scope.
pub fn gcp_assertion(
    client_email: &str,
    private_key_pem: &str,
    token_uri: &str,
    now: i64,
) -> Result<String> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding, Signer};
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|_| err("the service-account key file holds no usable private key"))?;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = json!({
        "iss": client_email, "sub": client_email,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": token_uri, "iat": now, "exp": now + 3600,
    });
    let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
    let signature = SigningKey::<Sha256>::new(key).sign(signed.as_bytes());
    Ok(format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

impl GcpSecretManagerStore {
    pub fn from_config(config: &Config) -> Result<Self> {
        let env = config.env();
        let endpoint = match config.str("secrets.gcp.endpoint").trim_end_matches('/') {
            "" => "https://secretmanager.googleapis.com".to_string(),
            e => e.to_string(),
        };
        crate::http::require_online(config, "reaching Google Secret Manager", &endpoint)
            .map_err(err)?;
        let project = [config.str("secrets.gcp.project").trim().to_string()]
            .into_iter()
            .chain(
                ["GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT"]
                    .iter()
                    .filter_map(|n| env.get(*n).cloned()),
            )
            .find(|p| !p.is_empty())
            .ok_or_else(|| {
                err("secrets.backend = \"gcp\" needs secrets.gcp.project (or GOOGLE_CLOUD_PROJECT)")
            })?;
        if !project
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | ':' | '.'))
        {
            return Err(err(format!("`{project}` is not a Google Cloud project id")));
        }
        let auth = match config.str("secrets.gcp.auth") {
            "service_account" => {
                let path = config
                    .path("secrets.gcp.credential_file")
                    .or_else(|| env.get("GOOGLE_APPLICATION_CREDENTIALS").filter(|p| !p.is_empty()).map(Into::into))
                    .ok_or_else(|| err("service_account authentication needs secrets.gcp.credential_file (or GOOGLE_APPLICATION_CREDENTIALS)"))?;
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| err(format!("{}: {e}", path.display())))?;
                let v: Value = serde_json::from_str(&text)
                    .map_err(|_| err(format!("{} is not a JSON key file", path.display())))?;
                let field = |k: &str| v[k].as_str().filter(|s| !s.is_empty()).map(str::to_string);
                GcpAuth::ServiceAccount {
                    client_email: field("client_email")
                        .ok_or_else(|| err("the key file has no client_email"))?,
                    private_key_pem: field("private_key")
                        .ok_or_else(|| err("the key file has no private_key"))?,
                    token_uri: field("token_uri")
                        .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string()),
                }
            }
            _ => GcpAuth::Metadata {
                endpoint: env
                    .get("GCE_METADATA_HOST")
                    .map(|h| {
                        if h.contains("://") {
                            h.clone()
                        } else {
                            format!("http://{h}")
                        }
                    })
                    .unwrap_or_else(|| "http://metadata.google.internal".to_string()),
            },
        };
        Ok(Self {
            http: client(config)?,
            endpoint,
            project,
            prefix: clean_prefix(config.str("secrets.gcp.prefix"))?,
            auth,
            token: TokenCache::default(),
        })
    }

    async fn bearer(&self) -> Result<String> {
        if let Some(t) = self.token.get() {
            return Ok(t);
        }
        let res = match &self.auth {
            GcpAuth::Metadata { endpoint } => {
                self.http
                    .get(format!(
                        "{}/computeMetadata/v1/instance/service-accounts/default/token",
                        endpoint.trim_end_matches('/')
                    ))
                    .header("Metadata-Flavor", "Google")
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await
            }
            GcpAuth::ServiceAccount {
                client_email,
                private_key_pem,
                token_uri,
            } => {
                let assertion = gcp_assertion(
                    client_email,
                    private_key_pem,
                    token_uri,
                    chrono::Utc::now().timestamp(),
                )?;
                self.http
                    .post(token_uri)
                    .form(&[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                        ("assertion", assertion.as_str()),
                    ])
                    .send()
                    .await
            }
        }
        .map_err(|e| err(format!("Google sign-in: {e}")))?;
        let status = res.status();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        let token = v["access_token"].as_str().ok_or_else(|| {
            err(format!(
                "Google sign-in refused (HTTP {status}): {}",
                v["error_description"]
                    .as_str()
                    .or(v["error"].as_str())
                    .unwrap_or("no access token")
            ))
        })?;
        self.token
            .put(token, v["expires_in"].as_u64().unwrap_or(300));
        Ok(token.to_string())
    }

    fn secret_path(&self, provider: &str) -> Result<String> {
        Ok(format!(
            "projects/{}/secrets/{}",
            self.project,
            cloud_name(&self.prefix, provider, true)?
        ))
    }

    fn failure(what: &str, status: reqwest::StatusCode, v: &Value) -> crate::Error {
        err(format!(
            "Google Secret Manager {what} refused (HTTP {status} {}): {}",
            v["error"]["status"].as_str().unwrap_or(""),
            v["error"]["message"].as_str().unwrap_or("")
        ))
    }

    async fn read(&self, provider: &str) -> Result<Option<Map<String, Value>>> {
        let url = format!(
            "{}/v1/{}/versions/latest:access",
            self.endpoint,
            self.secret_path(provider)?
        );
        let res = self
            .http
            .get(url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await
            .map_err(|e| err(format!("Google Secret Manager read: {e}")))?;
        let status = res.status();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Self::failure("read", status, &v));
        }
        let bytes = STANDARD
            .decode(v["payload"]["data"].as_str().unwrap_or(""))
            .map_err(|_| err("Google Secret Manager returned a payload that is not base64"))?;
        Ok(Some(parse_map(&String::from_utf8_lossy(&bytes))))
    }

    async fn write(&self, provider: &str, data: &Map<String, Value>) -> Result<()> {
        let path = self.secret_path(provider)?;
        let token = self.bearer().await?;
        let payload =
            json!({"payload": {"data": STANDARD.encode(Value::Object(data.clone()).to_string())}});
        let add = || async {
            self.http
                .post(format!("{}/v1/{path}:addVersion", self.endpoint))
                .bearer_auth(&token)
                .json(&payload)
                .send()
                .await
                .map_err(|e| err(format!("Google Secret Manager write: {e}")))
        };
        let res = add().await?;
        if res.status().is_success() {
            return Ok(());
        }
        if res.status() != reqwest::StatusCode::NOT_FOUND {
            let status = res.status();
            return Err(Self::failure(
                "write",
                status,
                &res.json().await.unwrap_or(Value::Null),
            ));
        }
        // the secret does not exist yet: create it, then add the first version
        let id = path.rsplit('/').next().unwrap_or_default().to_string();
        let res = self
            .http
            .post(format!(
                "{}/v1/projects/{}/secrets?secretId={id}",
                self.endpoint, self.project
            ))
            .bearer_auth(&token)
            .json(&json!({"replication": {"automatic": {}}, "labels": {"managed-by": "frontier"}}))
            .send()
            .await
            .map_err(|e| err(format!("Google Secret Manager create: {e}")))?;
        if !res.status().is_success() && res.status() != reqwest::StatusCode::CONFLICT {
            let status = res.status();
            return Err(Self::failure(
                "create",
                status,
                &res.json().await.unwrap_or(Value::Null),
            ));
        }
        let res = add().await?;
        if res.status().is_success() {
            Ok(())
        } else {
            let status = res.status();
            Err(Self::failure(
                "write",
                status,
                &res.json().await.unwrap_or(Value::Null),
            ))
        }
    }

    /// Delete the secret with every version.
    async fn remove(&self, provider: &str) -> Result<()> {
        let url = format!("{}/v1/{}", self.endpoint, self.secret_path(provider)?);
        let res = self
            .http
            .delete(url)
            .bearer_auth(self.bearer().await?)
            .send()
            .await
            .map_err(|e| err(format!("Google Secret Manager delete: {e}")))?;
        if res.status().is_success() || res.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            let status = res.status();
            Err(Self::failure(
                "delete",
                status,
                &res.json().await.unwrap_or(Value::Null),
            ))
        }
    }

    fn describe_store(&self) -> String {
        format!(
            "Google Secret Manager, project {} (ids `{}-<provider>`, auth {})",
            self.project,
            self.prefix.replace('/', "-"),
            match self.auth {
                GcpAuth::Metadata { .. } => "metadata server",
                GcpAuth::ServiceAccount { .. } => "service-account key",
            }
        )
    }
}
map_store!(GcpSecretManagerStore, "gcp");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_fit_both_services_and_stay_distinct() {
        assert_eq!(
            cloud_name("frontier", "huggingface", false).unwrap(),
            "frontier-huggingface"
        );
        assert_eq!(
            cloud_name("frontier/prod", "s3", false).unwrap(),
            "frontier-prod-s3"
        );
        // characters a service does not allow are spelled out, so ids cannot collide
        let a = cloud_name("f", "runpod+project.p1", false).unwrap();
        let b = cloud_name("f", "runpod-project-p1", false).unwrap();
        assert_ne!(a, b);
        assert!(
            a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "{a}"
        );
        assert_eq!(
            cloud_name("f", "frontier_server", true).unwrap(),
            "f-frontier_server"
        );
        assert_ne!(
            cloud_name("f", "frontier_server", false).unwrap(),
            "f-frontier_server"
        );
        assert!(cloud_name("f", "../x", false).is_err());
        assert!(cloud_name("f", "", false).is_err());
    }
}
