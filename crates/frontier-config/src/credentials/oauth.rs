// SPDX-License-Identifier: Apache-2.0
//! OAuth 2.0 for credential providers that declare `[auth.oauth]`: the device
//! authorization flow (RFC 8628, for terminals and headless servers), the authorization-code
//! flow with PKCE (RFC 7636, desktop loopback redirect or a server callback), and refresh.
//! Public clients only. Building requests and reading responses is pure; sending needs the
//! `http` feature.
//!
//! A sign-in stores a token set with the provider: the access token in the provider's
//! primary secret field, plus `refresh_token` and `expires_at`. [`access_token`] refreshes
//! an expired token before handing it out.

use super::{AuthProvider, OAuthConfig};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;

pub const ACCESS_TOKEN: &str = "access_token";
pub const REFRESH_TOKEN: &str = "refresh_token";
pub const EXPIRES_AT: &str = "expires_at";
/// Refresh this long before the recorded expiry.
pub const EXPIRY_SLACK_SECS: i64 = 60;

/// Tokens returned by a token endpoint. `Debug` never shows them.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TokenSet {{ access_token: ***, refresh_token: {}, expires_at: {:?} }}",
            if self.refresh_token.is_some() {
                "***"
            } else {
                "none"
            },
            self.expires_at
        )
    }
}

impl TokenSet {
    /// The field values to store for `provider`.
    pub fn fields(&self, provider: &AuthProvider) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let primary = provider
            .primary()
            .map(|f| f.name.clone())
            .unwrap_or_else(|| ACCESS_TOKEN.to_string());
        out.insert(primary, self.access_token.clone());
        if let Some(r) = &self.refresh_token {
            out.insert(REFRESH_TOKEN.to_string(), r.clone());
        }
        if let Some(at) = self.expires_at {
            out.insert(EXPIRES_AT.to_string(), at.to_rfc3339());
        }
        out
    }
}

/// Why a token request did not return tokens.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    /// Device flow: the user has not finished yet; poll again after the interval.
    #[error("waiting for the sign-in to be completed")]
    Pending,
    /// Device flow: polling too fast; add 5 seconds to the interval.
    #[error("polling too fast")]
    SlowDown,
    #[error("the sign-in was refused")]
    Denied,
    #[error("the sign-in expired before it was completed; start again")]
    Expired,
    #[error("{0}")]
    Other(String),
}

/// What a device authorization endpoint answers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeviceStart {
    #[serde(skip)]
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    /// Seconds between polls.
    pub interval: u64,
    pub expires_in: u64,
}

/// Percent-encode a query or form value.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The URL the user's browser opens for the authorization-code flow.
pub fn authorize_url(
    cfg: &OAuthConfig,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String, String> {
    let base = cfg
        .authorize_url
        .as_deref()
        .ok_or("the provider declares no authorize_url")?;
    let scopes = cfg.scopes.join(" ");
    let query = form(&[
        ("response_type", "code"),
        ("client_id", &cfg.client_id),
        ("redirect_uri", redirect_uri),
        ("scope", &scopes),
        ("state", state),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("audience", cfg.audience.as_deref().unwrap_or_default()),
    ]);
    Ok(format!(
        "{base}{}{query}",
        if base.contains('?') { '&' } else { '?' }
    ))
}

/// Body of the device authorization request.
pub fn device_request_body(cfg: &OAuthConfig) -> String {
    form(&[
        ("client_id", &cfg.client_id),
        ("scope", &cfg.scopes.join(" ")),
        ("audience", cfg.audience.as_deref().unwrap_or_default()),
    ])
}

pub fn device_token_body(cfg: &OAuthConfig, device_code: &str) -> String {
    form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", &cfg.client_id),
    ])
}

pub fn code_token_body(
    cfg: &OAuthConfig,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &cfg.client_id),
        ("code_verifier", verifier),
    ])
}

pub fn refresh_body(cfg: &OAuthConfig, refresh_token: &str) -> String {
    form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &cfg.client_id),
    ])
}

/// Read a device authorization response.
pub fn parse_device_response(status: u16, body: &str) -> Result<DeviceStart, OAuthError> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(OAuthError::Other(format!(
            "the device authorization endpoint answered HTTP {status}{}",
            describe(&v)
        )));
    }
    let text = |k: &str| v[k].as_str().map(str::to_string);
    match (text("device_code"), text("user_code"), text("verification_uri").or_else(|| text("verification_url"))) {
        (Some(device_code), Some(user_code), Some(verification_uri)) => Ok(DeviceStart {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete: text("verification_uri_complete"),
            interval: v["interval"].as_u64().unwrap_or(5).max(1),
            expires_in: v["expires_in"].as_u64().unwrap_or(900),
        }),
        _ => Err(OAuthError::Other(
            "the device authorization endpoint answered without device_code, user_code and verification_uri".into(),
        )),
    }
}

fn describe(v: &serde_json::Value) -> String {
    match (v["error"].as_str(), v["error_description"].as_str()) {
        (Some(e), Some(d)) => format!(": {e} ({d})"),
        (Some(e), None) => format!(": {e}"),
        _ => String::new(),
    }
}

/// Read a token endpoint response (any grant).
pub fn parse_token_response(
    status: u16,
    body: &str,
    now: DateTime<Utc>,
) -> Result<TokenSet, OAuthError> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    if let Some(err) = v["error"].as_str() {
        return Err(match err {
            "authorization_pending" => OAuthError::Pending,
            "slow_down" => OAuthError::SlowDown,
            "access_denied" => OAuthError::Denied,
            "expired_token" => OAuthError::Expired,
            _ => OAuthError::Other(format!(
                "the token endpoint refused the request{}",
                describe(&v)
            )),
        });
    }
    if !(200..300).contains(&status) {
        return Err(OAuthError::Other(format!(
            "the token endpoint answered HTTP {status}"
        )));
    }
    let Some(access_token) = v["access_token"].as_str().filter(|s| !s.is_empty()) else {
        return Err(OAuthError::Other(
            "the token endpoint answered without an access_token".into(),
        ));
    };
    Ok(TokenSet {
        access_token: access_token.to_string(),
        refresh_token: v["refresh_token"].as_str().map(str::to_string),
        expires_at: v["expires_in"]
            .as_i64()
            .or_else(|| v["expires_in"].as_str().and_then(|s| s.parse().ok()))
            .map(|secs| now + Duration::seconds(secs)),
        scope: v["scope"].as_str().map(str::to_string),
    })
}

/// Is a stored `expires_at` (RFC 3339) in the past, allowing for [`EXPIRY_SLACK_SECS`]?
pub fn expired(expires_at: Option<&str>, now: DateTime<Utc>) -> bool {
    expires_at
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .is_some_and(|t| t.with_timezone(&Utc) <= now + Duration::seconds(EXPIRY_SLACK_SECS))
}

#[cfg(feature = "http")]
mod net {
    use super::*;
    use crate::credentials::Resolver;
    use crate::loader::Config;
    use base64::Engine;
    use sha2::Digest;

    fn random_bytes<const N: usize>() -> Result<[u8; N], OAuthError> {
        let mut buf = [0u8; N];
        getrandom::fill(&mut buf)
            .map_err(|e| OAuthError::Other(format!("no random numbers available: {e}")))?;
        Ok(buf)
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A PKCE `(code_verifier, code_challenge)` pair (S256).
    pub fn pkce_pair() -> Result<(String, String), OAuthError> {
        let verifier = b64(&random_bytes::<32>()?);
        let challenge = challenge_for(&verifier);
        Ok((verifier, challenge))
    }

    /// The S256 challenge of a verifier.
    pub fn challenge_for(verifier: &str) -> String {
        b64(&sha2::Sha256::digest(verifier.as_bytes()))
    }

    /// An unguessable `state` value.
    pub fn random_state() -> Result<String, OAuthError> {
        Ok(b64(&random_bytes::<24>()?))
    }

    fn config_of(provider: &AuthProvider) -> Result<&OAuthConfig, OAuthError> {
        provider.oauth.as_ref().ok_or_else(|| {
            OAuthError::Other(format!("{} does not sign in with OAuth", provider.title))
        })
    }

    async fn post_form(
        config: &Config,
        url: &str,
        body: String,
    ) -> Result<(u16, String), OAuthError> {
        if config.bool("network.offline") {
            return Err(OAuthError::Other(
                "offline mode is on (network.offline)".into(),
            ));
        }
        if !super::super::secure_url(url) {
            return Err(OAuthError::Other(format!(
                "refusing an insecure OAuth endpoint ({url})"
            )));
        }
        let client = crate::http::client_builder(config)
            .map_err(OAuthError::Other)?
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| OAuthError::Other(e.to_string()))?;
        let resp = client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                OAuthError::Other(format!("could not reach {url}: {}", e.without_url()))
            })?;
        let status = resp.status().as_u16();
        Ok((status, resp.text().await.unwrap_or_default()))
    }

    /// Start the device flow: the user opens `verification_uri` and types `user_code`.
    pub async fn device_start(
        provider: &AuthProvider,
        config: &Config,
    ) -> Result<DeviceStart, OAuthError> {
        let cfg = config_of(provider)?;
        let url = cfg
            .device_code_url
            .as_deref()
            .ok_or_else(|| OAuthError::Other("the provider declares no device_code_url".into()))?;
        let (status, body) = post_form(config, url, device_request_body(cfg)).await?;
        parse_device_response(status, &body)
    }

    /// Ask the token endpoint once whether the device flow has completed.
    pub async fn device_poll(
        provider: &AuthProvider,
        config: &Config,
        device_code: &str,
    ) -> Result<TokenSet, OAuthError> {
        let cfg = config_of(provider)?;
        let (status, body) =
            post_form(config, &cfg.token_url, device_token_body(cfg, device_code)).await?;
        parse_token_response(status, &body, Utc::now())
    }

    /// Exchange an authorization code (with its PKCE verifier) for tokens.
    pub async fn exchange_code(
        provider: &AuthProvider,
        config: &Config,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenSet, OAuthError> {
        let cfg = config_of(provider)?;
        let (status, body) = post_form(
            config,
            &cfg.token_url,
            code_token_body(cfg, code, verifier, redirect_uri),
        )
        .await?;
        parse_token_response(status, &body, Utc::now())
    }

    /// Get a new token set from a refresh token. A provider that does not rotate refresh
    /// tokens answers without one: the old one is kept.
    pub async fn refresh(
        provider: &AuthProvider,
        config: &Config,
        refresh_token: &str,
    ) -> Result<TokenSet, OAuthError> {
        let cfg = config_of(provider)?;
        let (status, body) =
            post_form(config, &cfg.token_url, refresh_body(cfg, refresh_token)).await?;
        let mut tokens = parse_token_response(status, &body, Utc::now())?;
        if tokens.refresh_token.is_none() {
            tokens.refresh_token = Some(refresh_token.to_string());
        }
        Ok(tokens)
    }

    /// The access token of an OAuth provider from the local store, refreshed first when it
    /// has expired. Providers without OAuth behave like [`Resolver::require`].
    pub async fn access_token(
        resolver: &Resolver,
        id: &str,
        config: &Config,
    ) -> crate::Result<String> {
        let provider =
            resolver
                .registry()
                .get(id)
                .cloned()
                .ok_or_else(|| crate::Error::UnknownProvider {
                    id: id.to_string(),
                    known: resolver
                        .registry()
                        .ids()
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                })?;
        let values = resolver.values(id)?;
        let stale = provider.oauth.is_some()
            && expired(values.get(EXPIRES_AT).map(|r| r.value.as_str()), Utc::now());
        if stale {
            match values.get(REFRESH_TOKEN) {
                Some(r) => match refresh(&provider, config, &r.value).await {
                    Ok(tokens) => {
                        resolver.login(id, &tokens.fields(&provider))?;
                        return Ok(tokens.access_token);
                    }
                    Err(e) => {
                        return Err(crate::Error::Store(format!(
                            "{} sign-in could not be renewed ({e}); run `frontier auth login {id}`",
                            provider.title
                        )));
                    }
                },
                None => {
                    return Err(crate::Error::Store(format!(
                        "{} sign-in has expired; run `frontier auth login {id}`",
                        provider.title
                    )));
                }
            }
        }
        resolver.require(id)
    }
}

#[cfg(feature = "http")]
pub use net::{
    access_token, challenge_for, device_poll, device_start, exchange_code, pkce_pair, random_state,
    refresh,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::parse_declarations;

    fn provider(kind: &str) -> AuthProvider {
        parse_declarations(&format!(
            r#"
[[auth]]
id = "acme"
title = "Acme Cloud"
kind = "{kind}"
env = ["ACME_TOKEN"]
[auth.oauth]
authorize_url = "https://acme.example.com/oauth/authorize"
token_url = "https://acme.example.com/oauth/token"
device_code_url = "https://acme.example.com/oauth/device"
client_id = "frontier-cli"
scopes = ["read", "offline access"]
"#
        ))
        .unwrap()
        .remove(0)
    }

    #[test]
    fn declarations_get_the_token_set_fields_and_are_validated() {
        let p = provider("oauth_device");
        let names: Vec<&str> = p.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["access_token", "refresh_token", "expires_at"]);
        assert_eq!(p.primary().unwrap().name, "access_token");
        assert_eq!(p.primary().unwrap().env, ["ACME_TOKEN"]);
        assert!(p.fields[1].secret && !p.fields[1].required && !p.fields[2].secret);
        let err =
            parse_declarations("[[auth]]\nid = \"x\"\ntitle = \"X\"\nkind = \"oauth_pkce\"\n")
                .unwrap_err();
        assert!(err.contains("needs an [auth.oauth] table"), "{err}");
        let err = parse_declarations(
            "[[auth]]\nid = \"x\"\ntitle = \"X\"\nkind = \"oauth_device\"\n[auth.oauth]\ntoken_url = \"http://plain.example.com/t\"\ndevice_code_url = \"https://x.example.com/d\"\nclient_id = \"c\"\n",
        )
        .unwrap_err();
        assert!(err.contains("must be https"), "{err}");
        let err = parse_declarations(
            "[[auth]]\nid = \"x\"\ntitle = \"X\"\nkind = \"oauth_pkce\"\n[auth.oauth]\ntoken_url = \"https://x.example.com/t\"\nclient_id = \"c\"\n",
        )
        .unwrap_err();
        assert!(err.contains("authorize_url is required"), "{err}");
    }

    #[test]
    fn a_later_declaration_can_add_oauth_to_a_token_provider() {
        let mut r = crate::credentials::Registry::builtin();
        let mut hf = provider("oauth_device");
        hf.id = "huggingface".into();
        hf.env.clear();
        r.add(hf);
        let p = r.get("huggingface").unwrap();
        assert!(p.is_oauth());
        // the pasted token, HF_TOKEN and an OAuth sign-in all fill the same field
        assert_eq!(p.primary().unwrap().name, "token");
        assert!(p.field("refresh_token").is_some() && p.field("access_token").is_none());
    }

    #[test]
    fn request_building() {
        let p = provider("oauth_pkce");
        let cfg = p.oauth.as_ref().unwrap();
        let url = authorize_url(cfg, "http://127.0.0.1:53682/callback", "st&te", "chal").unwrap();
        assert_eq!(
            url,
            "https://acme.example.com/oauth/authorize?response_type=code&client_id=frontier-cli&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2Fcallback&scope=read%20offline%20access&state=st%26te&code_challenge=chal&code_challenge_method=S256"
        );
        assert_eq!(
            device_request_body(cfg),
            "client_id=frontier-cli&scope=read%20offline%20access"
        );
        assert!(device_token_body(cfg, "dc").starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=dc"
        ));
        assert_eq!(
            code_token_body(cfg, "c0de", "ver", "http://127.0.0.1:1/callback"),
            "grant_type=authorization_code&code=c0de&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2Fcallback&client_id=frontier-cli&code_verifier=ver"
        );
        assert_eq!(
            refresh_body(cfg, "r+1"),
            "grant_type=refresh_token&refresh_token=r%2B1&client_id=frontier-cli"
        );
    }

    #[test]
    fn responses() {
        let now = Utc::now();
        let d = parse_device_response(200, r#"{"device_code":"dc","user_code":"WDJB-MJHT","verification_uri":"https://acme.example.com/device","interval":2,"expires_in":600}"#).unwrap();
        assert_eq!(
            (d.user_code.as_str(), d.interval, d.expires_in),
            ("WDJB-MJHT", 2, 600)
        );
        assert!(
            !serde_json::to_string(&d).unwrap().contains("\"dc\""),
            "the device code is not serialised"
        );
        assert!(
            parse_device_response(400, r#"{"error":"invalid_client"}"#)
                .unwrap_err()
                .to_string()
                .contains("invalid_client")
        );
        assert_eq!(
            parse_token_response(400, r#"{"error":"authorization_pending"}"#, now),
            Err(OAuthError::Pending)
        );
        assert_eq!(
            parse_token_response(400, r#"{"error":"slow_down"}"#, now),
            Err(OAuthError::SlowDown)
        );
        assert_eq!(
            parse_token_response(400, r#"{"error":"access_denied"}"#, now),
            Err(OAuthError::Denied)
        );
        assert_eq!(
            parse_token_response(400, r#"{"error":"expired_token"}"#, now),
            Err(OAuthError::Expired)
        );
        let t = parse_token_response(200, r#"{"access_token":"at_secret_value","refresh_token":"rt_secret_value","expires_in":3600,"scope":"read"}"#, now).unwrap();
        assert_eq!(t.expires_at, Some(now + Duration::seconds(3600)));
        assert!(!format!("{t:?}").contains("secret_value"));
        let fields = t.fields(&provider("oauth_device"));
        assert_eq!(fields["access_token"], "at_secret_value");
        assert_eq!(fields["refresh_token"], "rt_secret_value");
        assert!(fields.contains_key("expires_at"));
        assert!(parse_token_response(200, "{}", now).is_err());
    }

    #[test]
    fn expiry() {
        let now = Utc::now();
        assert!(!expired(None, now));
        assert!(expired(
            Some(&(now - Duration::seconds(1)).to_rfc3339()),
            now
        ));
        assert!(
            expired(Some(&(now + Duration::seconds(30)).to_rfc3339()), now),
            "inside the slack"
        );
        assert!(!expired(
            Some(&(now + Duration::seconds(600)).to_rfc3339()),
            now
        ));
    }

    #[cfg(feature = "http")]
    #[test]
    fn pkce_challenge_matches_rfc_7636() {
        // RFC 7636 appendix B
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let (v1, c1) = pkce_pair().unwrap();
        let (v2, _) = pkce_pair().unwrap();
        assert!(v1 != v2 && v1.len() >= 43 && c1 == challenge_for(&v1));
        assert_ne!(random_state().unwrap(), random_state().unwrap());
    }
}
