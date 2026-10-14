// SPDX-License-Identifier: Apache-2.0
//! Testing a credential with one read-only HTTP request, described declaratively by the
//! provider (`[auth.test_http]`). Building the request is pure; sending it needs the `http`
//! feature.

use super::{AuthProvider, HttpTest, Resolved};
use crate::loader::Config;
use serde::Serialize;
use std::collections::BTreeMap;

/// Result of a credential test. `detail` never contains the credential.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TestOutcome {
    pub ok: bool,
    /// Account the credential belongs to, when the service reports one.
    pub identity: Option<String>,
    /// Human-readable error (or `None` on success).
    pub error: Option<String>,
    pub detail: String,
    pub status: Option<u16>,
}

impl TestOutcome {
    pub fn failed(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            ok: false,
            identity: None,
            error: Some(message.clone()),
            detail: message,
            status: None,
        }
    }
}

/// A request ready to send.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub basic: Option<(String, String)>,
}

impl std::fmt::Debug for PreparedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PreparedRequest {{ url: {:?}, headers: *** }}", self.url)
    }
}

fn origin_of(url: &str) -> &str {
    let after = url.find("://").map(|i| i + 3).unwrap_or(0);
    match url[after..].find('/') {
        Some(i) => &url[..after + i],
        None => url,
    }
}

/// Build the test request of `provider` from resolved `values`.
pub fn prepare(
    provider: &AuthProvider,
    values: &BTreeMap<String, Resolved>,
    config: &Config,
) -> Result<PreparedRequest, String> {
    let test: &HttpTest = provider
        .test_http
        .as_ref()
        .ok_or_else(|| format!("{} has no built-in test", provider.title))?;
    let primary = provider
        .primary()
        .ok_or_else(|| "provider declares no field".to_string())?;
    let secret = values
        .get(&primary.name)
        .map(|r| r.value.as_str())
        .ok_or_else(|| format!("no {} is configured", primary.title))?;
    let mut url = test.url.clone();
    let custom_origin = test
        .url_field
        .as_ref()
        .and_then(|f| values.get(f))
        .map(|r| r.value.clone())
        .or_else(|| {
            test.url_setting
                .as_ref()
                .and_then(|k| config.entry(k))
                .and_then(|e| e.value.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });
    if let Some(origin) = custom_origin {
        let path = test
            .url_path
            .clone()
            .unwrap_or_else(|| test.url[origin_of(&test.url).len()..].to_string());
        url = format!("{}{}", origin.trim_end_matches('/'), path);
    }
    if !url.starts_with("https://")
        && !url.starts_with("http://127.0.0.1")
        && !url.starts_with("http://localhost")
    {
        return Err(format!(
            "refusing to send a credential over an insecure connection ({})",
            origin_of(&url)
        ));
    }
    let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
    let mut basic = None;
    match test.auth.as_str() {
        "" | "bearer" => headers.push(("Authorization".into(), format!("Bearer {secret}"))),
        "basic" => {
            let user = values
                .get("username")
                .map(|r| r.value.clone())
                .unwrap_or_default();
            basic = Some((user, secret.to_string()));
        }
        other => match other.strip_prefix("header:") {
            Some(spec) => {
                let (name, prefix) = spec.split_once(':').unwrap_or((spec, ""));
                headers.push((name.to_string(), format!("{prefix}{secret}")));
            }
            None => return Err(format!("unsupported test auth scheme {other:?}")),
        },
    }
    Ok(PreparedRequest {
        url,
        headers,
        basic,
    })
}

/// Interpret a response.
pub fn interpret(test: &HttpTest, status: u16, body: &str) -> TestOutcome {
    if (200..300).contains(&status) {
        let json: Option<serde_json::Value> = serde_json::from_str(body).ok();
        let identity = test
            .identity
            .as_deref()
            .and_then(|ptr| json.as_ref()?.pointer(ptr))
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            });
        let count = test.count.as_deref().and_then(|ptr| {
            let v = json.as_ref()?;
            let v = if ptr.is_empty() { v } else { v.pointer(ptr)? };
            v.as_array().map(Vec::len)
        });
        let detail = match (&identity, count) {
            (Some(who), _) => format!("signed in as {who}"),
            (None, Some(n)) => format!(
                "accepted ({n} item{} visible)",
                if n == 1 { "" } else { "s" }
            ),
            _ => "accepted".to_string(),
        };
        return TestOutcome {
            ok: true,
            identity,
            error: None,
            detail,
            status: Some(status),
        };
    }
    let message = match status {
        401 => "rejected: the credential is invalid or expired (HTTP 401)".to_string(),
        403 => "rejected: the credential is valid but lacks permission (HTTP 403)".to_string(),
        s => format!("the service answered HTTP {s}; the credential could not be verified"),
    };
    TestOutcome {
        ok: false,
        identity: None,
        error: Some(message.clone()),
        detail: message,
        status: Some(status),
    }
}

/// Send the test request. Honours `network.offline`, the proxy and the CA bundle.
#[cfg(feature = "http")]
pub async fn run(
    provider: &AuthProvider,
    values: &BTreeMap<String, Resolved>,
    config: &Config,
) -> TestOutcome {
    let Some(test) = provider.test_http.as_ref() else {
        return TestOutcome::failed(format!("{} has no built-in test", provider.title));
    };
    if config.bool("network.offline") {
        return TestOutcome::failed(
            "offline mode is on (network.offline); the credential was not tested",
        );
    }
    let req = match prepare(provider, values, config) {
        Ok(r) => r,
        Err(e) => return TestOutcome::failed(e),
    };
    let redactor = crate::redact::Redactor::new(values.values().map(|r| r.value.clone()));
    let client = match crate::http::client_builder(config).and_then(|b| {
        b.timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())
    }) {
        Ok(c) => c,
        Err(e) => return TestOutcome::failed(redactor.redact(&e)),
    };
    let mut builder = client.get(&req.url);
    for (name, value) in &req.headers {
        builder = builder.header(name, value);
    }
    if let Some((user, pass)) = &req.basic {
        builder = builder.basic_auth(user, Some(pass));
    }
    match builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let mut out = interpret(test, status, &body);
            out.detail = redactor.redact(&out.detail);
            out
        }
        Err(e) => TestOutcome::failed(redactor.redact(&format!(
            "could not reach {}: {}",
            origin_of(&req.url),
            e.without_url()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Registry;

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, Resolved> {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    Resolved {
                        value: v.to_string(),
                        source: "memory".into(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn requests_per_auth_scheme() {
        let r = Registry::builtin();
        let cfg = Config::defaults();
        let hf = prepare(
            r.get("huggingface").unwrap(),
            &values(&[("token", "hf_x")]),
            &cfg,
        )
        .unwrap();
        assert_eq!(hf.url, "https://huggingface.co/api/whoami-v2");
        assert!(
            hf.headers
                .contains(&("Authorization".into(), "Bearer hf_x".into()))
        );
        assert!(!format!("{hf:?}").contains("hf_x"));
        let rp = prepare(
            r.get("runpod").unwrap(),
            &values(&[("api_key", "rp_x")]),
            &cfg,
        )
        .unwrap();
        assert_eq!(rp.url, "https://rest.runpod.io/v1/pods");
        let f = prepare(
            r.get("flow360").unwrap(),
            &values(&[("api_key", "k")]),
            &cfg,
        )
        .unwrap();
        assert!(f.headers.contains(&("simcloud-api-key".into(), "k".into())));
        let re = prepare(
            r.get("rescale").unwrap(),
            &values(&[("api_key", "k"), ("api_url", "https://eu.rescale.com/")]),
            &cfg,
        )
        .unwrap();
        assert_eq!(re.url, "https://eu.rescale.com/api/v2/users/me/");
        assert!(
            re.headers
                .contains(&("Authorization".into(), "Token k".into()))
        );
        let err = prepare(
            r.get("simscale").unwrap(),
            &values(&[("api_key", "k"), ("api_url", "http://insecure.example")]),
            &cfg,
        )
        .unwrap_err();
        assert!(err.contains("insecure"), "{err}");
        assert!(
            prepare(
                r.get("luminary").unwrap(),
                &values(&[("api_key", "k")]),
                &cfg
            )
            .is_err()
        );
        assert!(
            prepare(r.get("runpod").unwrap(), &values(&[]), &cfg)
                .unwrap_err()
                .contains("no API key is configured")
        );
    }

    #[test]
    fn responses() {
        let r = Registry::builtin();
        let hf = r.get("huggingface").unwrap().test_http.clone().unwrap();
        let ok = interpret(&hf, 200, r#"{"name":"ada","type":"user"}"#);
        assert!(ok.ok);
        assert_eq!(ok.identity.as_deref(), Some("ada"));
        assert_eq!(ok.detail, "signed in as ada");
        let rp = r.get("runpod").unwrap().test_http.clone().unwrap();
        assert_eq!(
            interpret(&rp, 200, "[{},{}]").detail,
            "accepted (2 items visible)"
        );
        assert!(
            interpret(&hf, 401, "")
                .error
                .unwrap()
                .contains("invalid or expired")
        );
        assert!(
            interpret(&hf, 403, "")
                .error
                .unwrap()
                .contains("lacks permission")
        );
        assert!(
            interpret(&hf, 503, "")
                .error
                .unwrap()
                .contains("could not be verified")
        );
    }
}
