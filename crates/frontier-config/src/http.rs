// SPDX-License-Identifier: Apache-2.0
//! HTTP clients that honour the network settings (proxy, proxy exceptions, CA bundle).

use crate::loader::Config;

/// A `reqwest` client builder configured from `network.*`. An unreadable CA bundle is an
/// error: silently falling back to the public roots would hide a misconfiguration.
pub fn client_builder(config: &Config) -> Result<reqwest::ClientBuilder, String> {
    let mut b =
        reqwest::Client::builder().user_agent(concat!("frontier/", env!("CARGO_PKG_VERSION")));
    if config.bool("network.offline") {
        // The backstop behind `require_online`: in offline mode every request of a client
        // built here that is not for an allowed host is sent to a port nothing listens on,
        // so it fails at once and never leaves the machine (PRIV-01). Configured proxies
        // are outside by definition and are not used.
        let allow = OfflineAllow::from_config(config);
        b = b.proxy(reqwest::Proxy::custom(move |url| {
            (!allow.allows(url.as_str())).then(|| "http://127.0.0.1:9".to_string())
        }));
    }
    let offline = config.bool("network.offline");
    let no_proxy = config.list("network.no_proxy").join(",");
    let no_proxy = (!no_proxy.is_empty())
        .then(|| reqwest::NoProxy::from_string(&no_proxy))
        .flatten();
    if let Some(url) = config.opt_str("network.https_proxy").filter(|_| !offline) {
        let p = reqwest::Proxy::https(url)
            .map_err(|e| format!("network.https_proxy: {e}"))?
            .no_proxy(no_proxy.clone());
        b = b.proxy(p);
    }
    if let Some(url) = config.opt_str("network.http_proxy").filter(|_| !offline) {
        let p = reqwest::Proxy::http(url)
            .map_err(|e| format!("network.http_proxy: {e}"))?
            .no_proxy(no_proxy);
        b = b.proxy(p);
    }
    if let Some(path) = config.path("network.ca_bundle") {
        let pem = std::fs::read(&path)
            .map_err(|e| format!("network.ca_bundle {}: {e}", path.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| format!("network.ca_bundle {}: {e}", path.display()))?;
        if certs.is_empty() {
            return Err(format!(
                "network.ca_bundle {}: no certificate found",
                path.display()
            ));
        }
        for c in certs {
            b = b.add_root_certificate(c);
        }
    }
    Ok(b)
}

/// What stays reachable with `network.offline` on: this machine, private and link-local
/// address literals, the control plane (`client.server_url`) and
/// `network.offline_allow_hosts`. Everything else is the public internet as far as a
/// program can tell.
#[derive(Debug, Clone, Default)]
pub struct OfflineAllow {
    hosts: Vec<String>,
}

fn host_of_url(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']')?.0.to_string(),
        None => authority
            .rsplit_once(':')
            .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
            .map_or(authority, |(h, _)| h)
            .to_string(),
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

impl OfflineAllow {
    pub fn from_config(config: &Config) -> Self {
        let mut hosts: Vec<String> = config
            .list("network.offline_allow_hosts")
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        hosts.extend(host_of_url(config.str("client.server_url")));
        Self { hosts }
    }

    pub fn allows(&self, url: &str) -> bool {
        let Some(host) = host_of_url(url) else {
            return false;
        };
        if host == "localhost" || host.ends_with(".localhost") || self.hosts.contains(&host) {
            return true;
        }
        match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => {
                ip.is_loopback() || ip.is_private() || ip.is_link_local()
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                ip.is_loopback()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00
                    || (ip.segments()[0] & 0xffc0) == 0xfe80
            }
            Err(_) => false,
        }
    }
}

/// The guard for outbound call sites: an error that says why, before any connection, when
/// `network.offline` is on and `url` is not one of the places that stay reachable.
pub fn require_online(config: &Config, what: &str, url: &str) -> Result<(), String> {
    if !config.bool("network.offline") || OfflineAllow::from_config(config).allows(url) {
        return Ok(());
    }
    Err(format!(
        "offline mode is on (setting network.offline), so {what} is not possible; a host inside your network can be allowed with network.offline_allow_hosts"
    ))
}

/// Provider id under which tokens for individual control planes are kept in the secret
/// store (`secrets.backend`); the field is [`crate::local_token::server_key`] of the URL.
pub const SERVER_TOKENS: &str = "frontier-server";

/// The token this machine presents to the control plane at `server_url` (default: the
/// setting `client.server_url`), most specific first:
/// 1. the local token of a single-user server on this machine ([`crate::local_token`]);
/// 2. the token kept for exactly that server in the secret store (a pod this machine
///    started with `frontier cloud up --standalone` / `frontier run --on runpod`);
/// 3. the `frontier` credential (`frontier login`, or `FRONTIER_TOKEN`).
pub fn server_token(config: &Config, server_url: Option<&str>) -> Option<String> {
    let url = server_url
        .map(str::to_string)
        .unwrap_or_else(|| config.str("client.server_url").to_string());
    if let Some(local) = crate::local_token::read(&config.paths.home, &url) {
        return Some(local);
    }
    let resolver = crate::credentials::Resolver::from_config(config).ok()?;
    if let Some(key) = crate::local_token::server_key(&url)
        && let Ok(Some(v)) = resolver.store().get(SERVER_TOKENS, &key)
        && !v.trim().is_empty()
    {
        return Some(v);
    }
    resolver
        .get("frontier", "token")
        .ok()
        .flatten()
        .map(|r| r.value)
        .filter(|v| !v.trim().is_empty())
}

/// Keep `token` for the control plane at `server_url` in the configured secret store.
pub fn remember_server_token(config: &Config, server_url: &str, token: &str) -> Result<(), String> {
    let key = crate::local_token::server_key(server_url)
        .ok_or_else(|| format!("{server_url} is not a URL a token can be kept for"))?;
    let resolver = crate::credentials::Resolver::from_config(config).map_err(|e| e.to_string())?;
    resolver
        .store()
        .set(SERVER_TOKENS, &key, token)
        .map_err(|e| e.to_string())
}

/// Remove the token kept for the control plane at `server_url`. Returns whether one existed.
pub fn forget_server_token(config: &Config, server_url: &str) -> bool {
    let Some(key) = crate::local_token::server_key(server_url) else {
        return false;
    };
    crate::credentials::Resolver::from_config(config)
        .ok()
        .and_then(|r| r.store().delete(SERVER_TOKENS, &key).ok())
        .unwrap_or(false)
}

/// [`client_builder`] for a client that talks to the control plane only: every request
/// carries the token of [`server_token`]. Never use it for another host.
pub fn server_client_builder(
    config: &Config,
    server_url: Option<&str>,
) -> Result<reqwest::ClientBuilder, String> {
    let mut b = client_builder(config)?;
    if let Some(token) = server_token(config, server_url) {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| {
                "the control-plane token contains characters a header cannot carry".to_string()
            })?;
        value.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, value);
        b = b.default_headers(headers);
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoadOptions;

    fn config(home: &std::path::Path, env: &[(&str, &str)]) -> Config {
        let mut vars: std::collections::BTreeMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        vars.insert("FRONTIER_SECRETS__BACKEND".into(), "file".into());
        Config::load(&LoadOptions {
            system_file: Some(home.join("none.toml")),
            home: home.to_path_buf(),
            env: vars,
            ..Default::default()
        })
    }

    /// PRIV-01: with `network.offline` on, nothing built here reaches the public internet.
    #[tokio::test]
    async fn offline_mode_stops_outbound_requests_before_they_leave() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(
            dir.path(),
            &[
                ("FRONTIER_OFFLINE", "true"),
                ("FRONTIER_SERVER", "https://frontier.site.example"),
                (
                    "FRONTIER_NETWORK__OFFLINE_ALLOW_HOSTS",
                    "vault.site.example",
                ),
            ],
        );
        let allow = OfflineAllow::from_config(&c);
        for ok in [
            "http://127.0.0.1:8787/x",
            "http://localhost:1",
            "http://[::1]:8787",
            "http://10.1.2.3/",
            "https://192.168.1.5:8200",
            "http://169.254.169.254/latest",
            "https://frontier.site.example/api",
            "https://vault.site.example:8200/v1",
        ] {
            assert!(allow.allows(ok), "{ok}");
            assert!(require_online(&c, "x", ok).is_ok());
        }
        for blocked in [
            "https://huggingface.co/api",
            "https://pypi.org/simple",
            "https://8.8.8.8/",
            "https://127.0.0.1.evil.example/",
            "https://user@evil.example/",
            "https://vault.site.example.evil.example/",
            "not a url",
        ] {
            assert!(!allow.allows(blocked), "{blocked}");
        }
        let e =
            require_online(&c, "pulling from the hub", "https://huggingface.co/api").unwrap_err();
        assert!(
            e.contains("network.offline") && e.contains("pulling from the hub"),
            "{e}"
        );
        // the backstop: a request nobody guarded fails at once instead of going out
        // (192.0.2.0/24 is reserved for documentation: a real attempt would hang)
        let client = client_builder(&c)
            .unwrap()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        assert!(client.get("http://192.0.2.1:9/").send().await.is_err());
        assert!(client.get("https://192.0.2.1/").send().await.is_err());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        // online: no guard
        let online = config(dir.path(), &[]);
        assert!(require_online(&online, "x", "https://huggingface.co").is_ok());
    }

    #[test]
    fn the_most_specific_token_for_a_server_wins() {
        let dir = tempfile::tempdir().unwrap();
        let pod = "https://abc123-8787.proxy.example.net";
        let c = config(dir.path(), &[("FRONTIER_TOKEN", "global-token")]);
        // nothing kept for the pod yet: the global credential
        assert_eq!(server_token(&c, Some(pod)).as_deref(), Some("global-token"));
        remember_server_token(&c, pod, "pod-admin-token").unwrap();
        assert_eq!(
            server_token(&c, Some(pod)).as_deref(),
            Some("pod-admin-token")
        );
        // it is for that pod only, and lives in the secret store (0600 file here)
        assert_eq!(
            server_token(&c, Some("https://other-8787.proxy.example.net")).as_deref(),
            Some("global-token")
        );
        let stored = std::fs::read_to_string(dir.path().join("credentials.toml")).unwrap();
        assert!(stored.contains("frontier-server") && stored.contains("pod-admin-token"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("credentials.toml"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // a single-user server on this machine: its own local token, whatever else is stored
        crate::local_token::write(
            &crate::local_token::path_for_port(dir.path(), 8787),
            "local-token",
        )
        .unwrap();
        assert_eq!(
            server_token(&c, Some("http://127.0.0.1:8787")).as_deref(),
            Some("local-token")
        );
        // `cloud down` and rotation remove it
        assert!(forget_server_token(&c, pod));
        assert!(!forget_server_token(&c, pod));
        assert_eq!(server_token(&c, Some(pod)).as_deref(), Some("global-token"));
        assert!(remember_server_token(&c, "ftp://nope", "x").is_err());
    }
}
