// SPDX-License-Identifier: Apache-2.0
//! The local token of a single-user control plane (`auth.mode = "none"`, setting
//! `auth.local_token`): a random secret the server writes at start-up into files only the
//! owner can read, so that "no accounts" does not mean "any local process or web page may
//! act". Clients on the same machine find it by the port of the server URL.

use std::path::{Path, PathBuf};

/// `<home>/servers/<port>.token`.
pub fn path_for_port(home: &Path, port: u16) -> PathBuf {
    home.join("servers").join(format!("{port}.token"))
}

/// The port of a `http://host:port[/...]` URL whose host is this machine, or `None`.
pub fn loopback_port(server_url: &str) -> Option<u16> {
    let rest = server_url
        .strip_prefix("http://")
        .or_else(|| server_url.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let (h, p) = v6.split_once(']')?;
            (format!("[{h}]"), p.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        },
    };
    let host = host.to_ascii_lowercase();
    if !(matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
        || host.ends_with(".localhost"))
    {
        return None;
    }
    match port {
        Some(p) => p.parse().ok(),
        None => Some(if server_url.starts_with("https://") {
            443
        } else {
            80
        }),
    }
}

/// The stable name of the server at `server_url` in the secret store: its host, with the
/// port when the URL names one (`pod-8787.proxy.example.net`, `frontier.example.com_8443`).
/// `None` for anything that is not an http(s) URL with a plain host.
pub fn server_key(server_url: &str) -> Option<String> {
    let rest = server_url
        .strip_prefix("https://")
        .or_else(|| server_url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    let name: String = authority
        .chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect();
    let ok = !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '[' | ']'));
    ok.then_some(name)
}

/// The local token of the server at `server_url`, when that server runs on this machine
/// and wrote one. Never an error: a missing file means "no token".
pub fn read(home: &Path, server_url: &str) -> Option<String> {
    let port = loopback_port(server_url)?;
    let text = std::fs::read_to_string(path_for_port(home, port)).ok()?;
    let token = text.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Write `token` where only the owner can read it, replacing an earlier file.
pub fn write(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _ = std::fs::remove_file(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts.open(path)?;
    f.write_all(token.as_bytes())?;
    f.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_urls_have_a_local_token() {
        assert_eq!(loopback_port("http://127.0.0.1:8787"), Some(8787));
        assert_eq!(loopback_port("http://localhost:9001/api"), Some(9001));
        assert_eq!(loopback_port("http://[::1]:8787"), Some(8787));
        assert_eq!(loopback_port("http://localhost"), Some(80));
        assert_eq!(loopback_port("https://frontier.example.com"), None);
        assert_eq!(loopback_port("http://127.0.0.1.evil.example:8787"), None);
        assert_eq!(loopback_port("ftp://localhost:1"), None);
    }

    #[test]
    fn round_trip_with_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let p = path_for_port(dir.path(), 8787);
        write(&p, "frt_abc").unwrap();
        write(&p, "frt_def").unwrap();
        assert_eq!(
            read(dir.path(), "http://127.0.0.1:8787").as_deref(),
            Some("frt_def")
        );
        assert_eq!(read(dir.path(), "http://127.0.0.1:8788"), None);
        assert_eq!(read(dir.path(), "https://example.com:8787"), None);
        // remote servers are named for the secret store, never mapped to a path
        assert_eq!(
            server_key("https://abc123-8787.proxy.example.net/api/v1/runs").as_deref(),
            Some("abc123-8787.proxy.example.net")
        );
        assert_eq!(
            server_key("http://Frontier.Example.com:8443").as_deref(),
            Some("frontier.example.com_8443")
        );
        assert_eq!(server_key("https://../../etc/x"), None);
        assert_eq!(server_key("https://user@host"), None);
        assert_eq!(server_key("ftp://host"), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
