// SPDX-License-Identifier: Apache-2.0
//! The organisation mirrors of the datasets hub (setting `hub.mirrors`): items
//! `<entry id or glob>=<location>`, first match wins. The Python hub package reads the same
//! setting (`frontier_hub.mirror`); the pattern rules here are those of `fnmatch`.

/// One item of `hub.mirrors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub pattern: String,
    /// A directory or an object-store prefix (`s3://`, `r2://`, `gs://`, `az://`).
    pub location: String,
}

/// Schemes of object stores a mirror or an attach source may name.
pub const OBJECT_STORES: [&str; 4] = ["s3", "r2", "gs", "az"];

/// The scheme of `location` (`s3` in `s3://bucket/x`), lower case; `None` for a path.
pub fn scheme(location: &str) -> Option<String> {
    let (scheme, rest) = location.split_once("://")?;
    let ok = !scheme.is_empty()
        && !rest.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    ok.then(|| scheme.to_ascii_lowercase())
}

/// Whether a URL-like location carries user info (a key and secret before the bucket).
pub fn has_userinfo(location: &str) -> bool {
    location
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .is_some_and(|authority| authority.contains('@'))
}

/// `location` as it may be shown and recorded: without user info, query or fragment.
pub fn redact(location: &str) -> String {
    let Some((scheme, rest)) = location.split_once("://") else {
        return location.to_string();
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = authority.rsplit('@').next().unwrap_or_default();
    format!("{scheme}://{host}{path}")
}

/// The credential provider whose stored secret opens `location`, if it needs one.
pub fn credential_for(location: &str) -> Option<&'static str> {
    match scheme(location)?.as_str() {
        "s3" | "r2" => Some("s3"),
        "gs" => Some("gcs"),
        "az" => Some("azure"),
        _ => None,
    }
}

impl Mirror {
    /// Parse one `<entry id or glob>=<location>` item.
    pub fn parse(item: &str) -> Result<Self, String> {
        let shape = || {
            format!(
                "{item:?} is not `<entry id or pattern>=<location>` (for example `*=s3://company-datasets/hub`)"
            )
        };
        let (pattern, location) = item.split_once('=').ok_or_else(shape)?;
        let (pattern, location) = (pattern.trim(), location.trim());
        if pattern.is_empty() || location.is_empty() {
            return Err(shape());
        }
        match scheme(location) {
            None => {}
            Some(s) if OBJECT_STORES.contains(&s.as_str()) => {
                if has_userinfo(location) {
                    return Err(format!(
                        "the location of {pattern:?} carries a credential; store it in the secret store instead (provider `{}`)",
                        credential_for(location).unwrap_or("s3")
                    ));
                }
            }
            Some(s) => {
                return Err(format!(
                    "`{s}://` is not a mirror location; use a directory or one of s3://, r2://, gs://, az://"
                ));
            }
        }
        Ok(Self {
            pattern: pattern.to_string(),
            location: location.to_string(),
        })
    }

    pub fn matches(&self, entry_id: &str) -> bool {
        let pattern: Vec<char> = self.pattern.chars().collect();
        let text: Vec<char> = entry_id.chars().collect();
        glob(&pattern, &text)
    }
}

/// `fnmatch` without case folding: `*`, `?`, `[seq]`, `[!seq]`.
fn glob(p: &[char], t: &[char]) -> bool {
    match p.split_first() {
        None => t.is_empty(),
        Some(('*', rest)) => (0..=t.len()).any(|i| glob(rest, &t[i..])),
        Some(('?', rest)) => !t.is_empty() && glob(rest, &t[1..]),
        Some(('[', rest)) => {
            // a class needs its closing bracket, else `[` is a literal
            let negate = rest.first() == Some(&'!');
            let body = if negate { &rest[1..] } else { rest };
            let close = body
                .iter()
                .enumerate()
                .position(|(i, c)| *c == ']' && i > 0);
            let (Some(close), Some((c, tail))) = (close, t.split_first()) else {
                return t.first() == Some(&'[') && glob(rest, &t[1..]);
            };
            let set = &body[..close];
            let mut hit = false;
            let mut i = 0;
            while i < set.len() {
                if i + 2 < set.len() && set[i + 1] == '-' {
                    hit |= set[i] <= *c && *c <= set[i + 2];
                    i += 3;
                } else {
                    hit |= set[i] == *c;
                    i += 1;
                }
            }
            hit != negate && glob(&body[close + 1..], tail)
        }
        Some((c, rest)) => t.first() == Some(c) && glob(rest, &t[1..]),
    }
}

/// Every item of the setting, in order.
pub fn parse_mirrors(items: &[String]) -> Result<Vec<Mirror>, String> {
    items.iter().map(|item| Mirror::parse(item)).collect()
}

/// The mirror that serves `entry_id`: the first pattern that matches. Items that do not
/// parse are skipped (the setting is validated when it is written).
pub fn mirror_for(items: &[String], entry_id: &str) -> Option<Mirror> {
    items
        .iter()
        .filter_map(|item| Mirror::parse(item).ok())
        .find(|m| m.matches(entry_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_first_matching_pattern_serves_an_entry() {
        let set = items(&[
            "shift-*=s3://company-datasets/restricted",
            "era[5-6]=/mnt/weather",
            "*=/mnt/datasets/hub",
        ]);
        let at = |id: &str| mirror_for(&set, id).map(|m| m.location);
        assert_eq!(
            at("shift-wing").as_deref(),
            Some("s3://company-datasets/restricted")
        );
        assert_eq!(at("era5").as_deref(), Some("/mnt/weather"));
        assert_eq!(at("era7").as_deref(), Some("/mnt/datasets/hub"));
        assert_eq!(mirror_for(&items(&["ahmedml=/m"]), "ahmedml-2"), None);
        assert_eq!(mirror_for(&[], "ahmedml"), None);
        // the patterns of fnmatch
        for (pattern, id, expect) in [
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("[!a]x", "bx", true),
            ("[!a]x", "ax", false),
            ("*-v[12]", "set-v2", true),
            ("*-v[12]", "set-v3", false),
            ("a[b", "a[b", true),
        ] {
            let m = Mirror {
                pattern: pattern.into(),
                location: "/m".into(),
            };
            assert_eq!(m.matches(id), expect, "{pattern} {id}");
        }
    }

    #[test]
    fn items_are_checked_and_locations_never_carry_a_credential() {
        assert!(Mirror::parse("*=/mnt/datasets/hub").is_ok());
        assert!(Mirror::parse("x-*= gs://bucket/prefix ").is_ok());
        for bad in ["/mnt/hub", "=/mnt/hub", "*=", "*=https://example.org/hub"] {
            assert!(Mirror::parse(bad).is_err(), "{bad}");
        }
        // a location with a key and a secret in front of the bucket
        let with_keys = |rest: &str| format!("s3://{}:{}@{rest}", "AKIA", "hunter2");
        let err = Mirror::parse(&format!("*={}", with_keys("bucket/hub"))).unwrap_err();
        assert!(
            err.contains("secret store") && !err.contains("hunter2"),
            "{err}"
        );
        assert_eq!(
            redact(&with_keys("bucket/hub?X-Amz-Signature=abc")),
            "s3://bucket/hub"
        );
        assert_eq!(redact("/mnt/hub"), "/mnt/hub");
        assert_eq!(credential_for("r2://b/p"), Some("s3"));
        assert_eq!(credential_for("az://c/p"), Some("azure"));
        assert_eq!(credential_for("/mnt/hub"), None);
        assert!(
            has_userinfo(&format!("https://{}@host/x", "u:p")) && !has_userinfo("https://host/x@y")
        );
    }
}
