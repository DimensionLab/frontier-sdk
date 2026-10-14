// SPDX-License-Identifier: Apache-2.0
//! Typed values: coercion from TOML, JSON and environment strings, and validation against a
//! [`SettingDef`]. Error messages name what was expected.

use crate::schema::{SettingDef, SettingType};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Parse `"2GiB"`, `"500MB"`, `"1024"` into bytes: `kB`/`MB`/`GB`/`TB` are decimal,
/// `KiB`/`MiB`/`GiB`/`TiB` binary, the same rule as the hub's `--max-bytes`.
pub fn parse_bytes(text: &str) -> Option<u64> {
    let t = text.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '_'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num.replace('_', "").parse().ok()?;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "m" | "mb" => 1e6,
        "g" | "gb" => 1e9,
        "t" | "tb" => 1e12,
        "kib" => 1024.0,
        "mib" => 1024.0 * 1024.0,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    (n >= 0.0).then_some((n * mult) as u64)
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "a table",
    }
}

fn expected(def: &SettingDef) -> String {
    let base = match def.ty {
        SettingType::String => "a string",
        SettingType::Path => "a path",
        SettingType::Url => "a URL starting with http:// or https://",
        SettingType::Int => "an integer",
        SettingType::Float => "a number",
        SettingType::Bool => "true or false",
        SettingType::List => "a list of strings",
        SettingType::Bytes => "a byte count such as 2147483648 or \"2GiB\"",
        SettingType::Table => "a table (a JSON object in the environment)",
    };
    match &def.choices {
        Some(choices) if def.ty == SettingType::List => {
            format!("{base}, each one of: {}", choices.join(", "))
        }
        Some(choices) => format!("one of: {}", choices.join(", ")),
        None => base.to_string(),
    }
}

/// Convert an environment (or `frontier config set`) string into a JSON value for `def`.
pub fn from_text(def: &SettingDef, text: &str) -> Result<Value, String> {
    let t = text.trim();
    let raw = match def.ty {
        SettingType::String | SettingType::Path | SettingType::Url => json!(t),
        SettingType::Int => t
            .parse::<i64>()
            .map(|n| json!(n))
            .map_err(|_| format!("expected {}, got {t:?}", expected(def)))?,
        SettingType::Float => t
            .parse::<f64>()
            .map(|n| json!(n))
            .map_err(|_| format!("expected {}, got {t:?}", expected(def)))?,
        SettingType::Bool => match t.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => json!(true),
            "0" | "false" | "no" | "off" | "" => json!(false),
            _ => return Err(format!("expected {}, got {t:?}", expected(def))),
        },
        SettingType::List => {
            if t.starts_with('[') {
                serde_json::from_str::<Value>(t)
                    .map_err(|e| format!("expected {}: {e}", expected(def)))?
            } else {
                json!(
                    t.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                )
            }
        }
        SettingType::Bytes => {
            json!(parse_bytes(t).ok_or_else(|| format!("expected {}, got {t:?}", expected(def)))?)
        }
        SettingType::Table => {
            if t.is_empty() {
                json!({})
            } else {
                serde_json::from_str::<Value>(t)
                    .map_err(|e| format!("expected {}: {e}", expected(def)))?
            }
        }
    };
    coerce(def, &raw)
}

/// Validate `value` for `def` and return its normalised form (byte counts as integers, URLs
/// without a trailing slash).
pub fn coerce(def: &SettingDef, value: &Value) -> Result<Value, String> {
    let out = coerce_type(def, value)?;
    if def.key == "hub.mirrors" {
        let items: Vec<String> = out
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|i| i.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        crate::hub::parse_mirrors(&items)?;
    }
    Ok(out)
}

fn coerce_type(def: &SettingDef, value: &Value) -> Result<Value, String> {
    let wrong = || format!("expected {}, got {}", expected(def), type_name(value));
    let out = match (def.ty, value) {
        (SettingType::String | SettingType::Path, Value::String(_)) => value.clone(),
        (SettingType::Url, Value::String(s)) => {
            if !s.is_empty() && !(s.starts_with("http://") || s.starts_with("https://")) {
                return Err(format!("expected {}, got {s:?}", expected(def)));
            }
            json!(s.trim_end_matches('/'))
        }
        (SettingType::Int, Value::Number(n)) => match n.as_i64() {
            Some(i) => json!(i),
            None => return Err(wrong()),
        },
        (SettingType::Float, Value::Number(n)) => json!(n.as_f64().ok_or_else(wrong)?),
        (SettingType::Bool, Value::Bool(_)) => value.clone(),
        (SettingType::List, Value::Array(items)) => {
            if !items.iter().all(Value::is_string) {
                return Err(wrong());
            }
            value.clone()
        }
        (SettingType::Bytes, Value::Number(n)) => json!(n.as_u64().ok_or_else(wrong)?),
        (SettingType::Bytes, Value::String(s)) => {
            json!(parse_bytes(s).ok_or_else(|| format!("expected {}, got {s:?}", expected(def)))?)
        }
        (SettingType::Table, Value::Object(_)) => value.clone(),
        _ => return Err(wrong()),
    };
    if let Some(choices) = &def.choices {
        let check = |s: &str| {
            choices
                .iter()
                .any(|c| c == s)
                .then_some(())
                .ok_or_else(|| format!("{s:?} is not allowed; expected {}", expected(def)))
        };
        match &out {
            Value::String(s) => check(s)?,
            Value::Array(items) => {
                for item in items {
                    check(item.as_str().unwrap_or_default())?;
                }
            }
            _ => {}
        }
    }
    if let Some(n) = out.as_f64() {
        if let Some(min) = def.min
            && n < min
        {
            return Err(format!("{n} is below the minimum {min}"));
        }
        if let Some(max) = def.max
            && n > max
        {
            return Err(format!("{n} is above the maximum {max}"));
        }
    }
    Ok(out)
}

/// Expand a leading `~` to the home directory.
pub fn expand_path(text: &str) -> PathBuf {
    if text == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
        return dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest);
    }
    PathBuf::from(text)
}

/// Display form of a value in CLI tables (`a, b` for lists, bare strings).
pub fn display(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| i.to_string())
            })
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::find;

    #[test]
    fn bytes_parse_with_units() {
        assert_eq!(parse_bytes("1024"), Some(1024));
        assert_eq!(parse_bytes("2GiB"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_bytes("1.5 MB"), Some(1_500_000));
        assert_eq!(parse_bytes("1.5MiB"), Some(1_572_864));
        assert_eq!(parse_bytes("lots"), None);
    }

    #[test]
    fn text_coercion_per_type() {
        let list = find("policy.allow_cloud_targets").unwrap();
        assert_eq!(
            from_text(list, "local, slurm").unwrap(),
            json!(["local", "slurm"])
        );
        assert_eq!(from_text(list, r#"["local"]"#).unwrap(), json!(["local"]));
        let err = from_text(list, "local,moon").unwrap_err();
        assert!(err.contains("\"moon\" is not allowed"), "{err}");
        let b = find("policy.allow_public_hub").unwrap();
        assert_eq!(from_text(b, "no").unwrap(), json!(false));
        assert!(from_text(b, "maybe").unwrap_err().contains("true or false"));
        let bytes = find("hub.max_bytes").unwrap();
        assert_eq!(from_text(bytes, "1GB").unwrap(), json!(1_000_000_000u64));
    }

    #[test]
    fn validation_messages_name_the_expectation() {
        let url = find("client.server_url").unwrap();
        let err = coerce(url, &json!("frontier.example.com")).unwrap_err();
        assert!(err.contains("http://"), "{err}");
        assert_eq!(
            coerce(url, &json!("https://x/")).unwrap(),
            json!("https://x")
        );
        let cost = find("policy.max_cost_per_run").unwrap();
        assert!(
            coerce(cost, &json!(-1.0))
                .unwrap_err()
                .contains("below the minimum")
        );
        let theme = find("ui.theme").unwrap();
        assert!(
            coerce(theme, &json!("pink"))
                .unwrap_err()
                .contains("one of: system, light, dark")
        );
        assert!(
            coerce(theme, &json!(3))
                .unwrap_err()
                .contains("got a number")
        );
    }
}
