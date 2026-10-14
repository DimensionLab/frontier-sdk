// SPDX-License-Identifier: Apache-2.0
//! Editing config files in place. `toml_edit` keeps comments, ordering and formatting of
//! everything that is not touched; writes go through a temporary file and a rename so a
//! crash never leaves half a file.

use crate::schema::{self, SettingDef};
use crate::{Error, Result, value};
use serde_json::Value;
use std::path::Path;
use toml_edit::{Array, DocumentMut, Item, Table};

fn load(path: &Path) -> Result<DocumentMut> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::io(path, e)),
    };
    text.parse::<DocumentMut>().map_err(|e| Error::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

/// Write `text` to `path` atomically, creating parent directories. `mode` is applied on Unix.
pub fn atomic_write(path: &Path, text: &str, mode: Option<u32>) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = opts.open(&tmp).map_err(|e| Error::io(&tmp, e))?;
        std::io::Write::write_all(&mut f, text.as_bytes()).map_err(|e| Error::io(&tmp, e))?;
        f.sync_all().ok();
    }
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(&tmp, e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}

fn to_item(v: &Value) -> Item {
    match v {
        Value::String(s) => toml_edit::value(s.as_str()),
        Value::Bool(b) => toml_edit::value(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => toml_edit::value(i),
            None => toml_edit::value(n.as_f64().unwrap_or_default()),
        },
        Value::Array(items) => {
            let mut a = Array::new();
            for i in items {
                match i {
                    Value::String(s) => a.push(s.as_str()),
                    Value::Number(n) if n.is_i64() => a.push(n.as_i64().unwrap_or_default()),
                    Value::Number(n) => a.push(n.as_f64().unwrap_or_default()),
                    Value::Bool(b) => a.push(*b),
                    other => a.push(other.to_string()),
                }
            }
            toml_edit::value(a)
        }
        // A table setting (`compute.pools`) is written inline: `pools = { training = { ... } }`.
        Value::Object(map) => {
            let mut t = toml_edit::InlineTable::new();
            for (k, v) in map {
                if let Item::Value(v) = to_item(v) {
                    t.insert(k, v);
                }
            }
            toml_edit::value(t)
        }
        Value::Null => toml_edit::value(""),
    }
}

fn known(key: &str) -> Result<&'static SettingDef> {
    schema::find(key).ok_or_else(|| Error::UnknownKey {
        key: key.to_string(),
        suggestions: schema::suggest(key).iter().map(|s| s.to_string()).collect(),
    })
}

/// Validate `value` for `key` (strings are parsed as the setting's type) and return the
/// normalised value.
pub fn validate(key: &str, value: &Value) -> Result<Value> {
    let def = known(key)?;
    let checked = match value {
        Value::String(s) if def.ty != schema::SettingType::String => value::from_text(def, s),
        other => value::coerce(def, other),
    };
    checked.map_err(|message| Error::Invalid {
        key: key.to_string(),
        message,
    })
}

/// Set `key` in the file at `path`. Returns the normalised value that was written.
pub fn set_in_file(path: &Path, key: &str, value: &Value) -> Result<Value> {
    let def = known(key)?;
    let value = validate(key, value)?;
    let mut doc = load(path)?;
    let section = doc
        .entry(def.section_id())
        .or_insert_with(|| Item::Table(Table::new()));
    let mut table = section.as_table_mut().ok_or_else(|| Error::Parse {
        path: path.to_path_buf(),
        message: format!("`{}` is not a table", def.section_id()),
    })?;
    // `policy.ai.allowed_providers` lives in `[policy.ai]`
    let (sub, leaf) = match def.name().split_once('.') {
        Some((sub, leaf)) => (Some(sub), leaf),
        None => (None, def.name()),
    };
    if let Some(sub) = sub {
        let item = table
            .entry(sub)
            .or_insert_with(|| Item::Table(Table::new()));
        if let Item::Value(toml_edit::Value::InlineTable(inline)) = item {
            *item = Item::Table(std::mem::take(inline).into_table());
        }
        table = item.as_table_mut().ok_or_else(|| Error::Parse {
            path: path.to_path_buf(),
            message: format!("`{}.{sub}` is not a table", def.section_id()),
        })?;
    }
    let new = to_item(&value);
    match table.get_mut(leaf) {
        // keep the comment that trails or precedes the existing value
        Some(Item::Value(old)) => {
            let decor = old.decor().clone();
            if let Item::Value(mut v) = new {
                *v.decor_mut() = decor;
                *old = v;
            }
        }
        _ => {
            table.insert(leaf, new);
        }
    }
    atomic_write(path, &doc.to_string(), None)?;
    Ok(value)
}

/// Remove a nested key (`policy.ai.local_model` from `[policy.ai]`); an emptied sub-table
/// goes with it.
fn unset_nested(path: &Path, def: &SettingDef, sub: &str, leaf: &str) -> Result<bool> {
    let mut doc = load(path)?;
    let Some(section) = doc.get_mut(def.section_id()).and_then(Item::as_table_mut) else {
        return Ok(false);
    };
    let Some(table) = section.get_mut(sub).and_then(Item::as_table_like_mut) else {
        return Ok(false);
    };
    if table.remove(leaf).is_none() {
        return Ok(false);
    }
    if table.is_empty() {
        section.remove(sub);
    }
    atomic_write(path, &doc.to_string(), None)?;
    Ok(true)
}

/// Remove `key` from the file at `path`. Returns whether it was present.
///
/// Only the `key = value` line goes. Comments above it stay (in the template they are the
/// documentation of the commented-out settings before it), and a section that becomes
/// empty keeps its header when it or the value carried comments: removing the last value
/// of `[storage]` must not make the lines that followed the header read as part of the
/// previous section.
pub fn unset_in_file(path: &Path, key: &str) -> Result<bool> {
    let def = known(key)?;
    if !path.is_file() {
        return Ok(false);
    }
    if let Some((sub, leaf)) = def.name().split_once('.') {
        return unset_nested(path, def, sub, leaf);
    }
    let mut doc = load(path)?;
    let section = def.section_id();
    let Some(table) = doc.get_mut(section).and_then(Item::as_table_mut) else {
        return Ok(false);
    };
    let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
    let Some(index) = keys.iter().position(|k| k == def.name()) else {
        return Ok(false);
    };
    // The comment lines the parser attached to this key.
    let orphaned = table
        .key(def.name())
        .and_then(|k| k.leaf_decor().prefix())
        .and_then(|raw| raw.as_str())
        .unwrap_or("")
        .to_string();
    let position = table.position();
    table.remove(def.name());
    // A section this tool created for the value alone (no comment on the header, none on
    // the value) goes with it.
    let bare_header = table
        .decor()
        .prefix()
        .and_then(|raw| raw.as_str())
        .unwrap_or("")
        .trim()
        .is_empty();
    if table.is_empty() && bare_header && orphaned.trim().is_empty() {
        doc.remove(section);
    } else if !orphaned.trim().is_empty() {
        let joined = |old: Option<&toml_edit::RawString>| {
            format!("{orphaned}{}", old.and_then(|r| r.as_str()).unwrap_or(""))
        };
        if let Some(mut next) = keys.get(index + 1).and_then(|k| table.key_mut(k)) {
            // the next value of the same section inherits them
            let text = joined(next.leaf_decor().prefix());
            next.leaf_decor_mut().set_prefix(text);
        } else {
            // last value of its section: they go in front of the next header, or to the
            // end of the file
            let next_table = doc
                .iter_mut()
                .filter_map(|(_, item)| item.as_table_mut())
                .filter(|t| t.position() > position && position.is_some())
                .min_by_key(|t| t.position());
            match next_table {
                Some(t) => {
                    let text = joined(t.decor().prefix());
                    t.decor_mut().set_prefix(text);
                }
                None => {
                    let text = joined(Some(doc.trailing()));
                    doc.set_trailing(text);
                }
            }
        }
    }
    atomic_write(path, &doc.to_string(), None)?;
    Ok(true)
}

/// A commented starting config: every setting of the given scopes as a commented-out line
/// with its description, so the file documents itself and changes nothing until edited.
pub fn template(for_system: bool) -> String {
    let mut out = String::new();
    if for_system {
        out.push_str(
            "# Frontier system configuration (administrators).\n\
             # Location: /etc/frontier/config.toml. Values here are defaults for every user of\n\
             # this machine; keys listed under [lock] cannot be overridden by users, projects,\n\
             # environment variables or command-line flags.\n\
             # Reference: the Frontier configuration guide. Credentials never go in this file.\n",
        );
    } else {
        out.push_str(
            "# Frontier user configuration.\n\
             # Uncomment a line to change a setting, or use `frontier config set <key> <value>`.\n\
             # `frontier config explain <key>` shows the effective value and where it comes from.\n\
             # Credentials never go in this file: use `frontier auth login <provider>`.\n",
        );
    }
    for (id, title, description) in schema::SECTIONS {
        let defs: Vec<&SettingDef> = schema::registry()
            .iter()
            .filter(|d| d.section_id() == *id)
            .filter(|d| {
                for_system || matches!(d.scope, schema::Scope::User | schema::Scope::Project)
            })
            .collect();
        if defs.is_empty() {
            continue;
        }
        out.push_str(&format!("\n# {title}: {description}\n[{id}]\n"));
        for def in defs {
            for line in wrap(&def.description, 92) {
                out.push_str(&format!("# {line}\n"));
            }
            if let Some(choices) = &def.choices {
                out.push_str(&format!("# One of: {}\n", choices.join(", ")));
            }
            let rendered = to_item(&def.default).to_string();
            out.push_str(&format!("# {} = {}\n", def.name(), rendered.trim()));
        }
    }
    if for_system {
        out.push_str(
            "\n# Keys users may not override, with the reason shown to them.\n\
             [lock]\n\
             # \"policy.allow_public_hub\" = \"Only the internal dataset mirror is approved\"\n\
             # \"policy.*\" = true\n",
        );
    }
    out
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn set_preserves_comments_and_unrelated_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "# my notes\n[ui]\ntheme = \"dark\"  # easier on the eyes\n\n[storage]\n# big disk\ndatasets_dir = \"/data\"\n",
        )
        .unwrap();
        set_in_file(&path, "ui.theme", &json!("light")).unwrap();
        set_in_file(&path, "hub.max_bytes", &json!("1GiB")).unwrap();
        set_in_file(&path, "policy.allow_cloud_targets", &json!("local,slurm")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# my notes"), "{text}");
        assert!(
            text.contains("theme = \"light\"  # easier on the eyes"),
            "{text}"
        );
        assert!(
            text.contains("# big disk\ndatasets_dir = \"/data\""),
            "{text}"
        );
        assert!(text.contains("max_bytes = 1073741824"), "{text}");
        assert!(
            text.contains("allow_cloud_targets = [\"local\", \"slurm\"]"),
            "{text}"
        );
        assert!(unset_in_file(&path, "hub.max_bytes").unwrap());
        assert!(!unset_in_file(&path, "hub.max_bytes").unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("[hub]"), "{text}");
        // no temp files left behind
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn unset_gives_back_the_file_it_started_from() {
        // The template documents every setting as a comment. Setting and unsetting a
        // value, in the middle or at the end of a section, must leave it as it was:
        // headers, descriptions and the order of sections.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = template(false);
        for key in [
            "storage.datasets_dir",
            "compute.image",
            "ui.refresh_ms",
            "client.server_url",
        ] {
            std::fs::write(&path, &original).unwrap();
            let value = match key {
                "ui.refresh_ms" => json!(250),
                "client.server_url" => json!("https://frontier.example.com"),
                _ => json!("/somewhere"),
            };
            set_in_file(&path, key, &value).unwrap();
            assert!(unset_in_file(&path, key).unwrap());
            let after = std::fs::read_to_string(&path).unwrap();
            let headers = |t: &str| -> Vec<String> {
                t.lines()
                    .filter(|l| l.starts_with('['))
                    .map(str::to_string)
                    .collect()
            };
            assert_eq!(headers(&after), headers(&original), "{key}: {after}");
            let comments = |t: &str| t.lines().filter(|l| l.starts_with('#')).count();
            assert_eq!(comments(&after), comments(&original), "{key}");
            // each commented default is still under its own section header
            let section = key.split('.').next().unwrap();
            let name = key.split('.').nth(1).unwrap();
            let start = after.find(&format!("[{section}]")).unwrap();
            let end = after[start + 1..]
                .find("\n[")
                .map_or(after.len(), |i| start + 1 + i);
            assert!(
                after[start..end].contains(&format!("# {name} = ")),
                "{key} left its section: {after}"
            );
            assert!(!unset_in_file(&path, key).unwrap(), "{key} twice");
        }
        // a value two sets apart in one section
        std::fs::write(
            &path,
            "[ui]\n# first\ntheme = \"dark\"\n# second\nunits = \"si\"\n",
        )
        .unwrap();
        unset_in_file(&path, "ui.theme").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[ui]\n# first\n# second\nunits = \"si\"\n"
        );
    }

    #[test]
    fn set_rejects_unknown_keys_and_bad_values_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let err = set_in_file(&path, "storage.dataset_dir", &json!("/x")).unwrap_err();
        assert!(
            err.to_string()
                .contains("did you mean storage.datasets_dir"),
            "{err}"
        );
        let err = set_in_file(&path, "ui.theme", &json!("pink")).unwrap_err();
        assert!(
            err.to_string().contains("ui.theme") && err.to_string().contains("one of"),
            "{err}"
        );
        assert!(!path.exists());
    }

    #[test]
    fn templates_are_valid_toml_and_change_nothing() {
        for system in [false, true] {
            let text = template(system);
            let table: toml::Table = text.parse().unwrap();
            for (section, body) in &table {
                assert!(
                    body.as_table().unwrap().is_empty(),
                    "{section} sets a value"
                );
            }
            // uncommenting every setting line still parses and validates
            let live: String = text
                .lines()
                .map(|l| match l.strip_prefix("# ") {
                    Some(rest)
                        if rest.contains(" = ")
                            && !rest.starts_with('"')
                            && rest.split(" = ").next().is_some_and(|k| {
                                k.chars().all(|c| {
                                    c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()
                                })
                            }) =>
                    {
                        rest.to_string()
                    }
                    _ => l.to_string(),
                })
                .collect::<Vec<_>>()
                .join("\n");
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("config.toml");
            std::fs::write(&file, &live).unwrap();
            let c = crate::Config::load(&crate::LoadOptions {
                system_file: system.then(|| file.clone()),
                home: if system {
                    dir.path().join("none")
                } else {
                    dir.path().to_path_buf()
                },
                ..Default::default()
            });
            assert!(c.problems.is_empty(), "{:?}", c.problems);
        }
        // the user template carries the user-scoped `[policy.ai]` preferences only
        let user = template(false);
        assert!(
            user.contains("[policy]") && user.contains("# ai.local_model"),
            "{user}"
        );
        assert!(!user.contains("allow_cloud_targets"));
        assert!(template(true).contains("allow_cloud_targets"));
    }
}
