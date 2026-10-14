// SPDX-License-Identifier: Apache-2.0
//! The schema files committed to the Python SDK must match the registry. Regenerate with
//! `pnpm nx run frontier-config:export-schema` (sets `FRONTIER_UPDATE_GENERATED=1`).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn pretty(v: &serde_json::Value) -> String {
    let mut s = serde_json::to_string_pretty(&frontier_config::schema::canonical(v)).expect("json");
    s.push('\n');
    s
}

fn check(path: &Path, expected: &str) {
    if std::env::var("FRONTIER_UPDATE_GENERATED").is_ok() {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, expected).expect("write");
        return;
    }
    let actual = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        actual == expected,
        "{} is out of date with the registry in crates/frontier-config; run `pnpm nx run frontier-config:export-schema`",
        path.display()
    );
}

#[test]
fn python_schema_and_providers_match_the_registry() {
    let pkg = repo_root().join("packages/frontier/src/frontier");
    if !pkg.is_dir() {
        return; // standalone checkout of the crate (public mirror)
    }
    check(
        &pkg.join("config_schema.json"),
        &pretty(&frontier_config::schema::flat_json()),
    );
    check(
        &pkg.join("auth_providers.json"),
        &pretty(&serde_json::to_value(frontier_config::credentials::builtin()).expect("json")),
    );
}
