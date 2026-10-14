// SPDX-License-Identifier: Apache-2.0
//! Compute pools: the shape of the `compute.pools` table, its validation, and device
//! matching. A pool names devices by node (`node_id`, hostname or a glob) and/or by GPU
//! (uuid, `<node>:<index>`, `*:<index>` or a bare index), carries a role mask and optional
//! quotas. Every device no pool names belongs to the built-in `auto` pool.
//!
//! ```toml
//! [compute.pools.rendering]
//! gpus = ["*:0"]                  # GPU 0 of every node
//! roles = ["rendering"]
//!
//! [compute.pools.training]
//! nodes = ["gpu-[0-3]*"]
//! roles = ["training", "prep"]
//! quota = { gpus = 32 }
//! priority = 10
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Name of the implicit pool holding every device no explicit pool names.
pub const AUTO_POOL: &str = "auto";

pub const ROLES: [&str; 5] = ["training", "inference", "rendering", "prep", "any"];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Quota {
    /// Devices this pool hands out at the same time (0 = all of them).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gpus: u32,
    /// Jobs running in this pool at the same time (0 = unlimited).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub jobs: u32,
    /// Largest number of GPUs one job may take from this pool (0 = unlimited).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gpus_per_job: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}
fn is_false(b: &bool) -> bool {
    !*b
}

/// One `[compute.pools.<name>]` table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Node patterns: `node_id`, hostname, or a glob with `*`/`?`/`[a-z]` over either.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// Device patterns: `GPU-<uuid>`, `<node>:<index>`, `*:<index>`, or a bare index (which
    /// means that index on every node of `nodes`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpus: Vec<String>,
    /// `training`, `inference`, `rendering`, `prep`, `any`. Empty = `any`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "quota_is_empty")]
    pub quota: Quota,
    /// Pools with a higher priority are tried first by `auto`.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub priority: i32,
    /// A device may belong to this pool and another `shared` pool (a rendering pool that
    /// borrows GPU 0 of the training nodes). Two non-shared pools may not overlap.
    #[serde(default, skip_serializing_if = "is_false")]
    pub shared: bool,
    /// Optional scheduler mapping for SLURM sites and cloud providers (`partition`,
    /// `gres`, `constraint`, `qos`, `account`, `instance_type`, `gpu_type`, `tier`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub map: BTreeMap<String, String>,
}

fn quota_is_empty(q: &Quota) -> bool {
    *q == Quota::default()
}
fn is_zero_i(n: &i32) -> bool {
    *n == 0
}

impl Default for PoolDef {
    fn default() -> Self {
        Self {
            description: String::new(),
            nodes: Vec::new(),
            gpus: Vec::new(),
            roles: vec!["any".into()],
            quota: Quota::default(),
            priority: 0,
            shared: false,
            map: BTreeMap::new(),
        }
    }
}

impl PoolDef {
    /// Roles with the empty list normalised to `any`.
    pub fn roles(&self) -> Vec<String> {
        if self.roles.is_empty() {
            vec!["any".into()]
        } else {
            self.roles.clone()
        }
    }

    pub fn serves(&self, role: &str) -> bool {
        role == "any" || self.roles().iter().any(|r| r == "any" || r == role)
    }

    /// Whether this pool names the node at all (no `nodes` = every node).
    pub fn matches_node(&self, node_id: &str, hostname: &str) -> bool {
        self.nodes.is_empty()
            || self
                .nodes
                .iter()
                .any(|p| glob_match(p, node_id) || glob_match(p, hostname))
    }

    /// Whether the device `(uuid, index)` on `(node_id, hostname)` belongs to this pool.
    pub fn matches_device(
        &self,
        node_id: &str,
        hostname: &str,
        uuid: Option<&str>,
        index: u32,
    ) -> bool {
        if !self.matches_node(node_id, hostname) {
            return false;
        }
        if self.gpus.is_empty() {
            // the whole node, but only when the pool names nodes (a pool naming nothing is
            // invalid; see `validate`)
            return !self.nodes.is_empty();
        }
        self.gpus.iter().any(|p| {
            if let Some(u) = uuid
                && (p == u || glob_match(p, u))
            {
                return true;
            }
            match p.rsplit_once(':') {
                Some((node, idx)) => {
                    idx.parse::<u32>().ok() == Some(index)
                        && (node == "*" || glob_match(node, node_id) || glob_match(node, hostname))
                }
                None => p.parse::<u32>().ok() == Some(index),
            }
        })
    }
}

/// Glob with `*`, `?` and `[...]` classes, case-sensitive.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| rec(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && rec(&p[1..], &t[1..]),
            Some('[') => {
                let Some(end) = p.iter().position(|c| *c == ']') else {
                    return !t.is_empty() && t[0] == '[' && rec(&p[1..], &t[1..]);
                };
                let Some(&c) = t.first() else { return false };
                let class = &p[1..end];
                let (negate, class) = match class.first() {
                    Some('!') | Some('^') => (true, &class[1..]),
                    _ => (false, class),
                };
                let mut hit = false;
                let mut i = 0;
                while i < class.len() {
                    if i + 2 < class.len() && class[i + 1] == '-' {
                        if class[i] <= c && c <= class[i + 2] {
                            hit = true;
                        }
                        i += 3;
                    } else {
                        if class[i] == c {
                            hit = true;
                        }
                        i += 1;
                    }
                }
                hit != negate && rec(&p[end + 1..], &t[1..])
            }
            Some(c) => !t.is_empty() && t[0] == *c && rec(&p[1..], &t[1..]),
        }
    }
    if !pattern.contains(['*', '?', '[']) {
        return pattern == text;
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    rec(&p, &t)
}

/// Parse the `compute.pools` value. Unknown keys inside a pool are errors (a typo in
/// `roles` would otherwise silently open a pool to every role).
pub fn parse_pools(value: &Value) -> Result<BTreeMap<String, PoolDef>, String> {
    let Some(map) = value.as_object() else {
        if value.is_null() {
            return Ok(BTreeMap::new());
        }
        return Err("`compute.pools` must be a table of pools".into());
    };
    let mut out = BTreeMap::new();
    for (name, body) in map {
        let def: PoolDef = serde_json::from_value(strict(body.clone())?)
            .map_err(|e| format!("pool `{name}`: {e}"))?;
        out.insert(name.clone(), def);
    }
    validate(&out)?;
    Ok(out)
}

fn strict(v: Value) -> Result<Value, String> {
    const KEYS: [&str; 8] = [
        "description",
        "nodes",
        "gpus",
        "roles",
        "quota",
        "priority",
        "shared",
        "map",
    ];
    if let Some(o) = v.as_object() {
        for k in o.keys() {
            if !KEYS.contains(&k.as_str()) {
                return Err(format!(
                    "unknown key `{k}` (expected one of {})",
                    KEYS.join(", ")
                ));
            }
        }
    } else {
        return Err("a pool is a table".into());
    }
    Ok(v)
}

/// Structural validation: names, roles, at least one selector, quotas.
pub fn validate(pools: &BTreeMap<String, PoolDef>) -> Result<(), String> {
    for (name, def) in pools {
        if name == AUTO_POOL {
            return Err(format!(
                "`{AUTO_POOL}` is the built-in pool and cannot be defined"
            ));
        }
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "pool name `{name}` must be letters, digits, `-` or `_`"
            ));
        }
        if def.nodes.is_empty() && def.gpus.is_empty() {
            return Err(format!("pool `{name}` names no nodes and no gpus"));
        }
        for r in def.roles() {
            if !ROLES.contains(&r.as_str()) {
                return Err(format!(
                    "pool `{name}`: unknown role `{r}` (expected one of {})",
                    ROLES.join(", ")
                ));
            }
        }
        for p in def.nodes.iter().chain(def.gpus.iter()) {
            if p.trim().is_empty() {
                return Err(format!("pool `{name}` has an empty pattern"));
            }
        }
        if def.quota.gpus_per_job > def.quota.gpus && def.quota.gpus > 0 {
            return Err(format!(
                "pool `{name}`: quota.gpus_per_job ({}) exceeds quota.gpus ({})",
                def.quota.gpus_per_job, def.quota.gpus
            ));
        }
    }
    Ok(())
}

/// A device as the overlap check sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRef<'a> {
    pub node_id: &'a str,
    pub hostname: &'a str,
    pub uuid: Option<&'a str>,
    pub index: u32,
}

/// Which pools a device belongs to, in priority order (highest first); `auto` when none.
pub fn pools_of(pools: &BTreeMap<String, PoolDef>, d: &DeviceRef<'_>) -> Vec<String> {
    let mut hits: Vec<(&String, &PoolDef)> = pools
        .iter()
        .filter(|(_, p)| p.matches_device(d.node_id, d.hostname, d.uuid, d.index))
        .collect();
    hits.sort_by(|a, b| b.1.priority.cmp(&a.1.priority).then(a.0.cmp(b.0)));
    if hits.is_empty() {
        vec![AUTO_POOL.into()]
    } else {
        hits.into_iter().map(|(n, _)| n.clone()).collect()
    }
}

/// Devices in two pools that are not both `shared`: `(device, pool a, pool b)`.
pub fn overlaps(
    pools: &BTreeMap<String, PoolDef>,
    devices: &[DeviceRef<'_>],
) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for d in devices {
        let names = pools_of(pools, d);
        for i in 0..names.len() {
            for j in i + 1..names.len() {
                let (a, b) = (&names[i], &names[j]);
                let shared = pools.get(a).is_some_and(|p| p.shared)
                    && pools.get(b).is_some_and(|p| p.shared);
                if !shared {
                    let id = d
                        .uuid
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{}:{}", d.node_id, d.index));
                    out.push((id, a.clone(), b.clone()));
                }
            }
        }
    }
    out
}

/// The effective pool table of a configuration.
pub fn from_config(config: &crate::Config) -> Result<BTreeMap<String, PoolDef>, String> {
    parse_pools(&config.json("compute.pools"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn globs() {
        assert!(glob_match("gpu-*", "gpu-01"));
        assert!(glob_match("gpu-0[0-3]", "gpu-02"));
        assert!(!glob_match("gpu-0[0-3]", "gpu-07"));
        assert!(glob_match("node?", "node7"));
        assert!(glob_match("plain", "plain"));
        assert!(!glob_match("plain", "plains"));
        assert!(glob_match("GPU-ab*", "GPU-abcdef"));
    }

    #[test]
    fn parses_and_validates() {
        let pools = parse_pools(&json!({
            "rendering": {"gpus": ["*:0"], "roles": ["rendering"], "shared": true},
            "training": {"nodes": ["gpu-*"], "roles": ["training", "prep"], "quota": {"gpus": 8}, "priority": 5, "shared": true},
        }))
        .unwrap();
        assert_eq!(pools["training"].quota.gpus, 8);
        assert!(pools["rendering"].serves("rendering"));
        assert!(!pools["rendering"].serves("training"));
        assert!(pools["training"].serves("any"));

        assert!(parse_pools(&json!({"auto": {"nodes": ["x"]}})).is_err());
        assert!(parse_pools(&json!({"x": {}})).is_err());
        assert!(parse_pools(&json!({"x": {"nodes": ["a"], "roles": ["gpu"]}})).is_err());
        assert!(parse_pools(&json!({"x": {"nodes": ["a"], "rolez": ["any"]}})).is_err());
        assert!(parse_pools(&json!({"bad name": {"nodes": ["a"]}})).is_err());
        assert!(parse_pools(&Value::Null).unwrap().is_empty());
    }

    #[test]
    fn device_membership_and_overlaps() {
        let pools = parse_pools(&json!({
            "rendering": {"gpus": ["*:0"], "roles": ["rendering"]},
            "training": {"nodes": ["gpu-*"], "roles": ["training"]},
            "serving": {"gpus": ["GPU-aaaa"], "roles": ["inference"]},
        }))
        .unwrap();
        let d0 = DeviceRef {
            node_id: "n1",
            hostname: "gpu-1",
            uuid: Some("GPU-aaaa"),
            index: 0,
        };
        let d1 = DeviceRef {
            node_id: "n1",
            hostname: "gpu-1",
            uuid: Some("GPU-bbbb"),
            index: 1,
        };
        let d2 = DeviceRef {
            node_id: "n9",
            hostname: "laptop",
            uuid: None,
            index: 0,
        };
        let d3 = DeviceRef {
            node_id: "n9",
            hostname: "laptop",
            uuid: None,
            index: 1,
        };
        assert_eq!(
            pools_of(&pools, &d0),
            vec!["rendering", "serving", "training"]
        );
        assert_eq!(pools_of(&pools, &d1), vec!["training"]);
        assert_eq!(pools_of(&pools, &d2), vec!["rendering"]);
        assert_eq!(pools_of(&pools, &d3), vec![AUTO_POOL]);
        let o = overlaps(&pools, &[d0.clone(), d1, d2, d3]);
        assert_eq!(o.len(), 3, "{o:?}");
        assert!(
            o.iter()
                .any(|(id, a, b)| id == "GPU-aaaa" && a == "rendering" && b == "serving")
        );

        let shared = parse_pools(&json!({
            "rendering": {"gpus": ["*:0"], "roles": ["rendering"], "shared": true},
            "training": {"nodes": ["gpu-*"], "roles": ["training"], "shared": true},
        }))
        .unwrap();
        assert!(overlaps(&shared, &[d0]).is_empty());
    }

    #[test]
    fn bare_index_and_node_index_patterns() {
        let pools = parse_pools(&json!({
            "p": {"nodes": ["gpu-1"], "gpus": ["1", "gpu-2:3"]},
        }))
        .unwrap();
        let p = &pools["p"];
        assert!(p.matches_device("n1", "gpu-1", None, 1));
        assert!(!p.matches_device("n1", "gpu-1", None, 0));
        // `gpu-2:3` names another node than `nodes` allows: node filter wins
        assert!(!p.matches_device("n2", "gpu-2", None, 3));
    }
}
