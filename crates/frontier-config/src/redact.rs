// SPDX-License-Identifier: Apache-2.0
//! Removing known secret values from text before it is logged or stored.

/// Replaces every known secret with `***`. Values shorter than 6 characters are not treated
/// as secrets (replacing them would mangle ordinary text).
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

pub const MASK: &str = "***";

impl Redactor {
    pub fn new(secrets: impl IntoIterator<Item = String>) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= 6)
            .collect();
        // longest first so a secret containing another is replaced whole
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Self { secrets }
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for s in &self.secrets {
            if out.contains(s.as_str()) {
                out = out.replace(s.as_str(), MASK);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_values_only() {
        let r = Redactor::new([
            "hf_abcdef123456".to_string(),
            "abc".to_string(),
            "hf_abcdef".to_string(),
        ]);
        assert_eq!(
            r.redact("Authorization: Bearer hf_abcdef123456 then hf_abcdef and abc"),
            "Authorization: Bearer *** then *** and abc"
        );
        assert!(Redactor::new([String::new()]).is_empty());
    }
}
