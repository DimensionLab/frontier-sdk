// SPDX-License-Identifier: Apache-2.0
//! Change detection for config files. Long-running processes (the server, the TUI, the app)
//! call [`Watcher::changed`] on a timer and reload when it returns `true`. Polling metadata
//! keeps this dependency-free and works on network file systems where inotify does not.

use crate::loader::Paths;
use std::path::PathBuf;
use std::time::SystemTime;

type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &PathBuf) -> Stamp {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// Remembers the modification time and size of each layer file.
#[derive(Debug)]
pub struct Watcher {
    files: Vec<(PathBuf, Stamp)>,
}

impl Watcher {
    pub fn new(files: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|p| {
                    let s = stamp(&p);
                    (p, s)
                })
                .collect(),
        }
    }

    /// Watch the system, user and project files of `paths`.
    pub fn for_paths(paths: &Paths) -> Self {
        let mut files = vec![paths.system.clone(), paths.user.clone()];
        files.extend(paths.project.clone());
        Self::new(files)
    }

    /// `true` once after any watched file was created, changed or removed.
    pub fn changed(&mut self) -> bool {
        let mut any = false;
        for (path, old) in &mut self.files {
            let new = stamp(path);
            if new != *old {
                *old = new;
                any = true;
            }
        }
        any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_create_change_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut w = Watcher::new([path.clone()]);
        assert!(!w.changed());
        std::fs::write(&path, "a").unwrap();
        assert!(w.changed());
        assert!(!w.changed());
        std::fs::write(&path, "ab").unwrap();
        assert!(w.changed());
        std::fs::remove_file(&path).unwrap();
        assert!(w.changed());
        assert!(!w.changed());
    }
}
