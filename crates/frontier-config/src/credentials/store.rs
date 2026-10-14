// SPDX-License-Identifier: Apache-2.0
//! Local secret stores. One entry is `(provider id, field name) -> value`.
//!
//! | backend    | where                                                                        |
//! |------------|------------------------------------------------------------------------------|
//! | `keychain` | macOS Keychain, Windows Credential Manager, Secret Service (via `secret-tool`) |
//! | `file`     | `<frontier home>/credentials.toml`, mode 0600                                |
//! | `env`      | the process environment, read-only                                           |
//! | `vault`    | HashiCorp Vault KV v2 (`super::remote`, feature `http`)                      |
//! | `aws`      | AWS Secrets Manager (`super::remote`, feature `http`)                        |
//!
//! The control plane has its own encrypted store (private, in `frontier-server`).

use super::Registry;
use crate::loader::Config;
use crate::{Error, Result, edit};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Service name of every keychain entry; the account is `<provider>/<field>`.
pub const KEYCHAIN_SERVICE: &str = "org.dimensionlab.frontier";
/// File name of the file store inside the Frontier home.
pub const CREDENTIALS_FILE: &str = "credentials.toml";

pub trait SecretStore: Send + Sync {
    /// `keychain`, `file`, `env`, `vault`, `aws` or `memory`.
    fn name(&self) -> &'static str;
    /// Where the values physically are, for `frontier auth status` and `doctor`.
    fn describe(&self) -> String;
    fn get(&self, provider: &str, field: &str) -> Result<Option<String>>;
    fn set(&self, provider: &str, field: &str, value: &str) -> Result<()>;
    /// Returns whether an entry existed.
    fn delete(&self, provider: &str, field: &str) -> Result<bool>;
    fn writable(&self) -> bool {
        true
    }
}

fn account(provider: &str, field: &str) -> String {
    format!("{provider}/{field}")
}

// -- file ---------------------------------------------------------------------------------

/// `credentials.toml`, readable by the owner only.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn in_home(home: &Path) -> Self {
        Self::new(home.join(CREDENTIALS_FILE))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<toml_edit::DocumentMut> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(Error::io(&self.path, e)),
        };
        #[cfg(unix)]
        if !text.is_empty() {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&self.path)
                .map_err(|e| Error::io(&self.path, e))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(Error::Store(format!(
                    "{} is readable by other users (mode {:o}); run `chmod 600 {}`",
                    self.path.display(),
                    mode & 0o777,
                    self.path.display()
                )));
            }
        }
        text.parse()
            .map_err(|e: toml_edit::TomlError| Error::Parse {
                path: self.path.clone(),
                message: e.to_string(),
            })
    }

    fn write(&self, doc: &toml_edit::DocumentMut) -> Result<()> {
        let mut text = doc.to_string();
        if !text.starts_with('#') {
            text.insert_str(
                0,
                "# Frontier credentials. Written by `frontier auth login`; do not commit or share.\n",
            );
        }
        edit::atomic_write(&self.path, &text, Some(0o600))
    }
}

impl SecretStore for FileStore {
    fn name(&self) -> &'static str {
        "file"
    }
    fn describe(&self) -> String {
        format!("file {} (owner-only)", self.path.display())
    }
    fn get(&self, provider: &str, field: &str) -> Result<Option<String>> {
        Ok(self
            .read()?
            .get(provider)
            .and_then(|t| t.get(field))
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }
    fn set(&self, provider: &str, field: &str, value: &str) -> Result<()> {
        let mut doc = self.read()?;
        let table = doc
            .entry(provider)
            .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
        let table = table.as_table_mut().ok_or_else(|| Error::Parse {
            path: self.path.clone(),
            message: format!("`{provider}` is not a table"),
        })?;
        table.insert(field, toml_edit::value(value));
        self.write(&doc)
    }
    fn delete(&self, provider: &str, field: &str) -> Result<bool> {
        if !self.path.is_file() {
            return Ok(false);
        }
        let mut doc = self.read()?;
        let Some(table) = doc.get_mut(provider).and_then(|t| t.as_table_mut()) else {
            return Ok(false);
        };
        let removed = table.remove(field).is_some();
        if removed {
            if table.is_empty() {
                doc.remove(provider);
            }
            self.write(&doc)?;
        }
        Ok(removed)
    }
}

// -- env ----------------------------------------------------------------------------------

/// Read-only: a field's value is the first of its fallback variables that is set.
#[derive(Debug, Clone)]
pub struct EnvStore {
    env: BTreeMap<String, String>,
    registry: Registry,
}

impl EnvStore {
    pub fn new(env: BTreeMap<String, String>, registry: Registry) -> Self {
        Self { env, registry }
    }

    /// The variable that provides `provider/field`, if one is set.
    pub fn variable(&self, provider: &str, field: &str) -> Option<(&str, &str)> {
        let f = self.registry.get(provider)?.field(field)?;
        f.env.iter().find_map(|name| {
            let v = self.env.get(name)?.trim();
            (!v.is_empty()).then_some((name.as_str(), v))
        })
    }
}

impl SecretStore for EnvStore {
    fn name(&self) -> &'static str {
        "env"
    }
    fn describe(&self) -> String {
        "environment variables (read-only)".into()
    }
    fn get(&self, provider: &str, field: &str) -> Result<Option<String>> {
        Ok(self.variable(provider, field).map(|(_, v)| v.to_string()))
    }
    fn set(&self, provider: &str, _field: &str, _value: &str) -> Result<()> {
        Err(Error::Store(format!(
            "the secret store is the environment (secrets.backend = \"env\"), which is read-only; set the variable for `{provider}` in the environment, or choose `keychain` or `file`"
        )))
    }
    fn delete(&self, _provider: &str, _field: &str) -> Result<bool> {
        Ok(false)
    }
    fn writable(&self) -> bool {
        false
    }
}

// -- memory (tests, and the dry-run of imports) --------------------------------------------

#[derive(Debug, Default)]
pub struct MemoryStore {
    values: Mutex<BTreeMap<String, String>>,
}

impl SecretStore for MemoryStore {
    fn name(&self) -> &'static str {
        "memory"
    }
    fn describe(&self) -> String {
        "memory (this process only)".into()
    }
    fn get(&self, provider: &str, field: &str) -> Result<Option<String>> {
        Ok(self
            .values
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?
            .get(&account(provider, field))
            .cloned())
    }
    fn set(&self, provider: &str, field: &str, value: &str) -> Result<()> {
        self.values
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?
            .insert(account(provider, field), value.to_string());
        Ok(())
    }
    fn delete(&self, provider: &str, field: &str) -> Result<bool> {
        Ok(self
            .values
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?
            .remove(&account(provider, field))
            .is_some())
    }
}

// -- keychain -----------------------------------------------------------------------------

/// The OS keychain.
#[derive(Debug, Clone, Default)]
pub struct KeychainStore;

#[cfg(all(feature = "keychain", any(target_os = "macos", target_os = "windows")))]
mod native {
    use super::*;

    pub fn available() -> bool {
        true
    }

    fn entry(provider: &str, field: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYCHAIN_SERVICE, &account(provider, field))
            .map_err(|e| Error::Store(format!("keychain: {e}")))
    }

    /// The keychain can answer with a permission dialog on the desktop (a new or rebuilt
    /// binary reading an item another one created). A terminal user gets time to answer it;
    /// a process without a terminal must not hang on a dialog nobody sees.
    fn guarded<T: Send + 'static>(op: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
        use std::io::IsTerminal;
        use std::sync::atomic::{AtomicBool, Ordering};
        // one unanswered dialog is enough: later calls in this process fail at once
        static UNRESPONSIVE: AtomicBool = AtomicBool::new(false);
        let secs = if std::io::stderr().is_terminal() {
            120
        } else {
            10
        };
        if UNRESPONSIVE.load(Ordering::Relaxed) {
            return Err(Error::Store("the OS keychain is not answering".into()));
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(op());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
            Ok(result) => result,
            Err(_) => {
                UNRESPONSIVE.store(true, Ordering::Relaxed);
                Err(Error::Store(format!(
                    "the OS keychain did not answer within {secs} s; a permission dialog is probably waiting on the desktop (choose Always Allow). On machines without a desktop session use `frontier config set secrets.backend file`"
                )))
            }
        }
    }

    pub fn get(provider: &str, field: &str) -> Result<Option<String>> {
        let entry = entry(provider, field)?;
        guarded(move || match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::Store(format!("keychain: {e}"))),
        })
    }

    pub fn set(provider: &str, field: &str, value: &str) -> Result<()> {
        let entry = entry(provider, field)?;
        let value = value.to_string();
        guarded(move || {
            entry
                .set_password(&value)
                .map_err(|e| Error::Store(format!("keychain: {e}")))
        })
    }

    pub fn delete(provider: &str, field: &str) -> Result<bool> {
        let entry = entry(provider, field)?;
        guarded(move || match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(Error::Store(format!("keychain: {e}"))),
        })
    }
}

/// Linux and other Unix desktops: the Secret Service through libsecret's `secret-tool`, so
/// no native library is linked (static and musl builds keep working).
#[cfg(all(
    feature = "keychain",
    not(any(target_os = "macos", target_os = "windows"))
))]
mod native {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn available() -> bool {
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
            && Command::new("secret-tool")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok()
    }

    fn attrs(provider: &str, field: &str) -> [String; 4] {
        [
            "service".into(),
            KEYCHAIN_SERVICE.into(),
            "username".into(),
            account(provider, field),
        ]
    }

    pub fn get(provider: &str, field: &str) -> Result<Option<String>> {
        let out = Command::new("secret-tool")
            .arg("lookup")
            .args(attrs(provider, field))
            .stderr(Stdio::null())
            .output()
            .map_err(|e| Error::Store(format!("secret-tool: {e}")))?;
        if !out.status.success() || out.stdout.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            String::from_utf8_lossy(&out.stdout)
                .trim_end_matches('\n')
                .to_string(),
        ))
    }

    pub fn set(provider: &str, field: &str, value: &str) -> Result<()> {
        let mut child = Command::new("secret-tool")
            .args(["store", "--label", &format!("Frontier {provider} {field}")])
            .args(attrs(provider, field))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Store(format!("secret-tool: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(value.as_bytes())
                .map_err(|e| Error::Store(format!("secret-tool: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| Error::Store(format!("secret-tool: {e}")))?;
        if !out.status.success() {
            return Err(Error::Store(format!(
                "secret-tool store failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    pub fn delete(provider: &str, field: &str) -> Result<bool> {
        let existed = get(provider, field)?.is_some();
        if existed {
            Command::new("secret-tool")
                .arg("clear")
                .args(attrs(provider, field))
                .status()
                .map_err(|e| Error::Store(format!("secret-tool: {e}")))?;
        }
        Ok(existed)
    }
}

#[cfg(not(feature = "keychain"))]
mod native {
    use super::*;

    pub fn available() -> bool {
        false
    }
    fn off<T>() -> Result<T> {
        Err(Error::Store(
            "this build has no OS keychain support; use secrets.backend = \"file\"".into(),
        ))
    }
    pub fn get(_: &str, _: &str) -> Result<Option<String>> {
        off()
    }
    pub fn set(_: &str, _: &str, _: &str) -> Result<()> {
        off()
    }
    pub fn delete(_: &str, _: &str) -> Result<bool> {
        off()
    }
}

impl KeychainStore {
    /// Whether an OS keychain can be used from this process.
    pub fn available() -> bool {
        native::available()
    }
}

impl SecretStore for KeychainStore {
    fn name(&self) -> &'static str {
        "keychain"
    }
    fn describe(&self) -> String {
        let what = if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else if cfg!(target_os = "windows") {
            "Windows Credential Manager"
        } else {
            "Secret Service keyring"
        };
        format!("{what} (service {KEYCHAIN_SERVICE})")
    }
    fn get(&self, provider: &str, field: &str) -> Result<Option<String>> {
        native::get(provider, field)
    }
    fn set(&self, provider: &str, field: &str, value: &str) -> Result<()> {
        native::set(provider, field, value)
    }
    fn delete(&self, provider: &str, field: &str) -> Result<bool> {
        native::delete(provider, field)
    }
}

/// The store selected by `secrets.backend`. `auto` prefers the keychain when one is
/// available and falls back to the file store (headless nodes, containers).
pub fn open(config: &Config, registry: &Registry) -> Result<Box<dyn SecretStore>> {
    let home = &config.paths.home;
    match config.str("secrets.backend") {
        "file" => Ok(Box::new(FileStore::in_home(home))),
        "env" => Ok(Box::new(EnvStore::new(
            config.env().clone(),
            registry.clone(),
        ))),
        #[cfg(feature = "http")]
        "vault" => Ok(Box::new(super::remote::VaultStore::from_config(config)?)),
        #[cfg(feature = "http")]
        "aws" => Ok(Box::new(
            super::remote::AwsSecretsManagerStore::from_config(config)?,
        )),
        #[cfg(feature = "http")]
        backend @ ("azure" | "gcp") => super::remote::open_remote(config, backend),
        #[cfg(not(feature = "http"))]
        backend @ ("vault" | "aws" | "azure" | "gcp") => Err(Error::Store(format!(
            "secrets.backend = \"{backend}\" is not available in this build (it was compiled without the `http` feature)"
        ))),
        "keychain" => {
            if KeychainStore::available() {
                Ok(Box::new(KeychainStore))
            } else {
                Err(Error::Store(
                    "secrets.backend = \"keychain\" but no OS keychain is available in this session; use `frontier config set secrets.backend file` on headless machines".into(),
                ))
            }
        }
        _ => {
            if KeychainStore::available() {
                Ok(Box::new(KeychainStore))
            } else {
                Ok(Box::new(FileStore::in_home(home)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trip_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_home(&dir.path().join("home"));
        assert_eq!(store.get("huggingface", "token").unwrap(), None);
        store
            .set("huggingface", "token", "hf_secret_value")
            .unwrap();
        store.set("s3", "access_key_id", "AKIA").unwrap();
        store
            .set("s3", "secret_access_key", "s3cr3t-value")
            .unwrap();
        assert_eq!(
            store.get("huggingface", "token").unwrap().as_deref(),
            Some("hf_secret_value")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(store.delete("s3", "secret_access_key").unwrap());
        assert!(!store.delete("s3", "secret_access_key").unwrap());
        assert!(store.delete("s3", "access_key_id").unwrap());
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(!text.contains("[s3]"), "{text}");
        assert!(text.starts_with("# Frontier credentials"));
    }

    #[cfg(unix)]
    #[test]
    fn file_store_refuses_a_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::in_home(dir.path());
        store.set("runpod", "api_key", "rp_secret_value").unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = store.get("runpod", "api_key").unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
        assert!(!err.contains("rp_secret_value"));
    }

    #[test]
    fn env_store_reads_fallbacks_and_is_read_only() {
        let mut env = BTreeMap::new();
        env.insert(
            "HUGGING_FACE_HUB_TOKEN".to_string(),
            " hf_from_env ".to_string(),
        );
        env.insert("RUNPOD_API_KEY".to_string(), "".to_string());
        let store = EnvStore::new(env, Registry::builtin());
        assert_eq!(
            store.variable("huggingface", "token"),
            Some(("HUGGING_FACE_HUB_TOKEN", "hf_from_env"))
        );
        assert_eq!(store.get("runpod", "api_key").unwrap(), None);
        assert!(!store.writable());
        assert!(
            store
                .set("runpod", "api_key", "x")
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
    }
}
