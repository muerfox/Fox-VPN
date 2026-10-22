use std::fmt;

use zeroize::Zeroizing;

pub const SERVICE: &str = "dev.muerfox.fox-vpn";

#[derive(Clone)]
pub struct SessionSecrets {
    pub password: Option<Zeroizing<String>>,
    pub passphrase: Option<Zeroizing<String>>,
    pub socks_password: Option<Zeroizing<String>>,
    pub jump_password: Option<Zeroizing<String>>,
    pub jump_passphrase: Option<Zeroizing<String>>,
}

impl Default for SessionSecrets {
    fn default() -> Self {
        Self {
            password: None,
            passphrase: None,
            socks_password: None,
            jump_password: None,
            jump_passphrase: None,
        }
    }
}

impl fmt::Debug for SessionSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSecrets")
            .field("password", &self.password.as_ref().map(|_| "set"))
            .field("passphrase", &self.passphrase.as_ref().map(|_| "set"))
            .field("socks_password", &self.socks_password.as_ref().map(|_| "set"))
            .field("jump_password", &self.jump_password.as_ref().map(|_| "set"))
            .field("jump_passphrase", &self.jump_passphrase.as_ref().map(|_| "set"))
            .finish()
    }
}

pub trait SecretStore {
    fn get(&self, account: &str) -> std::result::Result<Option<String>, String>;
    fn set(&self, account: &str, secret: &str) -> std::result::Result<(), String>;
    fn delete(&self, account: &str) -> std::result::Result<(), String>;
}

#[derive(Default)]
pub struct MemoryStore {
    inner: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

impl SecretStore for MemoryStore {
    fn get(&self, account: &str) -> std::result::Result<Option<String>, String> {
        Ok(self.inner.lock().map_err(|e| e.to_string())?.get(account).cloned())
    }
    fn set(&self, account: &str, secret: &str) -> std::result::Result<(), String> {
        self.inner.lock().map_err(|e| e.to_string())?.insert(account.to_string(), secret.to_string());
        Ok(())
    }
    fn delete(&self, account: &str) -> std::result::Result<(), String> {
        self.inner.lock().map_err(|e| e.to_string())?.remove(account);
        Ok(())
    }
}

pub struct SystemStore;

impl SecretStore for SystemStore {
    fn get(&self, account: &str) -> std::result::Result<Option<String>, String> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(keyring_err)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(err) => {
                let text = err.to_string();
                if text.to_lowercase().contains("no entry") || text.to_lowercase().contains("not found") || text.contains("NoEntry") {
                    Ok(None)
                } else {
                    Err(keyring_err(err))
                }
            }
        }
    }

    fn set(&self, account: &str, secret: &str) -> std::result::Result<(), String> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(keyring_err)?;
        entry.set_password(secret).map_err(keyring_err)
    }

    fn delete(&self, account: &str) -> std::result::Result<(), String> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(keyring_err)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(err) => {
                let text = err.to_string().to_lowercase();
                if text.contains("no entry") || text.contains("not found") {
                    Ok(())
                } else {
                    Err(keyring_err(err))
                }
            }
        }
    }
}

fn keyring_err(err: impl std::fmt::Display) -> String {
    format!(
        "system credential store is unavailable ({err}). On Linux this is Secret Service; on Windows it is Credential Manager. The password was not written to disk."
    )
}

pub fn account(profile_id: &str, kind: &str) -> String {
    format!("profile/{profile_id}/{kind}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip_and_debug_redacts() {
        let store = MemoryStore::default();
        store.set("profile/a/password", "s3cret").unwrap();
        assert_eq!(store.get("profile/a/password").unwrap().as_deref(), Some("s3cret"));
        let secrets = SessionSecrets {
            password: Some(Zeroizing::new("s3cret".into())),
            ..SessionSecrets::default()
        };
        let rendered = format!("{secrets:?}");
        assert!(!rendered.contains("s3cret"));
        assert!(rendered.contains("set"));
    }
}
