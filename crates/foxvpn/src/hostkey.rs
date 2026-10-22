use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use russh::keys::{HashAlg, PublicKey};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyStatus {
    Trusted,
    Unknown,
    Changed { line: usize },
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub fn classify(host: &str, port: u16, key: &PublicKey, path: &Path) -> Result<HostKeyStatus> {
    match russh::keys::known_hosts::check_known_hosts_path(host, port, key, path) {
        Ok(true) => Ok(HostKeyStatus::Trusted),
        Ok(false) => Ok(HostKeyStatus::Unknown),
        Err(russh::keys::Error::KeyChanged { line }) => Ok(HostKeyStatus::Changed { line }),
        Err(err) => Err(Error::fatal(
            format!("could not read known hosts: {err}"),
            "Check the permissions of the Fox-VPN known_hosts file.",
        )),
    }
}

pub fn trust(host: &str, port: u16, key: &PublicKey, path: &Path, owner: Option<(u32, u32)>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::fatal(e.to_string(), "Could not create the config directory."))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    // A changed key must replace the old line. Appending would leave the
    // mismatch in place, and the next connection would still be rejected.
    remove_host(host, port, path)?;
    russh::keys::known_hosts::learn_known_hosts_path(host, port, key, path).map_err(|e| {
        Error::fatal(
            format!("could not store host key: {e}"),
            "Check that the config directory is writable.",
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        if let Some((uid, gid)) = owner {
            let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).map_err(|e| Error::fatal(e.to_string(), "Host key path is not valid."))?;
            unsafe {
                libc::chown(c.as_ptr(), uid, gid);
            }
        }
    }
    let _ = owner;
    Ok(())
}

fn remove_host(host: &str, port: u16, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let marker = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    let text = fs::read_to_string(path).map_err(|e| Error::fatal(e.to_string(), "Could not read known_hosts."))?;
    let mut kept = String::new();
    for line in text.lines() {
        let token = line.split_whitespace().next().unwrap_or("");
        if token == marker {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::fatal(e.to_string(), "Could not update known_hosts."))?;
    file.write_all(kept.as_bytes()).map_err(|e| Error::fatal(e.to_string(), "Could not update known_hosts."))?;
    Ok(())
}

/// Decide whether a presented key may be accepted.
/// A changed key is accepted only when `replace` is explicit.
pub fn decision(status: HostKeyStatus, accept_new: bool, replace: bool) -> bool {
    match status {
        HostKeyStatus::Trusted => true,
        HostKeyStatus::Unknown => accept_new,
        HostKeyStatus::Changed { .. } => replace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};

    fn key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn unknown_key_is_not_trusted_until_explicit_accept_and_change_requires_replace() {
        let dir = std::env::temp_dir().join(format!("fox-vpn-hk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        let first = key();
        let status = classify("example.test", 2222, first.public_key(), &path).unwrap();
        assert_eq!(status, HostKeyStatus::Unknown);
        assert!(!decision(status, false, false));
        assert!(decision(status, true, false));
        trust("example.test", 2222, first.public_key(), &path, None).unwrap();
        let again = classify("example.test", 2222, first.public_key(), &path).unwrap();
        assert_eq!(again, HostKeyStatus::Trusted);

        let second = key();
        let changed = classify("example.test", 2222, second.public_key(), &path).unwrap();
        assert!(matches!(changed, HostKeyStatus::Changed { .. }));
        assert!(!decision(changed, true, false));
        assert!(decision(changed, false, true));
        trust("example.test", 2222, second.public_key(), &path, None).unwrap();
        let replaced = classify("example.test", 2222, second.public_key(), &path).unwrap();
        assert_eq!(replaced, HostKeyStatus::Trusted);
        let _ = fs::remove_dir_all(&dir);
    }
}
