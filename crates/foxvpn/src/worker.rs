//! Privilege boundary.
//!
//! The graphical process stays unprivileged. It reads secrets from the system
//! keyring and sends them, once, over a mode-0600 socket to a root worker.
//! The worker is the same `fox-cli` binary. Secrets are never placed in argv.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::config::Profile;
use crate::control::{ControlEvent, Decision, HostKeyChoice, PromptSlot, SessionControl};
use crate::error::{Error, Result};
use crate::platform;
use crate::secrets::SessionSecrets;
use crate::session::{self, SessionRequest};
use crate::ssh_link::DesktopGuard;

#[derive(Serialize, Deserialize)]
pub struct WorkerRequest {
    pub profile: Profile,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub socks_password: Option<String>,
    #[serde(default)]
    pub jump_password: Option<String>,
    #[serde(default)]
    pub jump_passphrase: Option<String>,
    pub accept_new_host_key: bool,
    pub known_hosts: PathBuf,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

impl WorkerRequest {
    pub fn into_session(self) -> SessionRequest {
        use zeroize::Zeroizing;
        SessionRequest {
            profile: self.profile,
            secrets: SessionSecrets {
                password: self.password.map(Zeroizing::new),
                passphrase: self.passphrase.map(Zeroizing::new),
                socks_password: self.socks_password.map(Zeroizing::new),
                jump_password: self.jump_password.map(Zeroizing::new),
                jump_passphrase: self.jump_passphrase.map(Zeroizing::new),
            },
            accept_new_host_key: self.accept_new_host_key,
            known_hosts: self.known_hosts,
            owner: Some((self.owner_uid, self.owner_gid)),
            guard: Arc::new(DesktopGuard),
            android_fd: None,
        }
    }
}

pub async fn elevate_and_run(request: WorkerRequest, control: SessionControl) -> Result<()> {
    if platform::is_elevated() {
        return session::run_session(request.into_session(), control).await;
    }
    #[cfg(unix)]
    {
        elevate_unix(request, control).await
    }
    #[cfg(not(unix))]
    {
        let _ = (request, control);
        Err(Error::fatal(
            "this process is not elevated",
            "On Windows, start Fox-VPN with Run as administrator so the tunnel adapter and routes can be created.",
        ))
    }
}

#[cfg(unix)]
async fn elevate_unix(request: WorkerRequest, control: SessionControl) -> Result<()> {
    let dir = std::env::temp_dir().join(format!("fox-vpn-{}", current_uid()));
    std::fs::create_dir_all(&dir).map_err(|e| Error::fatal(e.to_string(), "Could not create the elevation socket directory."))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = dir.join("worker.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| Error::fatal(format!("could not bind {}: {e}", path.display()), "Another Fox-VPN worker may still be starting."))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    let cli = cli_path();
    let mut child = if which("pkexec") {
        tokio::process::Command::new("pkexec")
            .arg(&cli)
            .arg("worker")
            .arg("--socket")
            .arg(&path)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::fatal(format!("could not start pkexec: {e}"), "Approve the privilege prompt, or run `sudo fox-cli connect --profile <name>`."))?
    } else {
        return Err(Error::fatal(
            "pkexec is not installed and this process is not root",
            "Run `sudo fox-cli connect --profile <name>` so routes can be installed.",
        ));
    };
    let accepted = tokio::time::timeout(Duration::from_secs(180), listener.accept()).await;
    let stream = match accepted {
        Ok(Ok((stream, _))) => stream,
        _ => {
            let _ = child.kill().await;
            return Err(Error::fatal(
                "the privilege prompt was dismissed or the worker did not start",
                "Fox-VPN did not change any routes.",
            ));
        }
    };
    check_peer(&stream)?;
    proxy(stream, request, control).await
}

#[cfg(unix)]
pub async fn run_worker(socket: &Path) -> Result<()> {
    if !platform::is_elevated() {
        return Err(crate::error::needs_elevation());
    }
    let stream = UnixStream::connect(socket).await.map_err(|e| Error::fatal(format!("could not connect to the controller: {e}"), "Start the connection from the application again."))?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let first = lines.next_line().await.map_err(|e| Error::fatal(e.to_string(), "The controller closed the elevation socket."))?.ok_or_else(|| {
        Error::fatal("the controller sent no request", "Start the connection again.")
    })?;
    let request: WorkerRequest = serde_json::from_str(&first).map_err(|e| Error::fatal(format!("bad worker request: {e}"), "The controller and worker versions do not match."))?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let prompt = PromptSlot::default();
    let cancel = Arc::new(AtomicBool::new(false));
    let control = SessionControl::new(tx, prompt.clone(), cancel.clone());
    let prompt_reader = prompt.clone();
    let cancel_reader = cancel.clone();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(decision) = serde_json::from_str::<Decision>(&line) else { continue };
            match decision {
                Decision::Disconnect => cancel_reader.store(true, Ordering::Relaxed),
                Decision::HostKey { .. } => {
                    if let Some(choice) = decision.choice() {
                        prompt_reader.resolve(choice);
                    }
                }
            }
        }
        cancel_reader.store(true, Ordering::Relaxed);
    });
    let session = session::run_session(request.into_session(), control);
    tokio::pin!(session);
    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else { break };
                let line = serde_json::to_string(&event).unwrap_or_else(|_| "{\"type\":\"log\",\"level\":\"error\",\"msg\":\"event encode failed\"}".into());
                if write.write_all(line.as_bytes()).await.is_err() || write.write_all(b"\n").await.is_err() {
                    break;
                }
                if matches!(event, ControlEvent::Exit { .. }) {
                    break;
                }
            }
            result = &mut session => {
                return result;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run_worker(socket: &Path) -> Result<()> {
    let _ = socket;
    Err(Error::fatal(
        "the elevation worker socket is only used on Linux",
        "On Windows, start Fox-VPN with Run as administrator.",
    ))
}

#[cfg(unix)]
async fn proxy(stream: UnixStream, request: WorkerRequest, control: SessionControl) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let encoded = serde_json::to_string(&request).map_err(|e| Error::fatal(e.to_string(), "Could not encode the worker request."))?;
    write.write_all(encoded.as_bytes()).await.map_err(|e| Error::fatal(e.to_string(), "The worker exited before reading the request."))?;
    write.write_all(b"\n").await.map_err(|e| Error::fatal(e.to_string(), "The worker exited before reading the request."))?;
    let mut lines = BufReader::new(read).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let line = line.map_err(|e| Error::retryable(e.to_string(), "The elevated worker disconnected."))?.ok_or_else(|| {
                    Error::retryable("the elevated worker closed the control socket", "If this repeats, run the CLI under sudo to see its stderr.")
                })?;
                let event: ControlEvent = serde_json::from_str(&line).map_err(|e| Error::retryable(format!("bad worker event: {e}"), "The worker sent a malformed status line."))?;
                if let ControlEvent::HostKeyPrompt { fingerprint, changed } = &event {
                    let rx = control.prompt.arm();
                    let _ = control.events.send(ControlEvent::HostKeyPrompt { fingerprint: fingerprint.clone(), changed: *changed });
                    let choice = rx.await.unwrap_or(HostKeyChoice::Reject);
                    let decision = match choice {
                        HostKeyChoice::TrustNew => Decision::HostKey { accept: true, replace: false },
                        HostKeyChoice::Replace => Decision::HostKey { accept: true, replace: true },
                        HostKeyChoice::Reject => Decision::HostKey { accept: false, replace: false },
                    };
                    let line = serde_json::to_string(&decision).unwrap_or_default();
                    let _ = write.write_all(line.as_bytes()).await;
                    let _ = write.write_all(b"\n").await;
                    continue;
                }
                let exit = matches!(event, ControlEvent::Exit { .. });
                let _ = control.events.send(event);
                if exit {
                    break;
                }
            }
            _ = wait_cancel(&control) => {
                let line = serde_json::to_string(&Decision::Disconnect).unwrap_or_default();
                let _ = write.write_all(line.as_bytes()).await;
                let _ = write.write_all(b"\n").await;
                break;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_cancel(control: &SessionControl) {
    loop {
        if control.cancelled() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[cfg(unix)]
fn check_peer(stream: &UnixStream) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(Error::fatal("could not verify the worker identity", "The elevation socket was closed."));
        }
        let me = current_uid();
        if cred.uid != 0 && cred.uid != me {
            return Err(Error::fatal(
                "the process on the elevation socket is neither root nor this user",
                "Refusing to send credentials.",
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
    }
    Ok(())
}

pub fn cli_path() -> PathBuf {
    let raw = std::env::current_exe()
        .ok()
        .and_then(|path| {
            let sibling = path.parent()?.join("fox-cli");
            if sibling.exists() { Some(sibling) } else { Some(path) }
        })
        .unwrap_or_else(|| PathBuf::from("fox-cli"));
    // AppImages are FUSE mounts. pkexec runs as root and cannot read that
    // mount, which surfaces as "Error accessing …/fox-cli: Permission denied".
    materialize_outside_appimage(&raw).unwrap_or(raw)
}

fn is_appimage_mount(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.contains("/.mount_")
        || std::env::var_os("APPDIR").is_some_and(|dir| path.starts_with(PathBuf::from(dir)))
}

fn materialize_outside_appimage(src: &Path) -> Option<PathBuf> {
    if !is_appimage_mount(src) || !src.is_file() {
        return None;
    }
    let dir = std::env::temp_dir().join(format!("fox-vpn-{}-bin", current_uid()));
    std::fs::create_dir_all(&dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    }
    let dest = dir.join(src.file_name()?);
    if copy_if_changed(src, &dest).is_err() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
    }
    Some(dest)
}

fn copy_if_changed(src: &Path, dest: &Path) -> std::io::Result<()> {
    let src_meta = std::fs::metadata(src)?;
    let same = std::fs::metadata(dest)
        .map(|meta| meta.len() == src_meta.len())
        .unwrap_or(false);
    if !same {
        let tmp = dest.with_extension("tmp");
        std::fs::copy(src, &tmp)?;
        std::fs::rename(&tmp, dest)?;
    }
    Ok(())
}

#[cfg(unix)]
fn which(name: &str) -> bool {
    for dir in ["/usr/bin", "/bin", "/usr/local/bin"] {
        if Path::new(dir).join(name).exists() {
            return true;
        }
    }
    false
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub fn peer_allowed(peer: u32, self_uid: u32) -> bool {
    peer == 0 || peer == self_uid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_socket_rejects_other_users() {
        assert!(peer_allowed(0, 1000));
        assert!(peer_allowed(1000, 1000));
        assert!(!peer_allowed(1001, 1000));
    }

    #[test]
    fn appimage_mount_is_copied_before_pkexec() {
        assert!(is_appimage_mount(Path::new("/tmp/.mount_Fox-VPaLjiPi/usr/bin/fox-cli")));
        assert!(!is_appimage_mount(Path::new("/usr/bin/fox-cli")));
        let dir = std::env::temp_dir().join(format!("fox-vpn-appimage-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join(".mount_test").join("fox-cli");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        std::fs::write(&src, b"#!/bin/sh\necho fox\n").unwrap();
        let copied = materialize_outside_appimage(&src).expect("copy out of the mount");
        assert!(copied.starts_with(std::env::temp_dir()));
        assert!(!is_appimage_mount(&copied));
        assert_eq!(std::fs::read(&copied).unwrap(), b"#!/bin/sh\necho fox\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
