//! Platform integration for the virtual interface, routes, DNS, and kill switch.
//!
//! Linux policy routing keeps the SSH socket on the original gateway. The
//! commands are argument vectors, never a shell. A state file records the
//! exact undo steps so a crash can be repaired.

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{self, Profile};
use crate::error::{Error, Result};
use crate::routes::{self, DefaultRoute, RoutePlan};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Persisted {
    restore: Vec<Vec<String>>,
    resolv_backup: Option<String>,
    resolvectl_iface: Option<String>,
    pid: u32,
    started_unix: u64,
}

pub struct NetGuard {
    restore: Vec<Vec<String>>,
    resolv_backup: Option<Vec<u8>>,
    resolvectl_iface: Option<String>,
    restored: bool,
}

impl NetGuard {
    pub fn restore_now(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        if let Some(iface) = self.resolvectl_iface.take() {
            let _ = run(&[routes::tool("resolvectl"), "revert".into(), iface]);
        }
        if let Some(bytes) = self.resolv_backup.take() {
            let _ = fs::write("/etc/resolv.conf", bytes);
        }
        for cmd in &self.restore {
            let _ = run(cmd);
        }
        let _ = fs::remove_file(config::state_path());
    }
}

impl Drop for NetGuard {
    fn drop(&mut self) {
        self.restore_now();
    }
}

pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        windows_is_elevated()
    }
}

pub fn current_owner() -> Option<(u32, u32)> {
    #[cfg(unix)]
    {
        Some(unsafe { (libc::getuid(), libc::getgid()) })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

pub fn open_tun(mtu: u16) -> Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.tun_name(crate::TUN_NAME).address(crate::TUN_ADDR).netmask("255.255.255.0").mtu(mtu).up();
    #[cfg(target_os = "linux")]
    config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });
    #[cfg(target_os = "windows")]
    {
        let wintun = bundled_wintun_path();
        config.platform_config(|platform| {
            platform.device_guid(0x6670_6670_6670_6670_6670_6670_6670_6670);
            platform.wintun_file(wintun.clone());
        });
    }
    tun::create_as_async(&config).map_err(|err| {
        let text = err.to_string();
        if text.to_lowercase().contains("permission") || text.to_lowercase().contains("root") || text.to_lowercase().contains("access") {
            crate::error::needs_elevation()
        } else {
            Error::fatal(
                format!("could not create the tunnel device: {text}"),
                "Linux needs /dev/net/tun and administrator privileges. Windows writes wintun.dll beside the executable and still needs an elevated process.",
            )
        }
    })
}

/// Windows loads Wintun from a file. The official DLL is embedded in the executable
/// and written beside it on first use, so the program can still be distributed as one file.
#[cfg(target_os = "windows")]
fn bundled_wintun_path() -> PathBuf {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let dest = dir.join("wintun.dll");
    let bytes: &[u8] = include_bytes!("../../../third_party/wintun/amd64/wintun.dll");
    let replace = std::fs::metadata(&dest).map(|meta| meta.len() != bytes.len() as u64).unwrap_or(true);
    if replace {
        let _ = std::fs::write(&dest, bytes);
    }
    dest
}

#[cfg(target_os = "android")]
pub fn open_tun_fd(fd: std::os::unix::io::RawFd, mtu: u16) -> Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.raw_fd(fd).mtu(mtu).close_fd_on_drop(true);
    tun::create_as_async(&config).map_err(|err| {
        Error::fatal(
            format!("could not adopt the Android VPN interface: {err}"),
            "The VPN permission must be granted and the service must still be running.",
        )
    })
}

pub fn read_default_route() -> Result<DefaultRoute> {
    let output = Command::new(routes::tool("ip"))
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| Error::fatal(format!("could not run ip: {e}"), "Install iproute2."))?;
    let text = String::from_utf8_lossy(&output.stdout);
    routes::parse_default_route(&text).ok_or_else(|| {
        Error::fatal(
            "no IPv4 default route was found",
            "Connect to a network before starting the tunnel. Fox-VPN will not replace a routing table it cannot restore.",
        )
    })
}

pub fn apply(profile: &Profile, plan: &RoutePlan, dns: &[Ipv4Addr]) -> Result<NetGuard> {
    let mtu_cmds = match () {
        #[cfg(target_os = "linux")]
        () => {
            let (apply, restore) = routes::linux_commands(plan, crate::TUN_NAME, crate::ROUTE_TABLE, crate::SSH_MARK);
            (apply, restore)
        }
        #[cfg(target_os = "windows")]
        () => routes::windows_route_commands(plan, crate::TUN_PEER),
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        () => (Vec::<Vec<String>>::new(), Vec::<Vec<String>>::new()),
    };
    let (apply_cmds, restore) = mtu_cmds;
    let mut guard = NetGuard {
        restore,
        resolv_backup: None,
        resolvectl_iface: None,
        restored: false,
    };
    for cmd in &apply_cmds {
        if let Err(err) = run(cmd) {
            guard.restore_now();
            return Err(Error::fatal(
                format!("network setup failed: {err}"),
                "Routes were rolled back. On Linux, nftables is required only when the kill switch is enabled.",
            ));
        }
    }
    if profile.tunnel_dns {
        if let Err(err) = configure_dns(&mut guard, dns) {
            guard.restore_now();
            return Err(err);
        }
    }
    persist(&guard)?;
    Ok(guard)
}

fn configure_dns(guard: &mut NetGuard, dns: &[Ipv4Addr]) -> Result<()> {
    if dns.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let resolv = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        if resolv.contains("127.0.0.53") && std::path::Path::new("/usr/bin/resolvectl").exists() {
            let mut cmd = vec![routes::tool("resolvectl"), "dns".into(), crate::TUN_NAME.into()];
            cmd.extend(dns.iter().map(|ip| ip.to_string()));
            run(&cmd).map_err(|e| Error::fatal(e, "Could not point DNS at the tunnel interface."))?;
            run(&[routes::tool("resolvectl"), "domain".into(), crate::TUN_NAME.into(), "~.".into()])
                .map_err(|e| Error::fatal(e, "Could not route DNS lookups through the tunnel."))?;
            guard.resolvectl_iface = Some(crate::TUN_NAME.into());
            return Ok(());
        }
        let backup = fs::read("/etc/resolv.conf").map_err(|e| Error::fatal(format!("could not read resolv.conf: {e}"), "DNS was not changed."))?;
        let mut body = String::from("# fox-vpn temporary resolver configuration\n");
        for ip in dns {
            body.push_str(&format!("nameserver {ip}\n"));
        }
        fs::write("/etc/resolv.conf", body).map_err(|e| Error::fatal(format!("could not write resolv.conf: {e}"), "DNS was not changed."))?;
        guard.resolv_backup = Some(backup);
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let servers = dns.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(" ");
        run(&["netsh".into(), "interface".into(), "ip".into(), "set".into(), "dns".into(), crate::TUN_NAME.into(), "static".into(), dns[0].to_string()])
            .map_err(|e| Error::fatal(e, "Could not set DNS on the tunnel adapter."))?;
        let _ = servers;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (guard, dns);
        Ok(())
    }
}

fn persist(guard: &NetGuard) -> Result<()> {
    let path = config::state_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let persisted = Persisted {
        restore: guard.restore.clone(),
        resolv_backup: guard.resolv_backup.as_ref().map(|b| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)),
        resolvectl_iface: guard.resolvectl_iface.clone(),
        pid: std::process::id(),
        started_unix: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    };
    let json = serde_json::to_string_pretty(&persisted).map_err(|e| Error::fatal(e.to_string(), "Could not record rollback state."))?;
    fs::write(&path, json).map_err(|e| Error::fatal(format!("could not write {}: {e}", path.display()), "Rollback state was not saved. Avoid force-killing the process."))?;
    Ok(())
}

pub fn repair() -> Result<()> {
    let path = config::state_path();
    if !path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&path).map_err(|e| Error::fatal(e.to_string(), "Could not read the rollback file."))?;
    let persisted: Persisted = serde_json::from_str(&text).map_err(|e| Error::fatal(e.to_string(), "The rollback file is corrupt. Remove it only after restoring routes manually."))?;
    if let Some(iface) = persisted.resolvectl_iface {
        let _ = run(&[routes::tool("resolvectl"), "revert".into(), iface]);
    }
    if let Some(encoded) = persisted.resolv_backup {
        if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded) {
            let _ = fs::write("/etc/resolv.conf", bytes);
        }
    }
    for cmd in &persisted.restore {
        let _ = run(cmd);
    }
    let _ = fs::remove_file(path);
    Ok(())
}

pub fn run(args: &[String]) -> std::result::Result<(), String> {
    if args.is_empty() {
        return Err("empty command".into());
    }
    let mut command = Command::new(&args[0]);
    if args.len() >= 3 && args[0].ends_with("nft") && args[1] == "-f" && args[2] == "-" {
        let script = args.get(3).map(String::as_str).unwrap_or("");
        let mut child = command
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
        }
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if output.status.success() {
            return Ok(());
        }
        return Err(format!("nft failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let output = command.args(&args[1..]).output().map_err(|e| format!("{}: {e}", args[0]))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim()))
    }
}

pub fn state_exists() -> bool {
    config::state_path().exists()
}

pub fn state_path() -> PathBuf {
    config::state_path()
}

#[cfg(windows)]
fn windows_is_elevated() -> bool {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = windows_sys::Win32::Foundation::CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}
