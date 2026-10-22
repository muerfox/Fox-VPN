use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEFAULT_PORT: u16 = 2222;
pub const DEFAULT_USER: &str = "root";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    PrivateKey,
    Password,
    PrivateKeyPassphrase,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::PrivateKey
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    FullTunnel,
    SplitTunnel,
}

impl Default for RoutingMode {
    fn default() -> Self {
        Self::FullTunnel
    }
}

/// How captured packets are forwarded.
///
/// `ssh_direct` uses SSH `direct-tcpip` and DNS-over-TCP. It works with a
/// normal OpenSSH server and covers TCP plus DNS. It does not forward ICMP or
/// arbitrary UDP.
///
/// `helper_l4` and `helper_l3` require the Fox helper on the server. They are
/// never selected implicitly when the helper is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    SshDirect,
    HelperL4,
    HelperL3,
}

impl Default for TransportMode {
    fn default() -> Self {
        Self::SshDirect
    }
}

impl TransportMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::SshDirect => "SSH direct-tcpip (TCP and DNS)",
            Self::HelperL4 => "Remote helper (TCP and UDP)",
            Self::HelperL3 => "Remote helper (full IP packets)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpHost {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default = "default_user")]
    pub username: String,
    #[serde(default)]
    pub authentication: AuthMethod,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

fn default_ssh_port() -> u16 {
    22
}
fn default_user() -> String {
    DEFAULT_USER.to_string()
}
fn default_port() -> u16 {
    DEFAULT_PORT
}
fn default_timeout() -> u64 {
    20
}
fn default_keepalive() -> u64 {
    15
}
fn default_mtu() -> u16 {
    1500
}
fn default_true() -> bool {
    true
}
fn default_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksProxy {
    pub host: String,
    #[serde(default = "default_socks_port")]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
}

fn default_socks_port() -> u16 {
    1080
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default = "new_id")]
    pub id: String,
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_user")]
    pub username: String,
    #[serde(default)]
    pub authentication: AuthMethod,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub routing_mode: RoutingMode,
    #[serde(default)]
    pub split_routes: Vec<String>,
    #[serde(default)]
    pub auto_networks: bool,
    #[serde(default = "default_true")]
    pub tunnel_dns: bool,
    #[serde(default = "default_dns")]
    pub dns_servers: Vec<String>,
    #[serde(default = "default_true")]
    pub ipv4: bool,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default = "default_true")]
    pub reconnect: bool,
    #[serde(default)]
    pub verbose_logging: bool,
    #[serde(default = "default_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub exclude_lan: bool,
    #[serde(default)]
    pub transport: TransportMode,
    /// Fixed remote command that starts an already installed helper.
    /// When empty, helper transports upload no binary; they run the embedded
    /// Python helper through the SSH exec channel.
    #[serde(default)]
    pub remote_command: Option<String>,
    #[serde(default)]
    pub jump: Option<JumpHost>,
    #[serde(default)]
    pub socks: Option<SocksProxy>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("os random");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Profile {
    pub fn blank() -> Self {
        Self {
            id: new_id(),
            name: "My SSH VPN".into(),
            host: String::new(),
            port: DEFAULT_PORT,
            username: DEFAULT_USER.into(),
            authentication: AuthMethod::PrivateKey,
            key_path: None,
            routing_mode: RoutingMode::FullTunnel,
            split_routes: Vec::new(),
            auto_networks: false,
            tunnel_dns: true,
            dns_servers: default_dns(),
            ipv4: true,
            ipv6: false,
            reconnect: true,
            verbose_logging: true,
            connect_timeout_secs: default_timeout(),
            keepalive_secs: default_keepalive(),
            kill_switch: false,
            exclude_lan: false,
            transport: TransportMode::SshDirect,
            remote_command: None,
            jump: None,
            socks: None,
            mtu: default_mtu(),
        }
    }

    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub active_profile: Option<String>,
    #[serde(default)]
    pub connect_on_startup: bool,
    #[serde(default)]
    pub start_minimized: bool,
    /// 0 = warnings, 1 = connection events, 2 = flows, 3 = trace.
    #[serde(default = "default_verbosity")]
    pub log_verbosity: u8,
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

fn default_verbosity() -> u8 {
    2
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            active_profile: None,
            connect_on_startup: false,
            start_minimized: false,
            log_verbosity: 2,
            profiles: Vec::new(),
        }
    }
}

impl AppConfig {
    pub fn active(&self) -> Option<&Profile> {
        let id = self.active_profile.as_deref()?;
        self.profiles.iter().find(|p| p.id == id || p.name == id)
    }

    pub fn active_mut(&mut self) -> Option<&mut Profile> {
        let id = self.active_profile.clone()?;
        self.profiles.iter_mut().find(|p| p.id == id || p.name == id)
    }
}

const FORBIDDEN_SECRET_KEYS: &[&str] = &[
    "password",
    "passphrase",
    "private_key",
    "key_data",
    "socks_password",
];

pub fn config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("fox-vpn")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.yaml")
}

pub fn known_hosts_path() -> PathBuf {
    config_dir().join("known_hosts")
}

pub fn state_path() -> PathBuf {
    PathBuf::from("/run/fox-vpn/state.json")
}

pub fn load_config(path: &Path) -> Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let text = fs::read_to_string(path).map_err(|e| {
        Error::fatal(
            format!("could not read {}: {e}", path.display()),
            "Check that the config file is readable.",
        )
    })?;
    parse_config_yaml(&text).map_err(|e| {
        Error::fatal(
            format!("invalid config: {e}"),
            "Fix the YAML. Passwords and passphrases are not accepted in the file.",
        )
    })
}

pub fn parse_config_yaml(text: &str) -> std::result::Result<AppConfig, String> {
    let value: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    reject_secrets(&value, "")?;
    if let Some(profile) = value.get("profile") {
        let mut profile: Profile = serde_yaml::from_value(profile.clone()).map_err(|e| e.to_string())?;
        if profile.name.is_empty() {
            profile.name = "Imported".into();
        }
        return Ok(AppConfig {
            active_profile: Some(profile.id.clone()),
            profiles: vec![profile],
            ..AppConfig::default()
        });
    }
    serde_yaml::from_value(value).map_err(|e| e.to_string())
}

fn reject_secrets(value: &serde_yaml::Value, path: &str) -> std::result::Result<(), String> {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, child) in map {
                let key = key.as_str().unwrap_or("");
                if FORBIDDEN_SECRET_KEYS.contains(&key) {
                    return Err(format!(
                        "refusing `{path}{key}`: store secrets in the system keyring, not in the config file"
                    ));
                }
                reject_secrets(child, &format!("{path}{key}."))?;
            }
            Ok(())
        }
        serde_yaml::Value::Sequence(items) => {
            for child in items {
                reject_secrets(child, path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn save_config(path: &Path, config: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::fatal(format!("could not create {}: {e}", parent.display()), "Check directory permissions.")
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let yaml = serde_yaml::to_string(config).map_err(|e| Error::fatal(e.to_string(), "Config could not be serialized."))?;
    fs::write(path, yaml).map_err(|e| Error::fatal(format!("could not write {}: {e}", path.display()), "Check directory permissions."))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn validate_profile(profile: &Profile) -> std::result::Result<(), String> {
    if profile.name.trim().is_empty() || profile.name.chars().count() > 80 {
        return Err("profile name must be 1 to 80 characters".into());
    }
    validate_host(&profile.host)?;
    if profile.port == 0 {
        return Err("SSH port must be between 1 and 65535".into());
    }
    validate_user(&profile.username)?;
    if !(1..=120).contains(&profile.connect_timeout_secs) {
        return Err("connection timeout must be 1 to 120 seconds".into());
    }
    if profile.keepalive_secs > 300 {
        return Err("keepalive must be 0 to 300 seconds".into());
    }
    if !(576..=1500).contains(&profile.mtu) && profile.mtu != 0 {
        return Err("MTU must be between 576 and 1500".into());
    }
    if !profile.ipv4 && !profile.ipv6 {
        return Err("enable IPv4, IPv6, or both".into());
    }
    match profile.authentication {
        AuthMethod::PrivateKey | AuthMethod::PrivateKeyPassphrase => {
            let path = profile.key_path.as_ref().ok_or("choose a private key file")?;
            if !path.is_file() {
                return Err(format!("private key file does not exist: {}", path.display()));
            }
        }
        AuthMethod::Password => {}
    }
    for dns in &profile.dns_servers {
        if dns.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("DNS server `{dns}` is not an IP address"));
        }
    }
    if profile.routing_mode == RoutingMode::SplitTunnel && profile.split_routes.is_empty() && !profile.auto_networks {
        return Err("split tunnel needs at least one route, or automatic network discovery".into());
    }
    for route in &profile.split_routes {
        if route.parse::<ipnet::IpNet>().is_err() {
            return Err(format!("route `{route}` is not a CIDR prefix"));
        }
    }
    if let Some(jump) = &profile.jump {
        validate_host(&jump.host)?;
        validate_user(&jump.username)?;
        if jump.port == 0 {
            return Err("jump host port is invalid".into());
        }
    }
    if let Some(socks) = &profile.socks {
        validate_host(&socks.host)?;
        if socks.port == 0 {
            return Err("SOCKS port is invalid".into());
        }
    }
    if let Some(cmd) = &profile.remote_command {
        if cmd.chars().any(|c| c.is_control()) {
            return Err("remote helper command contains control characters".into());
        }
    }
    Ok(())
}

pub fn validate_host(host: &str) -> std::result::Result<(), String> {
    if host.is_empty() || host.len() > 253 || host.contains([' ', '/', '\\', '\n', '\r']) {
        return Err("SSH host must be a hostname or IP address".into());
    }
    Ok(())
}

fn validate_user(user: &str) -> std::result::Result<(), String> {
    if user.is_empty() || user.len() > 64 || !user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '%')) {
        return Err("SSH username contains unsupported characters".into());
    }
    Ok(())
}

pub fn parse_dns_v4(profile: &Profile) -> std::result::Result<Vec<Ipv4Addr>, String> {
    let mut out = Vec::new();
    for dns in &profile.dns_servers {
        match dns.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => out.push(v4),
            Ok(_) => {}
            Err(_) => return Err(format!("bad DNS server {dns}")),
        }
    }
    if out.is_empty() && profile.tunnel_dns && profile.ipv4 {
        return Err("tunnel DNS needs at least one IPv4 resolver".into());
    }
    Ok(out)
}

pub fn effective_mtu(profile: &Profile) -> u16 {
    let requested = if profile.mtu < 1280 { 1280 } else { profile.mtu };
    match profile.transport {
        TransportMode::HelperL3 => requested.min(1280),
        _ => requested,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
profile:
  name: My SSH VPN
  host: 78.39.47.49
  port: 2222
  username: root
  authentication: private_key
  routing_mode: full_tunnel
  auto_networks: true
  tunnel_dns: true
  ipv4: true
  ipv6: false
  reconnect: true
  verbose_logging: true
"#;

    #[test]
    fn parses_requested_example_without_secrets() {
        let cfg = parse_config_yaml(EXAMPLE).unwrap();
        let profile = &cfg.profiles[0];
        assert_eq!(profile.host, "78.39.47.49");
        assert_eq!(profile.port, 2222);
        assert_eq!(profile.username, "root");
        assert_eq!(profile.authentication, AuthMethod::PrivateKey);
        assert_eq!(profile.routing_mode, RoutingMode::FullTunnel);
        assert!(profile.auto_networks);
        assert!(profile.tunnel_dns);
        assert!(profile.ipv4);
        assert!(!profile.ipv6);
        assert!(profile.reconnect);
        assert!(profile.verbose_logging);
        assert_eq!(profile.transport, TransportMode::SshDirect);
    }

    #[test]
    fn rejects_plaintext_password() {
        let yaml = "profiles:\n  - name: x\n    host: 10.0.0.1\n    password: hunter2\n";
        let err = parse_config_yaml(yaml).unwrap_err();
        assert!(err.contains("keyring"), "{err}");
    }

    #[test]
    fn validates_port_host_and_routes() {
        let mut profile = Profile::blank();
        profile.host = "bad host".into();
        assert!(validate_profile(&profile).is_err());
        profile.host = "10.0.0.8".into();
        profile.port = 2222;
        profile.authentication = AuthMethod::Password;
        profile.key_path = None;
        assert!(validate_profile(&profile).is_ok());
        profile.routing_mode = RoutingMode::SplitTunnel;
        profile.split_routes = vec!["not-a-cidr".into()];
        assert!(validate_profile(&profile).is_err());
    }
}
