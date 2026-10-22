//! SSH session used as the tunnel transport.
//!
//! The socket is created before connect so it can be marked (Linux) or excluded
//! from a VPN interface (Android). Host-key verification never defaults to accept.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handler};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, load_secret_key};
use russh::{ChannelMsg, Disconnect};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::config::{AuthMethod, JumpHost, Profile, SocksProxy};
use crate::control::{HostKeyChoice, SessionControl};
use crate::error::{self, Error, Result};
use crate::hostkey::{self, HostKeyStatus};
use crate::secrets::SessionSecrets;

pub type SshChannel = russh::Channel<client::Msg>;

pub trait SocketGuard: Send + Sync {
    /// Called with the raw socket before `connect`. Return false to abort.
    /// Desktop returns true. Android uses this to call `VpnService.protect`.
    fn prepare(&self, raw_fd: i32) -> bool;
}

pub struct DesktopGuard;

impl SocketGuard for DesktopGuard {
    fn prepare(&self, _raw_fd: i32) -> bool {
        true
    }
}

enum Req {
    Direct {
        host: String,
        port: u32,
        origin_host: String,
        origin_port: u32,
        reply: oneshot::Sender<std::result::Result<SshChannel, String>>,
    },
    Exec {
        command: String,
        reply: oneshot::Sender<std::result::Result<SshChannel, String>>,
    },
    Disconnect,
}

pub struct SshLink {
    tx: mpsc::UnboundedSender<Req>,
}

impl Clone for SshLink {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone() }
    }
}

impl SshLink {
    pub async fn open_direct(&self, host: &str, port: u16, origin_host: &str, origin_port: u16) -> Result<SshChannel> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Direct {
                host: host.to_string(),
                port: u32::from(port),
                origin_host: origin_host.to_string(),
                origin_port: u32::from(origin_port),
                reply,
            })
            .map_err(|_| dead())?;
        rx.await.map_err(|_| dead())?.map_err(|e| {
            Error::retryable(
                format!("SSH server refused a forwarded connection to {host}:{port}: {e}"),
                "The remote SSH server may disable TCP forwarding, or the destination refused the connection.",
            )
        })
    }

    pub async fn open_exec(&self, command: &str) -> Result<SshChannel> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Exec {
                command: command.to_string(),
                reply,
            })
            .map_err(|_| dead())?;
        rx.await.map_err(|_| dead())?.map_err(|e| {
            Error::retryable(
                format!("could not run the remote helper command: {e}"),
                "Confirm that the server allows exec channels. The command is fixed by Fox-VPN; server-supplied commands are never executed.",
            )
        })
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(Req::Disconnect);
    }
}

fn dead() -> Error {
    Error::retryable(
        "SSH connection closed",
        "The server disconnected or the network path failed. Reconnect will be attempted when it is enabled.",
    )
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    accept_new: bool,
    owner: Option<(u32, u32)>,
    control: SessionControl,
    rejection: Arc<std::sync::Mutex<Option<Error>>>,
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKeyOrCertificate) -> std::result::Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        let fp = hostkey::fingerprint(&key);
        let status = match hostkey::classify(&self.host, self.port, &key, &self.known_hosts) {
            Ok(status) => status,
            Err(err) => {
                *self.rejection.lock().unwrap() = Some(err);
                return Ok(false);
            }
        };
        let allowed = match status {
            HostKeyStatus::Trusted => true,
            HostKeyStatus::Unknown => {
                let accept = if self.accept_new {
                    true
                } else {
                    self.control.ask_host_key(fp.clone(), false).await == HostKeyChoice::TrustNew
                };
                if accept {
                    hostkey::trust(&self.host, self.port, &key, &self.known_hosts, self.owner).is_ok()
                } else {
                    *self.rejection.lock().unwrap() = Some(error::host_key_rejected(&fp, false));
                    false
                }
            }
            HostKeyStatus::Changed { .. } => {
                let choice = self.control.ask_host_key(fp.clone(), true).await;
                if choice == HostKeyChoice::Replace {
                    hostkey::trust(&self.host, self.port, &key, &self.known_hosts, self.owner).is_ok()
                } else {
                    *self.rejection.lock().unwrap() = Some(error::host_key_rejected(&fp, true));
                    false
                }
            }
        };
        if allowed {
            self.control.log("info", format!("SSH host key accepted for {}:{} ({fp})", self.host, self.port));
        }
        Ok(allowed)
    }
}

pub struct ConnectParams<'a> {
    pub profile: &'a Profile,
    pub secrets: &'a SessionSecrets,
    pub server: SocketAddr,
    pub known_hosts: &'a Path,
    pub accept_new_host_key: bool,
    pub owner: Option<(u32, u32)>,
    pub guard: &'a dyn SocketGuard,
    pub control: &'a SessionControl,
}

pub async fn connect(params: ConnectParams<'_>) -> Result<SshLink> {
    let timeout = Duration::from_secs(params.profile.connect_timeout_secs.max(1));
    let rejection = Arc::new(std::sync::Mutex::new(None));
    let target_handler = ClientHandler {
        host: params.profile.host.clone(),
        port: params.profile.port,
        known_hosts: params.known_hosts.to_path_buf(),
        accept_new: params.accept_new_host_key,
        owner: params.owner,
        control: params.control.clone(),
        rejection: rejection.clone(),
    };

    let (handle, extra) = if let Some(jump) = &params.profile.jump {
        let (handle, jump_handle) = connect_via_jump(params.control, params.guard, jump, params.secrets, params.known_hosts, params.owner, params.accept_new_host_key, params.server, timeout, target_handler, params.profile).await?;
        (handle, Some(jump_handle))
    } else if let Some(socks) = &params.profile.socks {
        let mut stream = dial(params.guard, socks_addr(socks).await?, timeout).await?;
        socks5_handshake(&mut stream, &params.server, socks, params.secrets).await?;
        (handshake(params.profile, stream, target_handler, timeout).await?, None)
    } else {
        let stream = dial(params.guard, params.server, timeout).await?;
        (handshake(params.profile, stream, target_handler, timeout).await?, None)
    };

    let handle = match tokio::time::timeout(timeout, authenticate(handle, params.profile, params.secrets)).await {
        Ok(result) => result?,
        Err(_) => return Err(error::timed_out()),
    };
    if let Some(err) = rejection.lock().unwrap().take() {
        return Err(err);
    }
    params.control.log(
        "info",
        format!("authenticated to {} as {}", params.profile.endpoint(), params.profile.username),
    );
    Ok(spawn_link(handle, extra))
}

fn spawn_link(handle: client::Handle<ClientHandler>, extra: Option<client::Handle<ClientHandler>>) -> SshLink {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let _extra = extra;
        let handle = handle;
        while let Some(req) = rx.recv().await {
            match req {
                Req::Disconnect => {
                    let _ = handle.disconnect(Disconnect::ByApplication, "fox-vpn disconnect", "en").await;
                    break;
                }
                Req::Direct { host, port, origin_host, origin_port, reply } => {
                    let result = handle
                        .channel_open_direct_tcpip(host, port, origin_host, origin_port)
                        .await
                        .map_err(|e| e.to_string());
                    let _ = reply.send(result);
                }
                Req::Exec { command, reply } => {
                    let result = async {
                        let mut channel = handle.channel_open_session().await.map_err(|e| e.to_string())?;
                        channel.exec(true, command).await.map_err(|e| e.to_string())?;
                        Ok(channel)
                    }
                    .await;
                    let _ = reply.send(result);
                }
            }
            if handle.is_closed() {
                break;
            }
        }
    });
    SshLink { tx }
}

async fn handshake<S>(
    profile: &Profile,
    stream: S,
    handler: ClientHandler,
    timeout: Duration,
) -> Result<client::Handle<ClientHandler>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(client::Config {
        nodelay: true,
        keepalive_interval: if profile.keepalive_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(profile.keepalive_secs))
        },
        keepalive_max: 3,
        inactivity_timeout: None,
        ..client::Config::default()
    });
    let rejection = handler.rejection.clone();
    let connect = client::connect_stream(config, stream, handler);
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(handle)) => Ok(handle),
        Ok(Err(err)) => {
            if let Some(rejected) = rejection.lock().unwrap().take() {
                Err(rejected)
            } else {
                Err(map_ssh(&err))
            }
        }
        Err(_) => Err(error::timed_out()),
    }
}

async fn authenticate(
    mut handle: client::Handle<ClientHandler>,
    profile: &Profile,
    secrets: &SessionSecrets,
) -> Result<client::Handle<ClientHandler>> {
    let username = profile.username.clone();
    let result = match profile.authentication {
        AuthMethod::Password => {
            let password = secrets.password.as_ref().ok_or_else(|| {
                error::auth_failed("no password is available in the system keyring or the connect dialog")
            })?;
            handle
                .authenticate_password(username, password.as_str())
                .await
                .map_err(|e| error::auth_failed(e.to_string()))?
        }
        AuthMethod::PrivateKey | AuthMethod::PrivateKeyPassphrase => {
            let path = profile.key_path.as_ref().ok_or_else(|| error::auth_failed("no private key path is configured"))?;
            let passphrase = secrets.passphrase.as_ref().map(|s| s.as_str());
            let key = load_secret_key(path, passphrase).map_err(|e| match e {
                russh::keys::Error::KeyIsEncrypted => {
                    error::auth_failed("the private key is encrypted and no passphrase was provided")
                }
                other => error::auth_failed(other.to_string()),
            })?;
            let hash = handle.best_supported_rsa_hash().await.map_err(|e| error::auth_failed(e.to_string()))?.flatten();
            handle
                .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(|e| error::auth_failed(e.to_string()))?
        }
    };
    if result.success() {
        Ok(handle)
    } else {
        Err(error::auth_failed("the server rejected the credentials"))
    }
}

async fn connect_via_jump(
    control: &SessionControl,
    guard: &dyn SocketGuard,
    jump: &JumpHost,
    secrets: &SessionSecrets,
    known_hosts: &Path,
    owner: Option<(u32, u32)>,
    accept_new: bool,
    target: SocketAddr,
    timeout: Duration,
    target_handler: ClientHandler,
    profile: &Profile,
) -> Result<(client::Handle<ClientHandler>, client::Handle<ClientHandler>)> {
    let jump_addr = resolve_one(&jump.host, jump.port).await?;
    let stream = dial(guard, jump_addr, timeout).await?;
    let jump_profile = Profile {
        host: jump.host.clone(),
        port: jump.port,
        username: jump.username.clone(),
        authentication: jump.authentication,
        key_path: jump.key_path.clone(),
        ..profile.clone()
    };
    let jump_secrets = SessionSecrets {
        password: secrets.jump_password.clone(),
        passphrase: secrets.jump_passphrase.clone(),
        ..SessionSecrets::default()
    };
    let rejection = Arc::new(std::sync::Mutex::new(None));
    let handler = ClientHandler {
        host: jump.host.clone(),
        port: jump.port,
        known_hosts: known_hosts.to_path_buf(),
        accept_new,
        owner,
        control: control.clone(),
        rejection: rejection.clone(),
    };
    let handle = handshake(&jump_profile, stream, handler, timeout).await?;
    let mut handle = authenticate(handle, &jump_profile, &jump_secrets).await?;
    if let Some(err) = rejection.lock().unwrap().take() {
        return Err(err);
    }
    control.log("info", format!("connected through jump host {}:{}", jump.host, jump.port));
    let channel = handle
        .channel_open_direct_tcpip(target.ip().to_string(), u32::from(target.port()), "127.0.0.1".to_string(), 0)
        .await
        .map_err(|e| {
            Error::retryable(
                format!("jump host could not reach {}: {e}", target),
                "Check that the jump host can open a TCP connection to the VPN server.",
            )
        })?;
    let target_handle = handshake(profile, channel.into_stream(), target_handler, timeout).await?;
    Ok((target_handle, handle))
}

pub async fn resolve_one(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = resolve_all(host, port).await?;
    Ok(addrs.remove(0))
}

pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host, port))).await {
        Ok(Ok(iter)) => {
            let addrs: Vec<_> = iter.collect();
            if addrs.is_empty() {
                Err(error::unreachable(format!("no addresses for {host}")))
            } else {
                Ok(addrs)
            }
        }
        Ok(Err(err)) => Err(error::unreachable(err.to_string())),
        Err(_) => Err(error::timed_out()),
    }
}

pub fn ipv4_of(addrs: &[SocketAddr]) -> Vec<std::net::Ipv4Addr> {
    addrs.iter().filter_map(|a| match a.ip() { std::net::IpAddr::V4(v4) => Some(v4), _ => None }).collect()
}

async fn dial(guard: &dyn SocketGuard, addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).map_err(map_io)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if !guard.prepare(sock.as_raw_fd()) {
            return Err(Error::fatal(
                "could not exclude the SSH socket from the VPN",
                "Android must protect the SSH socket before connect, otherwise the tunnel loops into itself.",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Err(err) = sock.set_mark(crate::SSH_MARK) {
                tracing::debug!("SO_MARK was not applied: {err}");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = guard.prepare(0);
    }
    sock.connect_timeout(&addr.into(), timeout).map_err(map_io)?;
    sock.set_tcp_nodelay(true).ok();
    sock.set_nonblocking(true).map_err(map_io)?;
    let std_stream: std::net::TcpStream = sock.into();
    TcpStream::from_std(std_stream).map_err(map_io)
}

async fn socks_addr(socks: &SocksProxy) -> Result<SocketAddr> {
    resolve_one(&socks.host, socks.port).await
}

async fn socks5_handshake(stream: &mut TcpStream, target: &SocketAddr, socks: &SocksProxy, secrets: &SessionSecrets) -> Result<()> {
    let user = socks.username.as_deref().filter(|s| !s.is_empty());
    let pass = secrets.socks_password.as_ref().map(|s| s.as_str());
    if user.is_some() {
        stream.write_all(&[0x05, 0x01, 0x02]).await.map_err(map_io)?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await.map_err(map_io)?;
    }
    let mut greet = [0u8; 2];
    read_exact(stream, &mut greet).await?;
    if greet[0] != 0x05 {
        return Err(Error::fatal("SOCKS proxy returned an unexpected version", "Use a SOCKS5 proxy."));
    }
    if greet[1] == 0x02 {
        let user = user.unwrap_or("");
        let pass = pass.unwrap_or("");
        if user.len() > 255 || pass.len() > 255 {
            return Err(Error::fatal("SOCKS username or password is too long", "SOCKS5 limits each field to 255 bytes."));
        }
        let mut auth = vec![0x01, user.len() as u8];
        auth.extend(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend(pass.as_bytes());
        stream.write_all(&auth).await.map_err(map_io)?;
        let mut ans = [0u8; 2];
        read_exact(stream, &mut ans).await?;
        if ans[1] != 0 {
            return Err(error::auth_failed("SOCKS proxy rejected the username or password"));
        }
    } else if greet[1] != 0x00 {
        return Err(Error::fatal("SOCKS proxy refused the authentication method", "Fox-VPN supports no-auth and username/password SOCKS5."));
    }
    let mut req = vec![0x05, 0x01, 0x00];
    match target.ip() {
        std::net::IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend(v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend(v6.octets());
        }
    }
    req.extend(target.port().to_be_bytes());
    stream.write_all(&req).await.map_err(map_io)?;
    let mut hdr = [0u8; 4];
    read_exact(stream, &mut hdr).await?;
    if hdr[1] != 0 {
        return Err(Error::retryable(
            format!("SOCKS connect failed with status {}", hdr[1]),
            "The proxy could not reach the SSH server.",
        ));
    }
    let skip = match hdr[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).await?;
            len[0] as usize
        }
        _ => return Err(Error::fatal("SOCKS reply address type is unsupported", "The proxy returned a malformed reply.")),
    };
    let mut rest = vec![0u8; skip + 2];
    read_exact(stream, &mut rest).await?;
    Ok(())
}

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(buf))
        .await
        .map_err(|_| error::timed_out())?
        .map_err(map_io)?;
    Ok(())
}

fn map_io(err: std::io::Error) -> Error {
    match err.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => error::timed_out(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound | std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
            error::unreachable(err.to_string())
        }
        _ => error::unreachable(err.to_string()),
    }
}

fn map_ssh(err: &russh::Error) -> Error {
    let text = err.to_string();
    let lower = text.to_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        error::timed_out()
    } else if lower.contains("key") {
        error::host_key_rejected("unverified", false)
    } else {
        error::unreachable(text)
    }
}

/// Read an exec channel to completion, capping the amount kept.
pub async fn read_exec_output(channel: &mut SshChannel, limit: usize) -> Result<String> {
    let mut out = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                if out.len() < limit {
                    let room = limit - out.len();
                    let take = room.min(data.len());
                    out.extend_from_slice(&data[..take]);
                }
            }
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                tracing::debug!("remote stderr: {}", String::from_utf8_lossy(&data));
            }
            Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
            _ => {}
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use russh::server::Server;
    use crate::control::{ControlEvent, HostKeyChoice, PromptSlot, SessionControl};
    use crate::secrets::SessionSecrets;
    use std::sync::atomic::AtomicBool;
    use zeroize::Zeroizing;

    #[test]
    fn socks_request_builder_covers_ipv4() {
        let addr: SocketAddr = "203.0.113.9:2222".parse().unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 2222);
    }

    #[derive(Clone)]
    struct LocalServer;

    impl russh::server::Server for LocalServer {
        type Handler = LocalServer;
        fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
            LocalServer
        }
    }

    impl russh::server::Handler for LocalServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> std::result::Result<russh::server::Auth, Self::Error> {
            if user == "root" && password == "correct-horse" {
                Ok(russh::server::Auth::Accept)
            } else {
                Ok(russh::server::Auth::reject())
            }
        }
    }

    async fn serve() -> u16 {
        let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
        let config = Arc::new(russh::server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::from_millis(20),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            inactivity_timeout: Some(Duration::from_secs(30)),
            ..russh::server::Config::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut server = LocalServer;
            let _ = server.run_on_socket(config, &listener).await;
        });
        port
    }

    fn control_pair() -> (SessionControl, PromptSlot, tokio::sync::mpsc::UnboundedReceiver<ControlEvent>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let prompt = PromptSlot::default();
        let control = SessionControl::new(tx, prompt.clone(), Arc::new(AtomicBool::new(false)));
        (control, prompt, rx)
    }

    fn password_profile(port: u16) -> Profile {
        let mut profile = Profile::blank();
        profile.host = "127.0.0.1".into();
        profile.port = port;
        profile.username = "root".into();
        profile.authentication = crate::config::AuthMethod::Password;
        profile.connect_timeout_secs = 2;
        profile.keepalive_secs = 0;
        profile.reconnect = false;
        profile
    }

    async fn try_password(port: u16, password: &str, known_hosts: &Path, accept_new: bool, prompt: PromptSlot) -> Result<SshLink> {
        let (control, _, _) = {
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let control = SessionControl::new(tx, prompt, Arc::new(AtomicBool::new(false)));
            (control, (), ())
        };
        let profile = password_profile(port);
        let secrets = SessionSecrets {
            password: Some(Zeroizing::new(password.to_string())),
            ..SessionSecrets::default()
        };
        let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        connect(ConnectParams {
            profile: &profile,
            secrets: &secrets,
            server,
            known_hosts,
            accept_new_host_key: accept_new,
            owner: None,
            guard: &DesktopGuard,
            control: &control,
        })
        .await
    }

    #[tokio::test]
    async fn authenticates_password_and_rejects_bad_credentials_and_changed_keys() {
        let port = serve().await;
        let dir = std::env::temp_dir().join(format!("fox-vpn-ssh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let known = dir.join("known_hosts");

        let link = try_password(port, "correct-horse", &known, true, PromptSlot::default()).await;
        match &link {
            Ok(link) => link.shutdown(),
            Err(err) => panic!("expected authentication to succeed: {} {}", err.message(), err.hint()),
        }

        let rejected = try_password(port, "wrong", &known, true, PromptSlot::default()).await;
        let err = match rejected {
            Err(err) => err,
            Ok(_) => panic!("bad password must fail"),
        };
        assert!(err.is_fatal(), "{err:?}");
        assert!(err.message().contains("authentication"));

        let other = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
        crate::hostkey::trust("127.0.0.1", port, other.public_key(), &known, None).unwrap();
        let (events_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let prompt = PromptSlot::default();
        let prompt_task = prompt.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if matches!(event, ControlEvent::HostKeyPrompt { .. }) {
                    prompt_task.resolve(HostKeyChoice::Reject);
                }
            }
        });
        let profile = password_profile(port);
        let secrets = SessionSecrets {
            password: Some(Zeroizing::new("correct-horse".into())),
            ..SessionSecrets::default()
        };
        let control = SessionControl::new(events_tx, prompt, Arc::new(AtomicBool::new(false)));
        let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let changed = connect(ConnectParams {
            profile: &profile,
            secrets: &secrets,
            server,
            known_hosts: &known,
            accept_new_host_key: false,
            owner: None,
            guard: &DesktopGuard,
            control: &control,
        })
        .await;
        let err = match changed {
            Err(err) => err,
            Ok(_) => panic!("a changed host key must be rejected"),
        };
        assert!(err.is_fatal(), "{err:?}");
        assert!(err.message().to_lowercase().contains("host key"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn closed_port_is_unreachable_and_silent_peer_times_out() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = probe.local_addr().unwrap().port();
        drop(probe);
        let dir = std::env::temp_dir().join(format!("fox-vpn-ssh-down-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let known = dir.join("known_hosts");
        let refused = try_password(closed, "correct-horse", &known, true, PromptSlot::default()).await;
        let err = match refused {
            Err(err) => err,
            Ok(_) => panic!("nothing is listening"),
        };
        assert!(!err.is_fatal(), "{err:?}");

        let stall = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stall_port = stall.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = stall.accept().await {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sock);
            }
        });
        let mut profile = password_profile(stall_port);
        profile.connect_timeout_secs = 1;
        let secrets = SessionSecrets {
            password: Some(Zeroizing::new("correct-horse".into())),
            ..SessionSecrets::default()
        };
        let (control, _, _) = control_pair();
        let server: SocketAddr = format!("127.0.0.1:{stall_port}").parse().unwrap();
        let timed = connect(ConnectParams {
            profile: &profile,
            secrets: &secrets,
            server,
            known_hosts: &known,
            accept_new_host_key: true,
            owner: None,
            guard: &DesktopGuard,
            control: &control,
        })
        .await;
        let err = match timed {
            Err(err) => err,
            Ok(_) => panic!("a peer that never speaks SSH must time out"),
        };
        assert!(!err.is_fatal());
        assert!(err.message().to_lowercase().contains("timed out"), "{err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
