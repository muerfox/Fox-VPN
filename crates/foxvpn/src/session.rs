//! Session supervisor. One attempt connects, installs routes, forwards, and
//! always restores the network. Fatal authentication and host-key errors are
//! not retried. A lost network connection is retried only when the profile
//! asks for it.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ipnet::Ipv4Net;

use crate::config::{self, Profile, RoutingMode, TransportMode};
use crate::control::{backoff, SessionControl};
use crate::error::{self, Error, Result};
use crate::forward::{self, Counters};
use crate::ipcheck;
use crate::platform::{self, NetGuard};
use crate::routes::{self, DefaultRoute, RoutePlan};
use crate::secrets::SessionSecrets;
use crate::ssh_link::{self, ConnectParams, SocketGuard};

pub struct SessionRequest {
    pub profile: Profile,
    pub secrets: SessionSecrets,
    pub accept_new_host_key: bool,
    pub known_hosts: PathBuf,
    pub owner: Option<(u32, u32)>,
    pub guard: Arc<dyn SocketGuard>,
    /// Android passes a TUN file descriptor and does not touch system routes.
    pub android_fd: Option<i32>,
}

pub async fn run_session(request: SessionRequest, control: SessionControl) -> Result<()> {
    let mut attempt = 0u32;
    let mut cached: Option<Vec<SocketAddr>> = None;
    loop {
        if control.cancelled() {
            control.status("disconnected");
            let _ = control.events.send(crate::control::ControlEvent::Exit { code: 0 });
            return Ok(());
        }
        control.status(if attempt == 0 { "connecting" } else { "reconnecting" });
        match run_once(&request, &control, &mut cached).await {
            Ok(()) => {
                control.status("disconnected");
                let _ = control.events.send(crate::control::ControlEvent::Exit { code: 0 });
                return Ok(());
            }
            Err(Error::Stopped) => {
                control.status("disconnected");
                let _ = control.events.send(crate::control::ControlEvent::Exit { code: 0 });
                return Ok(());
            }
            Err(err) if err.is_fatal() || !request.profile.reconnect || control.cancelled() => {
                control.status("error");
                control.log("error", format!("{} {}", err.message(), err.hint()));
                let _ = control.events.send(crate::control::ControlEvent::Error {
                    message: err.message().to_string(),
                    hint: err.hint().to_string(),
                });
                let _ = control.events.send(crate::control::ControlEvent::Exit { code: 1 });
                return Err(err);
            }
            Err(err) => {
                control.log("warn", format!("disconnected: {} {}", err.message(), err.hint()));
                control.status("reconnecting");
                let wait = backoff(attempt);
                attempt = attempt.saturating_add(1);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = wait_cancel(&control) => {
                        control.status("disconnected");
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn wait_cancel(control: &SessionControl) {
    loop {
        if control.cancelled() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn run_once(request: &SessionRequest, control: &SessionControl, cached: &mut Option<Vec<SocketAddr>>) -> Result<()> {
    config::validate_profile(&request.profile).map_err(|e| Error::fatal(e, "Correct the profile and try again."))?;
    if request.android_fd.is_none() && !platform::is_elevated() {
        return Err(error::needs_elevation());
    }
    let addrs = if let Some(addrs) = cached.clone() {
        addrs
    } else {
        let addrs = ssh_link::resolve_all(&request.profile.host, request.profile.port).await?;
        *cached = Some(addrs.clone());
        control.log("info", format!("resolved {} to {}", request.profile.host, addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")));
        addrs
    };
    let server = addrs[0];
    if let Some(ip) = ipcheck::public_ip().await {
        control.log("info", format!("public address before tunnel: {ip}"));
        let _ = control.events.send(crate::control::ControlEvent::PublicIp { phase: "before".into(), value: ip });
    } else {
        control.log("warn", "public address check is unavailable; the tunnel will still start");
    }

    let link = ssh_link::connect(ConnectParams {
        profile: &request.profile,
        secrets: &request.secrets,
        server,
        known_hosts: &request.known_hosts,
        accept_new_host_key: request.accept_new_host_key,
        owner: request.owner,
        guard: request.guard.as_ref(),
        control,
    })
    .await?;

    let remote_routes = remote_routes(&link, &request.profile, control).await?;
    let dns = config::parse_dns_v4(&request.profile).map_err(|e| Error::fatal(e, "Use numeric DNS server addresses."))?;
    let bypass_ips: Vec<IpAddr> = ssh_link::ipv4_of(&addrs).into_iter().map(IpAddr::V4).collect();

    let mut guard: Option<NetGuard> = None;
    let device = if let Some(fd) = request.android_fd {
        #[cfg(target_os = "android")]
        {
            platform::open_tun_fd(fd, config::effective_mtu(&request.profile))?
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = fd;
            return Err(Error::fatal(
                "an existing tunnel descriptor was provided on a non-Android build",
                "Use the Android application for VpnService file descriptors.",
            ));
        }
    } else {
        let default = platform::read_default_route()?;
        let plan = build_plan(&request.profile, &default, &ssh_link::ipv4_of(&addrs), &[], &remote_routes)?;
        let device = platform::open_tun(config::effective_mtu(&request.profile))?;
        guard = Some(platform::apply(&request.profile, &plan, &dns)?);
        control.log("info", "routes and DNS are installed; the SSH server stays on the original gateway");
        device
    };

    control.status("connected");
    let _ = control.events.send(crate::control::ControlEvent::Info {
        transport: request.profile.transport.label().into(),
        server: request.profile.endpoint(),
    });
    let counters = Arc::new(Counters::default());
    let counters_watch = counters.clone();
    let events = control.events.clone();
    let cancel = control.cancel.clone();
    tokio::spawn(async move {
        let mut last_up = 0u64;
        let mut last_down = 0u64;
        loop {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let up = counters_watch.up.load(std::sync::atomic::Ordering::Relaxed);
            let down = counters_watch.down.load(std::sync::atomic::Ordering::Relaxed);
            let _ = (last_up, last_down);
            last_up = up;
            last_down = down;
            let _ = events.send(crate::control::ControlEvent::Stats { up, down });
        }
    });
    let ip_events = control.events.clone();
    let ip_log = control.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Some(ip) = ipcheck::public_ip().await {
            ip_log.log("info", format!("public address through the tunnel: {ip}"));
            let _ = ip_events.send(crate::control::ControlEvent::PublicIp { phase: "after".into(), value: ip });
        }
    });

    let forward = forward::run_userspace(
        device,
        &request.profile,
        link.clone(),
        &dns,
        &bypass_ips,
        counters,
        control.clone(),
    );
    tokio::pin!(forward);
    tokio::select! {
        result = &mut forward => {
            link.shutdown();
            result?;
        }
        _ = wait_cancel(control) => {
            link.shutdown();
        }
    }
    control.log("info", "tunnel stopped; restoring routes, DNS, and firewall rules");
    drop(guard);
    Ok(())
}

fn build_plan(
    profile: &Profile,
    default: &DefaultRoute,
    server: &[std::net::Ipv4Addr],
    extra: &[std::net::Ipv4Addr],
    remote: &[Ipv4Net],
) -> Result<RoutePlan> {
    routes::plan_routes(profile, default, server, extra, remote).map_err(|e| {
        Error::fatal(e, "The tunnel was not started, so the existing network configuration is unchanged.")
    })
}

async fn remote_routes(link: &ssh_link::SshLink, profile: &Profile, control: &SessionControl) -> Result<Vec<Ipv4Net>> {
    let need = profile.auto_networks && (profile.routing_mode == RoutingMode::SplitTunnel || profile.verbose_logging);
    if !profile.auto_networks {
        return Ok(Vec::new());
    }
    if profile.transport == TransportMode::HelperL3 {
        return Ok(Vec::new());
    }
    let mut channel = match link.open_exec("ip -4 route show").await {
        Ok(channel) => channel,
        Err(err) => {
            if profile.routing_mode == RoutingMode::SplitTunnel && profile.split_routes.is_empty() {
                return Err(Error::fatal(err.message(), "Automatic network discovery could not read the server routing table."));
            }
            control.log("warn", format!("automatic network discovery skipped: {}", err.message()));
            return Ok(Vec::new());
        }
    };
    let text = ssh_link::read_exec_output(&mut channel, 64 * 1024).await?;
    let routes = routes::parse_remote_routes(&text);
    if need {
        control.log("info", format!("server reported {} usable IPv4 prefixes", routes.len()));
    }
    if profile.routing_mode == RoutingMode::SplitTunnel && profile.split_routes.is_empty() && routes.is_empty() {
        return Err(Error::fatal(
            "automatic network discovery found no usable prefixes",
            "Add explicit split routes, or switch the profile to full tunnel.",
        ));
    }
    Ok(routes)
}

// Silence unused import if a platform cfg drops a name during type checking.
#[allow(dead_code)]
fn _guard_type(guard: NetGuard) -> NetGuard {
    guard
}
