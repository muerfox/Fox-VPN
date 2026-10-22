//! Userspace forwarding.
//!
//! Packets arrive on a TUN device. `ipstack` turns them into TCP and UDP flows.
//! Those flows are carried either by SSH `direct-tcpip` (stock OpenSSH server)
//! or by the Fox helper. ICMP and non-DNS UDP are dropped in direct mode, which
//! keeps them off the physical network instead of leaking them.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore};

use crate::config::{Profile, TransportMode};
use crate::control::SessionControl;
use crate::error::{Error, Result};
use crate::helper_link::{self, HelperClient};
use crate::protocol::MODE_L3;
use crate::ssh_link::SshLink;

#[derive(Default)]
pub struct Counters {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

pub async fn run_userspace<D>(
    device: D,
    profile: &Profile,
    link: SshLink,
    dns: &[Ipv4Addr],
    bypass: &[IpAddr],
    counters: Arc<Counters>,
    control: SessionControl,
) -> Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let helper = if profile.transport == TransportMode::SshDirect {
        None
    } else {
        let command = profile.remote_command.clone().unwrap_or_else(helper_link::embedded_python_command);
        let want_l3 = profile.transport == TransportMode::HelperL3;
        control.log("info", format!("starting remote helper ({})", profile.transport.label()));
        let (client, mode, packets) = helper_link::start_helper(&link, &command, want_l3, crate::config::effective_mtu(profile)).await?;
        if want_l3 && mode != MODE_L3 {
            return Err(Error::fatal(
                "full IP mode was requested but the helper did not enable it",
                "Run the helper as root on a Linux server with /dev/net/tun, or switch the transport to SSH direct-tcpip.",
            ));
        }
        if mode == MODE_L3 {
            return run_l3(device, client, packets, counters, control).await;
        }
        Some(client)
    };

    let mtu = crate::config::effective_mtu(profile);
    let mut ip_config = ipstack::IpStackConfig::default();
    ip_config.mtu(mtu).map_err(|e| Error::fatal(e.to_string(), "Set MTU to at least 1280."))?;
    ip_config.udp_timeout(Duration::from_secs(30));
    let mut tcp_config = ipstack::TcpConfig::default();
    tcp_config.timeout = Duration::from_secs(120);
    tcp_config.max_unacked_bytes = 256 * 1024;
    ip_config.with_tcp_config(tcp_config);
    let mut stack = ipstack::IpStack::new(ip_config, device);
    let limit = Arc::new(Semaphore::new(512));
    let dns: Vec<SocketAddr> = dns.iter().map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53)).collect();
    let bypass = bypass.to_vec();
    let noted_udp = AtomicBool::new(false);
    let noted_other = AtomicBool::new(false);
    control.log(
        "info",
        match profile.transport {
            TransportMode::SshDirect => "forwarding TCP, and DNS over TCP, through SSH direct-tcpip".to_string(),
            _ => "forwarding TCP and UDP through the remote helper".to_string(),
        },
    );

    loop {
        if control.cancelled() {
            break;
        }
        let accepted = tokio::select! {
            _ = cancelled(&control) => break,
            value = stack.accept() => value,
        };
        let stream = match accepted {
            Ok(stream) => stream,
            Err(_) => break,
        };
        let peer = stream.peer_addr();
        if !profile.ipv6 && peer.is_ipv6() {
            control.log("debug", format!("dropped IPv6 flow {peer} because IPv6 forwarding is disabled"));
            continue;
        }
        if bypass.iter().any(|ip| *ip == peer.ip()) {
            control.log("warn", format!("dropped flow to {peer}; that address is excluded so the SSH transport cannot loop"));
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            control.log("warn", "connection limit reached; dropping a new flow");
            continue;
        };
        match stream {
            ipstack::IpStackStream::Tcp(tcp) => {
                if profile.verbose_logging || control_verbose() {
                    control.log("debug", format!("tcp {} -> {}", tcp.local_addr(), tcp.peer_addr()));
                }
                let link = link.clone();
                let helper = helper.clone();
                let counters = counters.clone();
                let control = control.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = drive_tcp(tcp, link, helper, counters, control.clone()).await {
                        control.log("debug", format!("tcp flow ended: {}", err.message()));
                    }
                });
            }
            ipstack::IpStackStream::Udp(udp) => {
                let is_dns = udp.peer_addr().port() == 53;
                if is_dns && profile.tunnel_dns && helper.is_none() {
                    let link = link.clone();
                    let dns = dns.clone();
                    let counters = counters.clone();
                    let control = control.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = drive_dns(udp, link, &dns, counters).await {
                            control.log("debug", format!("dns flow ended: {err}"));
                        }
                    });
                } else if helper.is_some() {
                    let helper = helper.clone().unwrap();
                    let counters = counters.clone();
                    let control = control.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = drive_udp(udp, helper, counters).await {
                            control.log("debug", format!("udp flow ended: {}", err.message()));
                        }
                    });
                } else if noted_udp.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    control.log(
                        "warn",
                        "non-DNS UDP is captured and dropped in SSH direct mode. QUIC may fall back to TCP. Use the remote helper transport to forward UDP.",
                    );
                }
            }
            ipstack::IpStackStream::UnknownTransport(_) | ipstack::IpStackStream::UnknownNetwork(_) => {
                if noted_other.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    control.log(
                        "warn",
                        "ICMP and other non-TCP protocols are captured and dropped in this transport. Ping will not work. Full IP mode forwards them through a root helper.",
                    );
                }
            }
        }
    }
    Ok(())
}

fn control_verbose() -> bool {
    false
}

async fn cancelled(control: &SessionControl) {
    loop {
        if control.cancelled() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn drive_tcp(
    local: ipstack::IpStackTcpStream,
    link: SshLink,
    helper: Option<HelperClient>,
    counters: Arc<Counters>,
    _control: SessionControl,
) -> Result<()> {
    let peer = local.peer_addr();
    let origin = local.local_addr();
    if let Some(helper) = helper {
        let (id, rx) = helper.open_tcp(peer.ip(), peer.port()).await?;
        helper_link::bridge_helper_tcp(helper, rx, local, id, &counters.up, &counters.down).await;
        return Ok(());
    }
    let channel = link.open_direct(&peer.ip().to_string(), peer.port(), &origin.ip().to_string(), origin.port()).await?;
    let remote = channel.into_stream();
    copy_both(local, remote, &counters).await;
    Ok(())
}

async fn drive_dns(
    mut udp: ipstack::IpStackUdpStream,
    link: SshLink,
    servers: &[SocketAddr],
    counters: Arc<Counters>,
) -> std::result::Result<(), String> {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = udp.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        counters.up.fetch_add(n as u64, Ordering::Relaxed);
        let query = buf[..n].to_vec();
        if let Some(name) = dns_qname(&query) {
            tracing::debug!("dns {name}");
        }
        let answer = dns_over_tcp(&link, servers, &query).await?;
        counters.down.fetch_add(answer.len() as u64, Ordering::Relaxed);
        udp.write_all(&answer).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn dns_over_tcp(link: &SshLink, servers: &[SocketAddr], query: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if query.is_empty() || query.len() > 4000 {
        return Err("dns query has an unexpected size".into());
    }
    let mut last = String::from("no DNS resolver configured");
    for server in servers {
        match dns_one(link, server, query).await {
            Ok(body) => return Ok(body),
            Err(err) => last = err,
        }
    }
    Err(last)
}

async fn dns_one(link: &SshLink, server: &SocketAddr, query: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let channel = link
        .open_direct(&server.ip().to_string(), server.port(), "10.77.0.2", 0)
        .await
        .map_err(|e| e.message().to_string())?;
    let mut stream = channel.into_stream();
    let mut packet = (query.len() as u16).to_be_bytes().to_vec();
    packet.extend_from_slice(query);
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(&packet)).await.map_err(|_| "dns timeout".to_string())?.map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf)).await.map_err(|_| "dns timeout".to_string())?.map_err(|e| e.to_string())?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 4000 {
        return Err("dns response length is invalid".into());
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body)).await.map_err(|_| "dns timeout".to_string())?.map_err(|e| e.to_string())?;
    Ok(body)
}

async fn drive_udp(mut udp: ipstack::IpStackUdpStream, helper: HelperClient, counters: Arc<Counters>) -> Result<()> {
    let peer = udp.peer_addr();
    let (id, mut rx) = helper.prepare_udp();
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            n = udp.read(&mut buf) => {
                let n = n.map_err(|e| Error::retryable(e.to_string(), "UDP flow closed."))?;
                if n == 0 { break; }
                counters.up.fetch_add(n as u64, Ordering::Relaxed);
                helper.send_udp(id, peer.ip(), peer.port(), buf[..n].to_vec())?;
            }
            data = rx.recv() => {
                let Some(data) = data else { break };
                counters.down.fetch_add(data.len() as u64, Ordering::Relaxed);
                if udp.write_all(&data).await.is_err() { break; }
            }
        }
    }
    Ok(())
}

async fn run_l3<D>(
    device: D,
    helper: HelperClient,
    mut packets: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    counters: Arc<Counters>,
    control: SessionControl,
) -> Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    control.log("info", "forwarding raw IP packets through the remote TUN helper");
    let (mut reader, mut writer) = tokio::io::split(device);
    let helper_up = helper.clone();
    let up_counter = Arc::clone(&counters);
    let down_counter = Arc::clone(&counters);
    let up_task = async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            up_counter.up.fetch_add(n as u64, Ordering::Relaxed);
            if helper_up.send_packet(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    };
    let down_task = async move {
        while let Some(packet) = packets.recv().await {
            down_counter.down.fetch_add(packet.len() as u64, Ordering::Relaxed);
            if writer.write_all(&packet).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = cancelled(&control) => {}
        _ = up_task => {}
        _ = down_task => {}
    }
    Ok(())
}

async fn copy_both<A, B>(local: A, remote: B, counters: &Counters)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut lr, mut lw) = tokio::io::split(local);
    let (mut rr, mut rw) = tokio::io::split(remote);
    let up = pipe(&mut lr, &mut rw, &counters.up);
    let down = pipe(&mut rr, &mut lw, &counters.down);
    let _ = tokio::join!(up, down);
}

async fn pipe<R, W>(reader: &mut R, writer: &mut W, counter: &AtomicU64) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16384];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
        writer.write_all(&buf[..n]).await?;
    }
}

pub fn dns_qname(query: &[u8]) -> Option<String> {
    if query.len() < 13 {
        return None;
    }
    let mut index = 12usize;
    let mut labels = Vec::new();
    while index < query.len() {
        let len = query[index] as usize;
        if len == 0 {
            break;
        }
        if len > 63 || index + 1 + len > query.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&query[index + 1..index + 1 + len]).into_owned());
        index += 1 + len;
        if labels.len() > 32 {
            return None;
        }
    }
    if labels.is_empty() { None } else { Some(labels.join(".")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_qname() {
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(b"\x07example\x03com\x00");
        query.extend([0, 1, 0, 1]);
        assert_eq!(dns_qname(&query).as_deref(), Some("example.com"));
    }
}
