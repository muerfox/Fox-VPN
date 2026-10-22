//! Client side of FoxTunnel v1.
//!
//! One SSH exec channel carries every proxied flow. Frames are demultiplexed
//! onto per-flow channels. The server is never asked to execute a command that
//! came from the network; the command string is chosen locally.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::protocol::{self, Frame, FrameDecoder, FEATURE_L3, FEATURE_L4, FEATURE_ROUTES, FEATURE_UDP, MODE_L3, MODE_L4};
use crate::ssh_link::{SshChannel, SshLink};

#[derive(Clone)]
pub struct HelperClient {
    tx: mpsc::UnboundedSender<Frame>,
    opens: Arc<Mutex<HashMap<u32, oneshot::Sender<std::result::Result<(), u16>>>>>,
    tcp: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    udp: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    next_id: Arc<AtomicU32>,
    mode: u8,
}

pub async fn start_helper(link: &SshLink, command: &str, want_l3: bool, mtu: u16) -> Result<(HelperClient, u8, mpsc::UnboundedReceiver<Vec<u8>>)> {
    let mut channel = link.open_exec(command).await?;
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Frame>();
    let opens = Arc::new(Mutex::new(HashMap::new()));
    let tcp = Arc::new(Mutex::new(HashMap::new()));
    let udp = Arc::new(Mutex::new(HashMap::new()));

    let (packet_tx, packet_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let hello = Frame::Hello {
        features: FEATURE_L3 | FEATURE_L4 | FEATURE_ROUTES | FEATURE_UDP,
        mode: if want_l3 { MODE_L3 } else { MODE_L4 },
        mtu,
    };
    let (read_half, write_half) = channel.split();
    let mut writer = write_half;
    writer.data_bytes(Bytes::from(hello.encode().map_err(|e| Error::fatal(e.to_string(), "Could not encode the helper handshake."))?)).await.map_err(|e| {
        Error::retryable(e.to_string(), "The remote helper exited before the handshake.")
    })?;

    let (ready_tx, ready_rx) = oneshot::channel();
    let opens_r = opens.clone();
    let tcp_r = tcp.clone();
    let udp_r = udp.clone();
    tokio::spawn(async move {
        let _ = pump_read(read_half, opens_r, tcp_r, udp_r, packet_tx, Some(ready_tx)).await;
    });
    tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            if let Ok(bytes) = frame.encode() {
                if writer.data_bytes(Bytes::from(bytes)).await.is_err() {
                    break;
                }
            }
        }
        let _ = writer.eof().await;
    });

    let ack = tokio::time::timeout(Duration::from_secs(20), ready_rx)
        .await
        .map_err(|_| Error::retryable("remote helper did not answer the handshake", "Install Python 3 on the server, or set remote_command to an installed fox-vpnd."))?
        .map_err(|_| Error::retryable("remote helper closed during the handshake", "Look at the connection log for the helper's stderr."))?;
    if ack.mode == 0 {
        return Err(Error::fatal(
            "remote helper refused the requested forwarding mode",
            "Full IP mode needs root and a TUN device on the server. TCP/UDP mode needs permission to open outbound sockets.",
        ));
    }
    let client = HelperClient {
        tx: frame_tx,
        opens,
        tcp,
        udp,
        next_id: Arc::new(AtomicU32::new(1)),
        mode: ack.mode,
    };
    Ok((client, ack.mode, packet_rx))
}

struct Ack {
    mode: u8,
}

async fn pump_read(
    mut read_half: russh::ChannelReadHalf,
    opens: Arc<Mutex<HashMap<u32, oneshot::Sender<std::result::Result<(), u16>>>>>,
    tcp: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    udp: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    packets: mpsc::UnboundedSender<Vec<u8>>,
    mut ready: Option<oneshot::Sender<Ack>>,
) -> Result<()> {
    let mut decoder = FrameDecoder::default();
    while let Some(msg) = read_half.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                let frames = decoder.push(&data).map_err(|e| Error::retryable(e.to_string(), "The remote helper sent a corrupt frame."))?;
                for frame in frames {
                    if let Frame::HelloAck { mode, .. } = &frame {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Ack { mode: *mode });
                        }
                    }
                    dispatch(frame, &opens, &tcp, &udp, &packets);
                }
            }
            ChannelMsg::ExtendedData { data, .. } => {
                let text = String::from_utf8_lossy(&data);
                tracing::info!("helper: {}", text.trim());
            }
            ChannelMsg::Eof | ChannelMsg::Close | ChannelMsg::ExitStatus { .. } => break,
            _ => {}
        }
    }
    Ok(())
}

fn dispatch(
    frame: Frame,
    opens: &Mutex<HashMap<u32, oneshot::Sender<std::result::Result<(), u16>>>>,
    tcp: &Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    udp: &Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    packets: &mpsc::UnboundedSender<Vec<u8>>,
) {
    match frame {
        Frame::TcpOpenOk { id } => {
            if let Some(tx) = opens.lock().ok().and_then(|mut m| m.remove(&id)) {
                let _ = tx.send(Ok(()));
            }
        }
        Frame::TcpOpenFail { id, code } => {
            if let Some(tx) = opens.lock().ok().and_then(|mut m| m.remove(&id)) {
                let _ = tx.send(Err(code));
            }
        }
        Frame::TcpData { id, data } => {
            if let Some(tx) = tcp.lock().ok().and_then(|m| m.get(&id).cloned()) {
                let _ = tx.send(data);
            }
        }
        Frame::UdpReply { id, data } => {
            if let Some(tx) = udp.lock().ok().and_then(|m| m.get(&id).cloned()) {
                let _ = tx.send(data);
            }
        }
        Frame::TcpClose { id } => {
            tcp.lock().ok().map(|mut m| m.remove(&id));
        }
        Frame::Packet(data) => {
            let _ = packets.send(data);
        }
        Frame::Error { message, .. } => tracing::warn!("helper error: {message}"),
        _ => {}
    }
}

impl HelperClient {
    pub fn mode(&self) -> u8 {
        self.mode
    }

    pub async fn open_tcp(&self, addr: IpAddr, port: u16) -> Result<(u32, mpsc::UnboundedReceiver<Vec<u8>>)> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (open_tx, open_rx) = oneshot::channel();
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.opens.lock().unwrap().insert(id, open_tx);
        self.tcp.lock().unwrap().insert(id, data_tx);
        self.tx
            .send(Frame::TcpOpen { id, addr, port })
            .map_err(|_| Error::retryable("helper channel closed", "The remote helper stopped."))?;
        match tokio::time::timeout(Duration::from_secs(20), open_rx).await {
            Ok(Ok(Ok(()))) => Ok((id, data_rx)),
            Ok(Ok(Err(code))) => {
                self.tcp.lock().ok().map(|mut m| m.remove(&id));
                Err(Error::retryable(
                    format!("remote connect failed with code {code}"),
                    "The server could not open the destination. The flow was dropped rather than sent outside the tunnel.",
                ))
            }
            _ => {
                self.tcp.lock().ok().map(|mut m| m.remove(&id));
                Err(Error::retryable("remote connect timed out", "The helper did not confirm the connection."))
            }
        }
    }

    pub fn prepare_udp(&self) -> (u32, mpsc::UnboundedReceiver<Vec<u8>>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.udp.lock().unwrap().insert(id, data_tx);
        (id, data_rx)
    }

    pub fn send_udp(&self, id: u32, addr: IpAddr, port: u16, data: Vec<u8>) -> Result<()> {
        self.tx
            .send(Frame::Udp { id, addr, port, data })
            .map_err(|_| Error::retryable("helper channel closed", "The remote helper stopped."))
    }

    pub fn send_tcp(&self, id: u32, data: Vec<u8>) -> Result<()> {
        self.tx
            .send(Frame::TcpData { id, data })
            .map_err(|_| Error::retryable("helper channel closed", "The remote helper stopped."))
    }

    pub fn close_tcp(&self, id: u32) {
        let _ = self.tx.send(Frame::TcpClose { id });
        self.tcp.lock().ok().map(|mut m| m.remove(&id));
    }

    pub fn send_packet(&self, packet: Vec<u8>) -> Result<()> {
        self.tx
            .send(Frame::Packet(packet))
            .map_err(|_| Error::retryable("helper channel closed", "The remote helper stopped."))
    }
}

/// Bridge a helper TCP flow to any async stream. Used by the packet forwarder.
pub async fn bridge_helper_tcp<S>(helper: HelperClient, id_rx: mpsc::UnboundedReceiver<Vec<u8>>, local: S, id: u32, up: &std::sync::atomic::AtomicU64, down: &std::sync::atomic::AtomicU64)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut lr, mut lw) = tokio::io::split(local);
    let mut rx = id_rx;
    let helper_w = helper.clone();
    let up_task = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match lr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            up.fetch_add(n as u64, Ordering::Relaxed);
            if helper_w.send_tcp(id, buf[..n].to_vec()).is_err() {
                break;
            }
        }
        helper_w.close_tcp(id);
    };
    let down_task = async {
        while let Some(data) = rx.recv().await {
            down.fetch_add(data.len() as u64, Ordering::Relaxed);
            if lw.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = lw.shutdown().await;
    };
    tokio::join!(up_task, down_task);
}

pub fn embedded_python_command() -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(include_str!("helper.py"));
    format!("python3 -u -c \"import base64,sys; exec(base64.b64decode('{encoded}').decode())\"")
}
