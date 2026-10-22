//! In-process FoxTunnel server used by `fox-vpnd` and by tests.
//! The embedded Python helper speaks the same frames for servers that do not
//! have a preinstalled binary.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::protocol::{self, Frame, FrameDecoder, FEATURE_L4, FEATURE_UDP, MODE_L3, MODE_L4};

enum ConnMsg {
    Data(Vec<u8>),
    Close,
}

pub async fn serve<R, W>(mut reader: R, mut writer: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Frame>();
    let write_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let Ok(bytes) = frame.encode() else { break };
            if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });
    let conns: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<ConnMsg>>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut decoder = FrameDecoder::default();
    let mut buf = vec![0u8; 16384];
    let mut mode = 0u8;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let frames = decoder.push(&buf[..n]).map_err(|e| std::io::Error::other(e.to_string()))?;
        for frame in frames {
            match frame {
                Frame::Hello { mode: requested, mtu, .. } => {
                    if requested == MODE_L3 {
                        let _ = out_tx.send(Frame::HelloAck { features: FEATURE_L4 | FEATURE_UDP, mode: 0, mtu });
                        let _ = out_tx.send(Frame::Error {
                            code: 1,
                            message: "this fox-vpnd build forwards TCP and UDP; full IP mode is provided by the Python helper when run as root".into(),
                        });
                        mode = 0;
                        break;
                    }
                    mode = MODE_L4;
                    let _ = out_tx.send(Frame::HelloAck {
                        features: FEATURE_L4 | FEATURE_UDP,
                        mode: MODE_L4,
                        mtu,
                    });
                }
                Frame::TcpOpen { id, addr, port } => {
                    if mode != MODE_L4 {
                        continue;
                    }
                    let (tx, rx) = mpsc::unbounded_channel();
                    conns.lock().await.insert(id, tx);
                    let out = out_tx.clone();
                    let conns2 = conns.clone();
                    tokio::spawn(async move {
                        drive_tcp(id, SocketAddr::new(addr, port), rx, out, conns2).await;
                    });
                }
                Frame::TcpData { id, data } => {
                    if let Some(tx) = conns.lock().await.get(&id).cloned() {
                        let _ = tx.send(ConnMsg::Data(data));
                    }
                }
                Frame::TcpClose { id } => {
                    if let Some(tx) = conns.lock().await.remove(&id) {
                        let _ = tx.send(ConnMsg::Close);
                    }
                }
                Frame::Udp { id, addr, port, data } => {
                    if data.is_empty() {
                        continue;
                    }
                    let out = out_tx.clone();
                    tokio::spawn(async move {
                        if let Ok(socket) = tokio::net::UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await {
                            if socket.send_to(&data, SocketAddr::new(addr, port)).await.is_ok() {
                                let mut buf = vec![0u8; 65535];
                                if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
                                    let _ = out.send(Frame::UdpReply { id, data: buf[..n].to_vec() });
                                }
                            }
                        }
                    });
                }
                Frame::Ping(n) => {
                    let _ = out_tx.send(Frame::Pong(n));
                }
                Frame::RoutesReq => {
                    let _ = out_tx.send(Frame::Routes(Vec::new()));
                }
                _ => {}
            }
        }
        if mode == 0 && out_tx.is_closed() {
            break;
        }
    }
    drop(out_tx);
    let _ = write_task.await;
    Ok(())
}

async fn drive_tcp(
    id: u32,
    addr: SocketAddr,
    mut rx: mpsc::UnboundedReceiver<ConnMsg>,
    out: mpsc::UnboundedSender<Frame>,
    conns: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<ConnMsg>>>>,
) {
    let stream = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            let _ = out.send(Frame::TcpOpenFail { id, code: err.raw_os_error().unwrap_or(1) as u16 });
            conns.lock().await.remove(&id);
            return;
        }
        Err(_) => {
            let _ = out.send(Frame::TcpOpenFail { id, code: 110 });
            conns.lock().await.remove(&id);
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    let _ = out.send(Frame::TcpOpenOk { id });
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(ConnMsg::Data(data)) => {
                        if wr.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(ConnMsg::Close) | None => break,
                }
            }
            n = rd.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.send(Frame::TcpData { id, data: buf[..n].to_vec() }).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = out.send(Frame::TcpClose { id });
    conns.lock().await.remove(&id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, dec: &mut FrameDecoder) -> Frame {
        let mut buf = [0u8; 2048];
        loop {
            if let Some(frame) = {
                // Decoder keeps its own buffer; poll it by pushing newly read bytes.
                None::<Frame>
            } {
                return frame;
            }
            let n = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf)).await.unwrap().unwrap();
            let frames = dec.push(&buf[..n]).unwrap();
            if let Some(frame) = frames.into_iter().next() {
                // If multiple, tests only send one at a time except the echo body.
                return frame;
            }
        }
    }

    #[tokio::test]
    async fn helper_proxies_tcp_echo() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (mut cr, mut cw) = tokio::io::split(client);
        let (sr, sw) = tokio::io::split(server);
        tokio::spawn(async move {
            serve(sr, sw).await.unwrap();
        });
        let hello = Frame::Hello { features: FEATURE_L4, mode: MODE_L4, mtu: 1500 }.encode().unwrap();
        cw.write_all(&hello).await.unwrap();
        let mut dec = FrameDecoder::default();
        let ack = next_frame(&mut cr, &mut dec).await;
        assert!(matches!(ack, Frame::HelloAck { mode: MODE_L4, .. }));
        let open = Frame::TcpOpen {
            id: 7,
            addr: "127.0.0.1".parse().unwrap(),
            port,
        }
        .encode()
        .unwrap();
        cw.write_all(&open).await.unwrap();
        let opened = next_frame(&mut cr, &mut dec).await;
        assert!(matches!(opened, Frame::TcpOpenOk { id: 7 }));
        let data = Frame::TcpData { id: 7, data: b"ping".to_vec() }.encode().unwrap();
        cw.write_all(&data).await.unwrap();
        let echoed = next_frame(&mut cr, &mut dec).await;
        match echoed {
            Frame::TcpData { id: 7, data } => assert_eq!(data, b"ping"),
            other => panic!("unexpected {other:?}"),
        }
    }

    async fn next_frame<R: AsyncRead + Unpin>(reader: &mut R, dec: &mut FrameDecoder) -> Frame {
        let mut buf = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf)).await.unwrap().unwrap();
            assert!(n > 0);
            let mut frames = dec.push(&buf[..n]).unwrap();
            if !frames.is_empty() {
                return frames.remove(0);
            }
        }
    }

    #[test]
    fn python_helper_echoes_tcp() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = std::io::Read::read(&mut sock, &mut buf).unwrap();
            std::io::Write::write_all(&mut sock, &buf[..n]).unwrap();
        });
        let mut child = std::process::Command::new("python3")
            .arg("-u")
            .arg("-c")
            .arg(crate::helper_link::embedded_python_command().trim_start_matches("python3 -u -c ").trim_matches('"'))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // The command builder wraps the script in quotes for SSH. Spawn Python
        // with the same exec expression the SSH command uses.
        let _ = child.kill();
        let script = format!(
            "import base64,sys; exec(base64.b64decode('{}').decode())",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, include_str!("helper.py"))
        );
        let mut child = std::process::Command::new("python3")
            .arg("-u")
            .arg("-c")
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let hello = Frame::Hello { features: FEATURE_L4, mode: MODE_L4, mtu: 1500 }.encode().unwrap();
        std::io::Write::write_all(&mut stdin, &hello).unwrap();
        let mut dec = FrameDecoder::default();
        let mut raw = Vec::new();
        let ack = read_one(&mut stdout, &mut raw, &mut dec);
        assert!(matches!(ack, Frame::HelloAck { mode: MODE_L4, .. }), "{ack:?}");
        let open = Frame::TcpOpen { id: 3, addr: "127.0.0.1".parse().unwrap(), port }.encode().unwrap();
        std::io::Write::write_all(&mut stdin, &open).unwrap();
        let opened = read_one(&mut stdout, &mut raw, &mut dec);
        assert!(matches!(opened, Frame::TcpOpenOk { id: 3 }), "{opened:?} stderr={}", String::from_utf8_lossy(&read_stderr(&mut child)));
        let data = Frame::TcpData { id: 3, data: b"abc".to_vec() }.encode().unwrap();
        std::io::Write::write_all(&mut stdin, &data).unwrap();
        let echoed = read_one(&mut stdout, &mut raw, &mut dec);
        match echoed {
            Frame::TcpData { id: 3, data } => assert_eq!(data, b"abc"),
            other => panic!("unexpected {other:?}"),
        }
        let _ = child.kill();
    }

    fn read_stderr(child: &mut std::process::Child) -> Vec<u8> {
        child.stderr.take().and_then(|mut s| {
            let mut b = Vec::new();
            use std::io::Read;
            s.read_to_end(&mut b).ok()?;
            Some(b)
        }).unwrap_or_default()
    }

    fn read_one(stdout: &mut std::process::ChildStdout, raw: &mut Vec<u8>, dec: &mut FrameDecoder) -> Frame {
        use std::io::Read;
        let mut tmp = [0u8; 4096];
        for _ in 0..50 {
            if let Some(frame) = dec.push(&[]).ok().and_then(|mut f| if f.is_empty() { None } else { Some(f.remove(0)) }) {
                return frame;
            }
            stdout.set_nonblocking_read();
            let n = stdout.read(&mut tmp).unwrap_or(0);
            if n == 0 {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            raw.extend_from_slice(&tmp[..n]);
            let mut frames = dec.push(&tmp[..n]).unwrap();
            if !frames.is_empty() {
                return frames.remove(0);
            }
        }
        panic!("python helper produced no frame");
    }
}

trait Nonblock {
    fn set_nonblocking_read(&mut self);
}

impl Nonblock for std::process::ChildStdout {
    fn set_nonblocking_read(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let fd = self.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
    }
}
