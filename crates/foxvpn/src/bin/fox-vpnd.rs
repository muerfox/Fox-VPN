//! Installed remote helper. Prefer this binary on servers that should not
//! depend on Python. It speaks FoxTunnel v1 on stdin and stdout.

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--stdio") | None => {
            let stdin = tokio::io::stdin();
            let stdout = tokio::io::stdout();
            if let Err(err) = foxvpn::helper_server::serve(stdin, stdout).await {
                eprintln!("fox-vpnd: {err}");
                std::process::exit(1);
            }
        }
        Some("--self-test") => {
            let (client, server) = tokio::io::duplex(1024);
            let (mut cr, mut cw) = tokio::io::split(client);
            let (sr, sw) = tokio::io::split(server);
            tokio::spawn(async move {
                let _ = foxvpn::helper_server::serve(sr, sw).await;
            });
            let hello = foxvpn::protocol::Frame::Ping(1).encode().unwrap();
            cw.write_all(&hello).await.unwrap();
            let mut buf = [0u8; 64];
            let n = cr.read(&mut buf).await.unwrap();
            let (frame, _) = foxvpn::protocol::decode_one(&buf[..n]).unwrap();
            assert!(matches!(frame, foxvpn::protocol::Frame::Pong(1)));
            println!("fox-vpnd self-test ok");
        }
        Some(other) => {
            eprintln!("usage: fox-vpnd [--stdio|--self-test] (got {other})");
            std::process::exit(2);
        }
    }
}

#[allow(dead_code)]
fn _write_bound<W: AsyncWrite>() {}
