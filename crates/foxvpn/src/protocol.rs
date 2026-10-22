//! FoxTunnel v1 framing.
//!
//! A frame is `FXVN`, a version byte, a type byte, a big-endian payload length,
//! and the payload. The maximum payload is 65,535 bytes. This protocol is used
//! only with the remote helper. The default transport does not use it; it opens
//! SSH `direct-tcpip` channels instead.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAGIC: &[u8; 4] = b"FXVN";
pub const VERSION: u8 = 1;
pub const MAX_PAYLOAD: usize = 65_535;

pub const FEATURE_L3: u32 = 1;
pub const FEATURE_L4: u32 = 2;
pub const FEATURE_ROUTES: u32 = 4;
pub const FEATURE_UDP: u32 = 8;

pub const MODE_AUTO: u8 = 0;
pub const MODE_L3: u8 = 1;
pub const MODE_L4: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        features: u32,
        mode: u8,
        mtu: u16,
    },
    HelloAck {
        features: u32,
        mode: u8,
        mtu: u16,
    },
    Packet(Vec<u8>),
    Ping(u64),
    Pong(u64),
    Error { code: u16, message: String },
    RoutesReq,
    Routes(Vec<(Ipv4Addr, u8)>),
    TcpOpen { id: u32, addr: IpAddr, port: u16 },
    TcpOpenOk { id: u32 },
    TcpOpenFail { id: u32, code: u16 },
    TcpData { id: u32, data: Vec<u8> },
    TcpClose { id: u32 },
    Udp {
        id: u32,
        addr: IpAddr,
        port: u16,
        data: Vec<u8>,
    },
    UdpReply { id: u32, data: Vec<u8> },
}

#[derive(Debug)]
pub enum DecodeError {
    BadMagic,
    BadVersion(u8),
    Truncated,
    TooLarge(usize),
    Malformed(&'static str),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "frame magic is not FXVN"),
            Self::BadVersion(v) => write!(f, "unsupported frame version {v}"),
            Self::Truncated => write!(f, "truncated frame"),
            Self::TooLarge(n) => write!(f, "frame payload {n} exceeds {MAX_PAYLOAD}"),
            Self::Malformed(m) => write!(f, "malformed frame: {m}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        let (typ, payload) = self.payload()?;
        if payload.len() > MAX_PAYLOAD {
            return Err(DecodeError::TooLarge(payload.len()));
        }
        let mut out = Vec::with_capacity(10 + payload.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(typ);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend(payload);
        Ok(out)
    }

    fn payload(&self) -> Result<(u8, Vec<u8>), DecodeError> {
        Ok(match self {
            Self::Hello { features, mode, mtu } => {
                let mut p = Vec::with_capacity(7);
                p.extend_from_slice(&features.to_be_bytes());
                p.push(*mode);
                p.extend_from_slice(&mtu.to_be_bytes());
                (1, p)
            }
            Self::HelloAck { features, mode, mtu } => {
                let mut p = Vec::with_capacity(7);
                p.extend_from_slice(&features.to_be_bytes());
                p.push(*mode);
                p.extend_from_slice(&mtu.to_be_bytes());
                (2, p)
            }
            Self::Packet(data) => (3, data.clone()),
            Self::Ping(n) => (4, n.to_be_bytes().to_vec()),
            Self::Pong(n) => (5, n.to_be_bytes().to_vec()),
            Self::Error { code, message } => {
                let mut p = code.to_be_bytes().to_vec();
                p.extend(message.as_bytes());
                (6, p)
            }
            Self::RoutesReq => (7, Vec::new()),
            Self::Routes(routes) => {
                let mut p = Vec::with_capacity(routes.len() * 5);
                for (addr, prefix) in routes {
                    p.extend_from_slice(&addr.octets());
                    p.push(*prefix);
                }
                (8, p)
            }
            Self::TcpOpen { id, addr, port } => (9, encode_flow(*id, *addr, *port, &[])?),
            Self::TcpOpenOk { id } => (10, id.to_be_bytes().to_vec()),
            Self::TcpOpenFail { id, code } => {
                let mut p = id.to_be_bytes().to_vec();
                p.extend_from_slice(&code.to_be_bytes());
                (11, p)
            }
            Self::TcpData { id, data } => {
                let mut p = id.to_be_bytes().to_vec();
                p.extend(data);
                (12, p)
            }
            Self::TcpClose { id } => (13, id.to_be_bytes().to_vec()),
            Self::Udp { id, addr, port, data } => (14, encode_flow(*id, *addr, *port, data)?),
            Self::UdpReply { id, data } => {
                let mut p = id.to_be_bytes().to_vec();
                p.extend(data);
                (15, p)
            }
        })
    }
}

fn encode_flow(id: u32, addr: IpAddr, port: u16, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let octets = match addr {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    let mut p = Vec::with_capacity(7 + octets.len() + data.len());
    p.extend_from_slice(&id.to_be_bytes());
    p.push(octets.len() as u8);
    p.extend(octets);
    p.extend_from_slice(&port.to_be_bytes());
    p.extend_from_slice(data);
    Ok(p)
}

fn decode_addr(buf: &[u8]) -> Result<(IpAddr, usize), DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::Malformed("address length missing"));
    }
    let len = buf[0] as usize;
    if buf.len() < 1 + len {
        return Err(DecodeError::Malformed("address truncated"));
    }
    let addr = match len {
        4 => IpAddr::V4(Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4])),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(DecodeError::Malformed("address length must be 4 or 16")),
    };
    Ok((addr, 1 + len))
}

fn need<'a>(buf: &'a [u8], n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
    if buf.len() < n {
        Err(DecodeError::Malformed(what))
    } else {
        Ok(buf)
    }
}

pub fn decode_one(buf: &[u8]) -> Result<(Frame, usize), DecodeError> {
    if buf.len() < 10 {
        return Err(DecodeError::Truncated);
    }
    if &buf[0..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if buf[4] != VERSION {
        return Err(DecodeError::BadVersion(buf[4]));
    }
    let typ = buf[5];
    let len = u32::from_be_bytes(buf[6..10].try_into().unwrap()) as usize;
    if len > MAX_PAYLOAD {
        return Err(DecodeError::TooLarge(len));
    }
    if buf.len() < 10 + len {
        return Err(DecodeError::Truncated);
    }
    let payload = &buf[10..10 + len];
    let frame = match typ {
        1 => {
            let p = need(payload, 7, "hello")?;
            Frame::Hello {
                features: u32::from_be_bytes(p[0..4].try_into().unwrap()),
                mode: p[4],
                mtu: u16::from_be_bytes(p[5..7].try_into().unwrap()),
            }
        }
        2 => {
            let p = need(payload, 7, "hello ack")?;
            Frame::HelloAck {
                features: u32::from_be_bytes(p[0..4].try_into().unwrap()),
                mode: p[4],
                mtu: u16::from_be_bytes(p[5..7].try_into().unwrap()),
            }
        }
        3 => Frame::Packet(payload.to_vec()),
        4 => {
            let p = need(payload, 8, "ping")?;
            Frame::Ping(u64::from_be_bytes(p[..8].try_into().unwrap()))
        }
        5 => {
            let p = need(payload, 8, "pong")?;
            Frame::Pong(u64::from_be_bytes(p[..8].try_into().unwrap()))
        }
        6 => {
            let p = need(payload, 2, "error")?;
            let message = String::from_utf8_lossy(&p[2..]).into_owned();
            Frame::Error {
                code: u16::from_be_bytes(p[..2].try_into().unwrap()),
                message,
            }
        }
        7 => Frame::RoutesReq,
        8 => {
            if payload.len() % 5 != 0 {
                return Err(DecodeError::Malformed("routes length"));
            }
            let mut routes = Vec::new();
            for chunk in payload.chunks(5) {
                routes.push((
                    Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                    chunk[4],
                ));
            }
            Frame::Routes(routes)
        }
        9 => {
            let (id, addr, port, rest) = decode_endpoint(payload)?;
            if !rest.is_empty() {
                return Err(DecodeError::Malformed("tcp open trailing bytes"));
            }
            Frame::TcpOpen { id, addr, port }
        }
        10 => {
            let p = need(payload, 4, "tcp ok")?;
            Frame::TcpOpenOk {
                id: u32::from_be_bytes(p[..4].try_into().unwrap()),
            }
        }
        11 => {
            let p = need(payload, 6, "tcp fail")?;
            Frame::TcpOpenFail {
                id: u32::from_be_bytes(p[..4].try_into().unwrap()),
                code: u16::from_be_bytes(p[4..6].try_into().unwrap()),
            }
        }
        12 => {
            let p = need(payload, 4, "tcp data")?;
            Frame::TcpData {
                id: u32::from_be_bytes(p[..4].try_into().unwrap()),
                data: p[4..].to_vec(),
            }
        }
        13 => {
            let p = need(payload, 4, "tcp close")?;
            Frame::TcpClose {
                id: u32::from_be_bytes(p[..4].try_into().unwrap()),
            }
        }
        14 => {
            let (id, addr, port, data) = decode_endpoint(payload)?;
            Frame::Udp {
                id,
                addr,
                port,
                data: data.to_vec(),
            }
        }
        15 => {
            let p = need(payload, 4, "udp reply")?;
            Frame::UdpReply {
                id: u32::from_be_bytes(p[..4].try_into().unwrap()),
                data: p[4..].to_vec(),
            }
        }
        _ => return Err(DecodeError::Malformed("unknown type")),
    };
    Ok((frame, 10 + len))
}

fn decode_endpoint(payload: &[u8]) -> Result<(u32, IpAddr, u16, &[u8]), DecodeError> {
    let p = need(payload, 4, "flow id")?;
    let id = u32::from_be_bytes(p[..4].try_into().unwrap());
    let (addr, used) = decode_addr(&payload[4..])?;
    let rest = &payload[4 + used..];
    let rest = need(rest, 2, "port")?;
    let port = u16::from_be_bytes(rest[..2].try_into().unwrap());
    Ok((id, addr, port, &rest[2..]))
}

#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Frame>, DecodeError> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        loop {
            if self.buf.len() < 10 {
                break;
            }
            if &self.buf[0..4] != MAGIC {
                return Err(DecodeError::BadMagic);
            }
            let len = u32::from_be_bytes(self.buf[6..10].try_into().unwrap()) as usize;
            if len > MAX_PAYLOAD {
                return Err(DecodeError::TooLarge(len));
            }
            if self.buf.len() < 10 + len {
                break;
            }
            let (frame, n) = decode_one(&self.buf)?;
            self.buf.drain(..n);
            frames.push(frame);
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_frames() {
        let frames = vec![
            Frame::Hello {
                features: FEATURE_L4 | FEATURE_UDP,
                mode: MODE_L4,
                mtu: 1280,
            },
            Frame::HelloAck {
                features: FEATURE_L4,
                mode: MODE_L4,
                mtu: 1280,
            },
            Frame::Packet(vec![0x45, 0x00, 0x00, 0x1c]),
            Frame::Ping(42),
            Frame::Pong(42),
            Frame::Error {
                code: 7,
                message: "no tun".into(),
            },
            Frame::RoutesReq,
            Frame::Routes(vec![(Ipv4Addr::new(10, 1, 0, 0), 16)]),
            Frame::TcpOpen {
                id: 9,
                addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 443,
            },
            Frame::TcpOpen {
                id: 10,
                addr: "2001:db8::1".parse().unwrap(),
                port: 53,
            },
            Frame::TcpOpenOk { id: 9 },
            Frame::TcpOpenFail { id: 3, code: 111 },
            Frame::TcpData {
                id: 9,
                data: b"hello".to_vec(),
            },
            Frame::TcpClose { id: 9 },
            Frame::Udp {
                id: 4,
                addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 53,
                data: b"\x12\x34".to_vec(),
            },
            Frame::UdpReply {
                id: 4,
                data: b"\xab".to_vec(),
            },
        ];
        for frame in frames {
            let bytes = frame.encode().unwrap();
            let (decoded, n) = decode_one(&bytes).unwrap();
            assert_eq!(n, bytes.len());
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn decoder_splits_and_buffers() {
        let a = Frame::Ping(1).encode().unwrap();
        let b = Frame::Pong(2).encode().unwrap();
        let mut both = a.clone();
        both.extend(&b);
        let mut dec = FrameDecoder::default();
        assert!(dec.push(&both[..3]).unwrap().is_empty());
        let got = dec.push(&both[3..]).unwrap();
        assert_eq!(got, vec![Frame::Ping(1), Frame::Pong(2)]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(decode_one(b"NOPE______"), Err(DecodeError::BadMagic)));
        let mut bad = Frame::Ping(1).encode().unwrap();
        bad[4] = 9;
        assert!(matches!(decode_one(&bad), Err(DecodeError::BadVersion(9))));
        let mut huge = b"FXVN\x01\x04".to_vec();
        huge.extend_from_slice(&1_000_000u32.to_be_bytes());
        assert!(matches!(decode_one(&huge), Err(DecodeError::TooLarge(1_000_000))));
        let mut dec = FrameDecoder::default();
        assert!(dec.push(&huge).is_err());
    }
}
