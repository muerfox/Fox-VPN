# FoxTunnel v1

The default transport does not use this protocol. It uses SSH `direct-tcpip` and DNS-over-TCP, which a normal OpenSSH server already implements when `AllowTcpForwarding` is enabled.

Helper modes use one SSH exec channel and the frames below. A frame is:

```
4 bytes  magic "FXVN"
1 byte   version (1)
1 byte   type
4 bytes  payload length, big endian
N bytes  payload (at most 65535)
```

| Type | Name | Payload |
| --- | --- | --- |
| 1 | Hello | u32 features, u8 mode, u16 mtu |
| 2 | HelloAck | same layout. Mode 0 means the helper refused the request. |
| 3 | Packet | raw IPv4 packet, L3 only |
| 4 | Ping | u64 |
| 5 | Pong | u64 |
| 6 | Error | u16 code, then the rest of the payload as a UTF-8 message |
| 7 | RoutesReq | empty |
| 8 | Routes | repeated IPv4 address and prefix length |
| 9 | TcpOpen | u32 id, u8 address length (4 or 16), address, u16 port |
| 10 | TcpOpenOk | u32 id |
| 11 | TcpOpenFail | u32 id, u16 code |
| 12 | TcpData | u32 id, bytes |
| 13 | TcpClose | u32 id |
| 14 | Udp | u32 id, address, u16 port, bytes |
| 15 | UdpReply | u32 id, bytes |

Feature bits: L3 = 1, L4 = 2, routes = 4, UDP = 8.

The client sends Hello with mode L4 (2) or L3 (1). HelloAck mode 0 is a hard failure. The client does not fall back to `direct-tcpip` after that.

The route command is fixed: `ip -4 route show`. Returned prefixes are parsed as CIDRs. Default routes, loopback, link-local, multicast, the tunnel prefix `10.77.0.0/24`, and any token with shell metacharacters are dropped. At most 256 prefixes are kept.

L3, when the helper is root and `/dev/net/tun` exists, creates `foxsrv0` at `10.77.0.1/24` with MTU 1280, sets `ip_forward` and disables reverse-path filtering on that interface, and adds an iptables NAT chain named `FOXVPN` with MASQUERADE plus a TCP MSS clamp. The chain is removed when the helper exits.

The helper never executes a command string taken from a frame.
