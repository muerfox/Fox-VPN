# Architecture

## Processes

```
fox-desktop (user)
    reads the keyring
    shows status, logs, host-key decisions
    pkexec
fox-cli worker (root)
    SSH session
    TUN fox0
    policy routing table 7660
    DNS and optional nftables kill switch
```

The user process and the root process talk over a socket in `/tmp/fox-vpn-<uid>/worker.sock`. The directory is mode `0700` and the socket is mode `0600`. The worker checks `SO_PEERCRED` and accepts only uid 0 or the invoking user. The request is one JSON line. It is not placed in argv. Events come back as JSON lines. A host-key prompt is answered with a second JSON line.

If the process is already root, the same session runs in-process. Starting the GUI with `sudo` is the wrong way to elevate: Secret Service is per user, and root will not see the passwords stored for the user.

Android does not use this socket. `FoxVpnService` creates the interface with `VpnService.Builder`, then `NativeBridge` calls `protect(fd)` on the SSH socket before connect. The Rust session receives the TUN file descriptor and does not run `ip` or `nft`.

## Traffic path

`ipstack` reads IP packets from the TUN device and accepts TCP and UDP flows. A semaphore caps concurrent flows at 512. Each TCP flow opens an SSH `direct-tcpip` channel, or a FoxTunnel `TcpOpen` when a helper is selected. Copy tasks propagate backpressure by awaiting both directions. Closing either side closes the other.

DNS to UDP/53 is parsed enough to recover the query name for the log, then sent as a TCP DNS message to the first configured resolver. The system resolver is pointed at those same addresses on `fox0`, or `/etc/resolv.conf` is replaced when systemd-resolved is not the stub at `127.0.0.53`.

The SSH server's IPv4 address is installed as a `/32` via the original gateway inside table `7660`. A rule `fwmark 0x6670 lookup main priority 50` prefers the main table for the marked SSH socket. A second rule `lookup 7660 priority 100` sends everything else, including the default route `0.0.0.0/0 dev fox0 src 10.77.0.2`, into the tunnel. `exclude_lan` adds the RFC1918 prefixes via the original gateway. It is off by default so a full tunnel matches `0.0.0.0/0`.

Reconnect uses the socket addresses resolved before the tunnel came up. A later reconnect does not ask a resolver that now points into the tunnel. Authentication failures, host-key rejection, and configuration errors are not retried. Network loss is retried when the profile says so, with delays of 1, 2, 4, 8, and 16 seconds.

## Remote helper

The client opens one SSH exec channel. The command is either the profile's `remote_command` or `python3 -c` running the embedded helper (`crates/foxvpn/src/helper.py`). The Python program speaks FoxTunnel v1. It does not evaluate client strings as a shell. The route request runs `ip -4 route show` with an argument vector.

`fox-vpnd --stdio` is the Rust helper for the same L4 frames. Its L3 path is intentionally refused; the Python helper is the one that creates `foxsrv0`, enables forwarding, and installs the `FOXVPN` NAT chain. Run that as root. See `scripts/install-remote.sh`.

## Windows

The same engine builds route commands with `route.exe` and asks `tun` for a Wintun adapter. DNS is set with `netsh` on the adapter. `wintun.dll` has to sit next to the executable. This repository does not vendor that DLL.

## Android

`VpnService` owns the capture interface. Routes, DNS, and the IPv6 blackhole (`::/0` when IPv6 is disabled) are applied in Kotlin before the native session starts. The native session then only forwards. `protect` is what keeps the SSH socket out of the VPN. On API 33 and newer the service also calls `excludeRoute` for the server when the host field is an IPv4 address.

The foreground service type is `specialUse` with subtype `ssh_vpn`. Cleartext HTTP is disabled. The password, if remembered, is stored with `EncryptedSharedPreferences`.
