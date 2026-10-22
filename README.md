# Fox-VPN

Fox-VPN is an SSH tunnel with a graphical client for Linux, plus Android and Windows shells around the same engine. It captures traffic on a virtual interface and forwards it through an SSH session. It does not call `sshuttle`, and it does not need a system `ssh` binary.

The default mode works with a normal OpenSSH server. It forwards TCP, including DNS-over-TCP. It does not forward ICMP or arbitrary UDP. Full IP forwarding, including UDP, uses a helper that you install on a server you administer.

## Stack

| Piece | Choice | Why |
| --- | --- | --- |
| Shared engine | Rust | One implementation of SSH, framing, routing plans, and the userspace TCP/UDP stack for Linux, Windows, and Android. |
| SSH | `russh` 0.64 | Pure Rust. No system OpenSSH client. |
| Userspace stack | `ipstack` 1.0 | Turns packets from the virtual interface into TCP and UDP flows without a kernel protocol stack on that interface. |
| Virtual interface | `tun` 0.8 | Linux TUN, Android `VpnService` file descriptor, Windows Wintun. |
| Desktop UI | `eframe` / `egui` 0.37 | Immediate-mode UI that stays responsive while the tunnel runs on another thread. |
| Android UI | Kotlin `VpnService` | The platform API that is allowed to capture device traffic. It calls the Rust engine through JNI. |
| Secrets | `keyring` 4 | Linux Secret Service, Windows Credential Manager. Android uses `EncryptedSharedPreferences` backed by the Android Keystore. |
| Remote helper | Embedded Python, or `fox-vpnd` | Sent over one SSH exec channel. The client does not install `sshuttle` on either side. |

Shared code lives in `crates/foxvpn`. Platform code is the desktop window (`crates/fox-desktop`), the Android JNI crate (`crates/fox-android`) with the Kotlin service under `android/`, and the route/DNS/firewall commands in `crates/foxvpn/src/platform.rs`.

## What a connection actually does

`ssh_direct` (the default, labeled "SSH direct-tcpip (TCP and DNS)"):

1. The unprivileged UI reads the profile and loads secrets from the keyring.
2. On Linux it starts `fox-cli worker` through `pkexec`. The worker is root. The UI is not.
3. The worker opens a TUN device named `fox0` (`10.77.0.2/24`) and installs routes in policy table `7660`.
4. The SSH socket is marked `0x6670` and looked up in the main table, so the SSH connection is not routed into itself.
5. TCP flows are opened with SSH `direct-tcpip`. DNS queries to port 53 are sent as DNS-over-TCP to the configured resolvers (`1.1.1.1` and `8.8.8.8` by default).
6. ICMP and non-DNS UDP are captured and dropped. They are not leaked to the physical network, and they are not delivered through the tunnel.
7. Disconnect deletes the policy rules, restores DNS, and removes the kill-switch table.

`helper_l4` forwards TCP and UDP through the FoxTunnel helper. `helper_l3` forwards raw IP packets to a remote TUN and NATs them. Neither mode is selected automatically. If you ask for a helper and it cannot start, the connection fails.

Host-key verification is on. An unknown key waits for an explicit decision. A changed key is replaced only if you choose Replace.

## Build

```sh
./scripts/build-linux.sh
```

That runs the engine tests and writes:

- `target/release/fox-desktop`
- `target/release/fox-cli`
- `target/release/fox-vpnd`

Linux AppImage, Windows, and Android commands are in [docs/BUILD.md](docs/BUILD.md). On this machine `./scripts/build-appimage.sh` produced the single file `dist/Fox-VPN-x86_64.AppImage`, and `./scripts/build-windows.sh` produced the single file `dist/Fox-VPN.exe`. The Android release APK for the 32-bit phone build is `dist/FoxVPN.apk`. The exe has not been started on Windows.

## Run

Start the window as your normal user, not as root. Root cannot read your Secret Service keyring.

```sh
./target/release/fox-desktop
```

Enter the server, port (default 2222), username (default `root`), and either a private-key path or a password. Click Connect. Approve the privilege prompt. The prompt exists because changing routes requires administrator rights.

Command line, for a profile already saved by the window:

```sh
FOX_VPN_PASSWORD='…' ./target/release/fox-cli connect --profile "My SSH VPN" --accept-new-host-key
```

`--accept-new-host-key` trusts an unseen key. It does not accept a key that changed.

If a crash leaves routes behind:

```sh
pkexec ./target/release/fox-cli repair
```

## Configuration

Profiles are YAML in `$XDG_CONFIG_HOME/fox-vpn/config.yaml` (mode `0600`). The example is [examples/profile.example.yaml](examples/profile.example.yaml). Keys named `password`, `passphrase`, `private_key`, `key_data`, and `socks_password` are rejected. Secrets go to the system keyring under the service name `dev.muerfox.fox-vpn`.

Import a profile file:

```sh
./target/release/fox-cli check examples/profile.example.yaml
```

The example host `78.39.47.49` is a schema sample. The application does not contact it unless you save that profile and connect.

## Tests that have been run

`cargo test -p foxvpn --lib` on this machine: 21 passed. That includes framing, profile parsing, route planning (server bypass, kill switch, LAN exclusions, auto-net filtering), a Python helper TCP echo, password authentication against an in-process SSH server, a rejected password, a rejected changed host key, a closed port, and an SSH handshake timeout.

Not run here, because this environment has no passwordless root and no Android device:

- installing routes on a live TUN device
- a full-tunnel public-IP check through a remote server
- an Android emulator or device
- running `dist/Fox-VPN.exe` on Windows (it was linked here, not launched there)

The manual checklist is [docs/MANUAL_TESTS.md](docs/MANUAL_TESTS.md).

## Limits you should know before relying on it

- Default mode is not a full IP VPN. Ping will not work. QUIC and other UDP fall back to whatever the application does over TCP, or they fail.
- The whole SSH server address is excluded from the tunnel, not only the SSH port. Services on that host are reached directly.
- IPv6 is off by default. On Linux the worker installs a blackhole for `::/0` so IPv6 does not bypass the tunnel. It is not forwarded.
- The kill switch is an nftables output filter. It is off by default. When it is on, it also blocks LAN traffic that is not the SSH server.
- An AppImage cannot include the kernel TUN driver. `/dev/net/tun` and administrator rights are still required.
- Windows embeds the official `wintun.dll` and writes that file beside `Fox-VPN.exe` when a tunnel opens. The driver DLL cannot live only inside the executable. Check the published Wintun checksum before you build.
- Android split-tunnel prefixes are the ones you type. Discovered remote networks are not applied, because `VpnService` routes are fixed when the interface is created, which is before the SSH session can ask the server for routes.
- Android lockdown (a kill switch that survives the app) is a system VPN setting. The app does not silently turn it on.

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/SECURITY.md](docs/SECURITY.md).
