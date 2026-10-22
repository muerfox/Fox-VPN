# Manual verification

Automated coverage is `cargo test -p foxvpn --lib`. The checks below need a server you administer, and on Linux they need the privilege prompt. Do not point them at a host you do not operate. The address in `examples/profile.example.yaml` is only a schema example.

## Engine tests already executed

On the development machine, `cargo test -p foxvpn --lib` passed 21 tests:

- profile YAML parsing and rejection of plaintext password fields
- route planning, including the SSH server `/32` via the original gateway, the `0.0.0.0/0` tunnel route, the fwmark rule, LAN exclusions, the IPv6 blackhole, and the nftables kill-switch script
- FoxTunnel frame round-trip and rejection of bad frames
- Python helper TCP echo and the Rust helper TCP echo
- password authentication against a local SSH server
- rejected password
- changed host key rejected when the prompt answers Reject
- closed port reported as unreachable and not retried as a configuration error
- silent TCP peer reported as a timeout

## Before connecting

- [ ] `fox-desktop` starts as a normal user and shows Disconnected.
- [ ] A profile can be saved and reloaded. The YAML file contains no password.
- [ ] The system keyring holds the password after "Remember secrets" is checked. Confirm with the platform's secret tool, not by opening the YAML.
- [ ] `fox-cli check examples/profile.example.yaml` loads the file. Validation of the sample key path fails until that file exists. That is the intended check.

## Authentication

- [ ] A correct key or password reaches Connected.
- [ ] A wrong password shows an authentication error and does not change routes (`ip rule` has no table 7660).
- [ ] An unknown host key shows the fingerprint and does nothing until Trust or Reject.
- [ ] After trust, a replaced server key shows the changed-key dialog. Replace updates known_hosts. Reject leaves the old line in place.
- [ ] A closed port and a filtered port surface as unreachable or timed out, and the status returns to Error or Reconnecting according to the reconnect switch.

## Routing

Use a server with `AllowTcpForwarding yes` and the default transport.

- [ ] Before connect, note the public IP from the window (or from `curl https://api.ipify.org`).
- [ ] After connect, the public IP shown as "through tunnel" is the server's address, and `curl -4 https://api.ipify.org` matches it.
- [ ] `ip route get 1.1.1.1 mark 0` uses table 7660 and `fox0`. `ip route get <ssh-server>` still uses the original gateway.
- [ ] `ping` fails in `ssh_direct`. That is expected. Switch to `helper_l3` on a root helper before expecting ICMP.
- [ ] DNS: `resolvectl dns fox0` or `/etc/resolv.conf` lists the configured resolvers, and a lookup of a name that is not cached returns an address. Disconnect and confirm the previous resolver is restored.
- [ ] Split tunnel with one prefix routes only that prefix into `fox0`.
- [ ] Auto-nets adds the server's non-default IPv4 prefixes and does not add `0.0.0.0/0` twice or the tunnel's own `10.77.0.0/24`.
- [ ] With IPv6 disabled, `ip -6 route get 2001:4860:4860::8888` hits the blackhole.
- [ ] With the kill switch on, stopping the SSH process without a clean disconnect blocks other output until `fox-cli repair`. With the kill switch off, traffic returns to the normal gateway after disconnect.
- [ ] Disconnect removes table 7660, the fwmark rule, `fox0`, and the `foxvpn` nftables table.
- [ ] Pull the network cable or stop `sshd`. With reconnect on, the status becomes Reconnecting and recovers. With reconnect off, it stays on Error and the routes are gone.

## Privilege and packaging

- [ ] Launching the GUI without administrator rights shows the window. Connect then asks for elevation.
- [ ] A machine without `sshuttle` installed still connects. `command -v sshuttle` can fail.
- [ ] `./scripts/build-linux.sh` finishes and the three release binaries exist.

## Android

- [ ] The first Connect shows the system VPN consent. Deny it. The status says the permission was denied and no notification remains.
- [ ] Approve it. A foreground notification stays up while the native session runs.
- [ ] Force-stop the app. The VPN indicator disappears and traffic is no longer captured.
- [ ] Airplane mode mid-session ends or reconnects the native session, and `onRevoke` or process death removes the interface.

## Windows

- [ ] Without `wintun.dll` the connect path reports that the adapter could not be created and does not leave a permanent route.
- [ ] With the DLL and an elevated process, the adapter appears, the server route points at the original gateway, and disconnect deletes those routes.
