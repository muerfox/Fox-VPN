# Security

## What is enforced

- SSH host keys are checked against `$XDG_CONFIG_HOME/fox-vpn/known_hosts`. Nothing is trusted on first use unless you accept that fingerprint. A changed key stays rejected until you choose Replace.
- The known_hosts file is mode `0600`. If root writes it, the worker changes the owner back to the user who started the UI.
- Profile YAML is mode `0600` and the directory is mode `0700`. The parser rejects embedded secrets.
- Passwords and passphrases go to Secret Service on Linux, Credential Manager on Windows, and EncryptedSharedPreferences on Android. The CLI can also read `FOX_VPN_PASSWORD`, `FOX_VPN_PASSPHRASE`, and `FOX_VPN_SOCKS_PASSWORD` from the environment. They are not accepted on the command line.
- The root worker is a fixed subcommand of `fox-cli`. It does not run a shell. Route and firewall commands are argument vectors. The nftables script is passed to `nft -f -` on stdin.
- The SSH server is not given a channel that executes attacker-controlled shell text. The helper command is the configured remote command or the embedded Python program.
- The SSH socket is kept out of the tunnel with a policy-routing mark on Linux, `protect()` on Android, and a host route on Windows.
- Public IP checks use HTTPS only (`https://api.ipify.org`, then `https://ifconfig.me/ip`) with redirects disabled.
- A failed tunnel does not switch to a cleartext proxy. The session returns an error and, on disconnect, restores the saved network state.
- Rollback state is `/run/fox-vpn/state.json`. `fox-cli repair` reapplies it after a crash.

## What is not enforced

- Default mode drops ICMP and non-DNS UDP inside the client. That is loss, not a leak, but it is also not full-tunnel IP.
- Applications that use DNS-over-HTTPS to their own servers still send that HTTPS through the tunnel only because TCP is captured. If you disable full tunnel, that traffic follows the split routes.
- The kill switch is optional and Linux-only in this version. It is an nftables output hook. Windows and Android do not get the same filter. On Android, lockdown mode in the system VPN settings is the comparable control, and the user has to enable it.
- Excluding the SSH server excludes every port on that address. A service on the SSH host is not covered by the tunnel.
- `pkexec` shows an authentication dialog. A user who can approve it can change routes. That is the privilege the tunnel needs.
- The elevation socket lives under `/tmp`. It is mode `0600` and peer-checked. A local attacker who is already that user can connect to it during the 180 second accept window. They already have that user's secrets.
- Host-key trust is TOFU plus an explicit prompt. Fox-VPN does not pin a CA.
- The Python helper on the server runs as the SSH user. L3 mode is root on the server and installs NAT. Install it only on a machine you administer. A malicious client that can authenticate can open TCP and UDP from that server, which is the point of the VPN, and can also ask for the server's IPv4 route table.
- Wintun is a third-party driver component. This repository does not audit or ship the DLL.
- Memory of passwords is wrapped in `Zeroizing` where the engine holds them. The GUI text fields are cleared after a successful keyring write. They are ordinary process memory until then.
- There is no code signing in the build scripts beyond printing the `signtool` and `apksigner` commands. Unsigned builds will warn on Windows and Android.

## Privilege

The GUI and `fox-cli connect` start unprivileged. They request elevation only when a TUN device and route changes are required. Android requests the VPN consent dialog instead of root. The engine returns an error if a desktop session is not elevated and no Android file descriptor was supplied.
