#!/bin/sh
# Install the Fox-VPN remote helper on a server you administer.
# The desktop client can also run the embedded Python helper without this
# install, as long as python3 is on the server.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root so the helper can install fox-vpnd and, for full IP mode, configure TUN and NAT."
    exit 1
fi
install -d -m 0755 /usr/local/libexec/fox-vpn /usr/local/bin
if [ -x ./target/release/fox-vpnd ]; then
    install -m 0755 ./target/release/fox-vpnd /usr/local/bin/fox-vpnd
    echo "Installed /usr/local/bin/fox-vpnd"
    echo "Set the profile remote command to: fox-vpnd --stdio"
else
    echo "fox-vpnd was not found. The client will send the embedded Python helper instead."
fi
echo
echo "OpenSSH must allow the account to exec that command."
echo "TCP and DNS mode (ssh_direct) does not need this helper. It needs AllowTcpForwarding yes."
echo "Full IP mode (helper_l3) must run as root and uses /dev/net/tun, ip_forward, and iptables NAT."
echo "The helper only accepts FoxTunnel frames. It does not run shell commands from the client."
