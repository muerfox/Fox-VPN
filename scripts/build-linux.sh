#!/bin/sh
# Build the Linux binaries. Does not require sshuttle.
set -eu
cd "$(dirname "$0")/.."
. "$HOME/.cargo/env"
cargo test -p foxvpn --lib
cargo build -p foxvpn -p fox-desktop --release
echo "binaries:"
echo "  target/release/fox-desktop"
echo "  target/release/fox-cli"
echo "  target/release/fox-vpnd"
