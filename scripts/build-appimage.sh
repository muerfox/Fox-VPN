#!/bin/sh
# Build a Linux AppImage from the release binaries.
# An AppImage can bundle this program and its shared libraries.
# It cannot bundle /dev/net/tun, nftables, or root privileges.
set -eu
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
. "$HOME/.cargo/env"
cargo build -p foxvpn -p fox-desktop --release

APP="$ROOT/dist/Fox-VPN.AppDir"
rm -rf "$APP"
mkdir -p "$APP/usr/bin" "$APP/usr/share/applications" "$APP/usr/lib" \
    "$APP/usr/share/icons/hicolor/256x256/apps" \
    "$APP/usr/share/icons/hicolor/128x128/apps"
cp target/release/fox-desktop target/release/fox-cli target/release/fox-vpnd "$APP/usr/bin/"
chmod 755 "$APP/usr/bin/"*

# Copy direct shared libraries other than the system libc and dynamic linker.
# linuxdeploy is preferable when it is installed; this fallback keeps the
# package usable on a machine with the same glibc.
copy_deps() {
    binary="$1"
    ldd "$binary" | awk '/=>/ { print $3 }' | while read -r lib; do
        case "$lib" in
            ""|linux-vdso*|/lib64/ld-linux*|/lib/ld-linux*) continue ;;
            *libc.so*|*libm.so*|*libdl.so*|*libpthread.so*|*librt.so*|*libresolv.so*) continue ;;
        esac
        if [ -f "$lib" ]; then
            cp -n "$lib" "$APP/usr/lib/" 2>/dev/null || cp "$lib" "$APP/usr/lib/"
        fi
    done
}
copy_deps "$APP/usr/bin/fox-desktop"
copy_deps "$APP/usr/bin/fox-cli"

cat > "$APP/fox-vpn.desktop" << 'EOF'
[Desktop Entry]
Name=Fox-VPN
Exec=fox-desktop
Icon=fox-vpn
Type=Application
Categories=Network;
StartupWMClass=fox-vpn
X-AppImage-Name=Fox-VPN
EOF
cp "$APP/fox-vpn.desktop" "$APP/usr/share/applications/"
cp "$ROOT/assets/fox-vpn-256.png" "$APP/fox-vpn.png"
cp "$ROOT/assets/fox-vpn-256.png" "$APP/.DirIcon"
cp "$ROOT/assets/fox-vpn-256.png" "$APP/usr/share/icons/hicolor/256x256/apps/fox-vpn.png"
cp "$ROOT/assets/fox-vpn-128.png" "$APP/usr/share/icons/hicolor/128x128/apps/fox-vpn.png"

cat > "$APP/AppRun" << 'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export PATH="$HERE/usr/bin:$PATH"
export LD_LIBRARY_PATH="$HERE/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export XDG_DATA_DIRS="$HERE/usr/share${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}"
export APPDIR="$HERE"
exec "$HERE/usr/bin/fox-desktop" "$@"
EOF
chmod 755 "$APP/AppRun"

TOOL=""
if command -v appimagetool >/dev/null 2>&1; then
    TOOL="appimagetool"
elif [ -x /tmp/appimagetool ]; then
    TOOL="/tmp/appimagetool"
fi
if [ -z "$TOOL" ]; then
    echo "appimagetool is not installed."
    echo "The AppDir is at $APP. Install appimagetool and rerun this script to produce the .AppImage."
    exit 1
fi
ARCH=x86_64 "$TOOL" "$APP" "$ROOT/dist/Fox-VPN-x86_64.AppImage"
rm -rf "$APP"
chmod 755 "$ROOT/dist/Fox-VPN-x86_64.AppImage"
echo "$ROOT/dist/Fox-VPN-x86_64.AppImage"
