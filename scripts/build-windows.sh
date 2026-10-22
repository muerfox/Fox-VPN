#!/bin/sh
# Cross-compile one Windows executable from Linux.
# Needs the Rust x86_64-pc-windows-gnu target and a mingw gcc named
# x86_64-w64-mingw32-gcc (this machine uses a user-local llvm-mingw).
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi
if [ -d "$HOME/toolchains/llvm-mingw/bin" ]; then
    PATH="$HOME/toolchains/llvm-mingw/bin:$PATH"
    # Rust's windows-gnu target asks for libgcc. llvm-mingw ships compiler-rt and libunwind under other names.
    MINGW_LIB="$HOME/toolchains/llvm-mingw/x86_64-w64-mingw32/lib"
    BUILTINS="$(echo "$HOME/toolchains/llvm-mingw"/lib/clang/*/lib/windows/libclang_rt.builtins-x86_64.a)"
    if [ -f "$MINGW_LIB/libunwind.a" ] && [ -f "$BUILTINS" ]; then
        ln -sfn "$MINGW_LIB/libunwind.a" "$MINGW_LIB/libgcc_eh.a"
        ln -sfn "$BUILTINS" "$MINGW_LIB/libgcc.a"
    fi
fi
if [ -d "$HOME/toolchains/nasm/bin" ]; then
    PATH="$HOME/toolchains/nasm/bin:$PATH"
fi
export PATH
if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "x86_64-w64-mingw32-gcc is not on PATH" >&2
    exit 1
fi
if [ ! -f "$ROOT/third_party/wintun/amd64/wintun.dll" ]; then
    echo "third_party/wintun/amd64/wintun.dll is missing. Download the official build from https://www.wintun.net/" >&2
    exit 1
fi
export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
rustup target add x86_64-pc-windows-gnu
cargo build -p fox-desktop --release --target x86_64-pc-windows-gnu
mkdir -p "$ROOT/dist"
cp "$ROOT/target/x86_64-pc-windows-gnu/release/fox-desktop.exe" "$ROOT/dist/Fox-VPN.exe"
echo "$ROOT/dist/Fox-VPN.exe"
