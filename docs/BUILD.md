# Builds

One command per platform. Run it from a machine that can compile for that platform. Do not treat a missing output file as a successful build.

## Linux binaries

```sh
./scripts/build-linux.sh
```

Requires Rust stable (the toolchain file pins `stable`), a C compiler, and the usual GTK-less EGL/GL libraries that `eframe` links. The script runs `cargo test -p foxvpn --lib` and then `cargo build -p foxvpn -p fox-desktop --release`.

The binaries need `/dev/net/tun`, `ip`, and either `resolvectl` or permission to rewrite `/etc/resolv.conf`. The kill switch needs `nft`. These are operating-system tools. They are not copied into the binary.

## Linux AppImage

```sh
./scripts/build-appimage.sh
```

Produces one file, `dist/Fox-VPN-x86_64.AppImage`. The staging directory is deleted after `appimagetool` finishes. If FUSE is unavailable, run it with `APPIMAGE_EXTRACT_AND_RUN=1`.

The file carries the fox icon as `.DirIcon`, as `fox-vpn.png`, and under `usr/share/icons/hicolor`. The desktop entry uses `Icon=fox-vpn` and `StartupWMClass=fox-vpn`, which matches the window id. On this machine the AppImage starts, opens an X11 window, and the 256 pixel icon is inside the desktop binary.

The AppImage bundles the three binaries and their non-libc shared libraries. It does not bundle a TUN driver, policy routing, or root. Before `pkexec`, the client copies `fox-cli` out of the AppImage mount, because root cannot read that FUSE filesystem. When `DISPLAY` is set, the window uses the X11 clipboard so a compositor without `ext-data-control` does not log a clipboard failure. The first connection still asks `pkexec` for permission.

## Windows

From Linux, with the Rust `x86_64-pc-windows-gnu` target and a mingw gcc named `x86_64-w64-mingw32-gcc`:

```sh
./scripts/build-windows.sh
```

On Windows:

```powershell
.\scripts\build-windows.ps1
```

Both commands write one file, `dist/Fox-VPN.exe`. Place the official amd64 `wintun.dll` from https://www.wintun.net/ at `third_party/wintun/amd64/wintun.dll` before building, and compare it with the checksum on that site. The executable contains that DLL. Wintun is a signed driver library and has to be loaded from disk, so the first connection writes `wintun.dll` beside the exe. No other Fox-VPN DLL is required. `libgcc` and `winpthread` are linked statically.

On this machine `./scripts/build-windows.sh` produced `dist/Fox-VPN.exe` (PE32+ GUI, x86-64). It has not been started on Windows.

Sign it after you have a certificate:

```text
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\Fox-VPN.exe
```

The process must be elevated to create the adapter and the routes. The window can start unelevated and will report that elevation is required; on Windows the current worker uses an in-process session only when the process is already elevated, because `pkexec` does not exist there. Start the shortcut with "Run as administrator".

An MSI installer is not generated.

## Android

```sh
export JAVA_HOME="$HOME/Android/jdk"
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/<version>"
./scripts/build-android.sh
```

The script cross-compiles `libfox_vpn.so` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`, copies them into `android/app/src/main/jniLibs`, and runs `gradlew assembleDebug`.

Debug APK: `android/app/build/outputs/apk/debug/app-debug.apk`.

Release:

```sh
cd android && ./gradlew assembleRelease
apksigner sign --ks your.keystore android/app/build/outputs/apk/release/app-release-unsigned.apk
```

Minimum SDK 26, target SDK 34. The manifest declares `INTERNET`, a `specialUse` foreground service, and notifications. The activity calls `VpnService.prepare` and stops if the user denies it.

On this machine the command produced `android/app/build/outputs/apk/debug/app-debug.apk` (debug-signed by the Android SDK). It contains `libfox_vpn.so` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`. It has not been installed on a device or emulator. The native libraries are unstripped; the packager reported that it could not strip them and included them as built.

## Remote helper

On a server you administer, as root, after `./scripts/build-linux.sh`:

```sh
./scripts/install-remote.sh
```

Leave `remote_command` empty to use the embedded Python helper instead. That path needs `python3` on the server and does not need a copied binary. Full IP mode must be root on the server. TCP-and-DNS mode needs neither helper, only `AllowTcpForwarding`.
