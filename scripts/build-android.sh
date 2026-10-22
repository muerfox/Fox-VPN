#!/bin/sh
# Build the Android native library and a debug APK.
# Requires JDK 17, the Android SDK (ANDROID_HOME), and the NDK.
set -eu
cd "$(dirname "$0")/.."
. "$HOME/.cargo/env"

if [ -z "${JAVA_HOME:-}" ] && [ -x "$HOME/Android/jdk/bin/java" ]; then
    export JAVA_HOME="$HOME/Android/jdk"
fi

if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
    echo "ANDROID_HOME is not set. Install the Android SDK command-line tools and an NDK."
    exit 1
fi
SDK="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
NDK="${ANDROID_NDK_HOME:-$(echo "$SDK"/ndk/* | awk '{ print $1 }')}"
if [ ! -d "$NDK" ]; then
    echo "Android NDK not found. Set ANDROID_NDK_HOME."
    exit 1
fi

API=26
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
for pair in "aarch64-linux-android arm64-v8a aarch64-linux-android" "armv7-linux-androideabi armeabi-v7a armv7a-linux-androideabi" "x86_64-linux-android x86_64 x86_64-linux-android"; do
    set -- $pair
    rust_target="$1"
    abi_dir="$2"
    triple="$3"
    linker="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/${triple}${API}-clang"
    if [ ! -x "$linker" ]; then
        echo "NDK clang not found: $linker"
        exit 1
    fi
    upper=$(echo "$rust_target" | tr 'a-z-' 'A-Z_')
    lower=$(echo "$rust_target" | tr 'A-Z-' 'a-z_')
    ar="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
    env "CC_${lower}=$linker" "CC_${upper}=$linker" \
        "AR_${lower}=$ar" "AR_${upper}=$ar" \
        "CARGO_TARGET_${upper}_LINKER=$linker" \
        cargo build -p fox-android --release --target "$rust_target"
    mkdir -p "android/app/src/main/jniLibs/$abi_dir"
    cp "target/$rust_target/release/libfox_vpn.so" "android/app/src/main/jniLibs/$abi_dir/"
done

printf 'sdk.dir=%s\n' "$SDK" > android/local.properties
cd android
if [ -x ./gradlew ]; then
    ./gradlew assembleDebug
else
    GRADLE="${GRADLE:-}"
    if [ -z "$GRADLE" ] && command -v gradle >/dev/null 2>&1; then
        GRADLE=$(command -v gradle)
    fi
    if [ -z "$GRADLE" ] && [ -x "$HOME/Android/gradle/bin/gradle" ]; then
        GRADLE="$HOME/Android/gradle/bin/gradle"
    fi
    if [ -z "$GRADLE" ]; then
        echo "gradlew is missing and gradle is not installed."
        exit 1
    fi
    "$GRADLE" assembleDebug
fi
APK="app/build/outputs/apk/debug/app-debug.apk"
APKSIGNER=$(echo "$SDK"/build-tools/*/apksigner | awk '{ print $1 }')
if [ -x "$APKSIGNER" ] && [ -f "$HOME/.android/debug.keystore" ] && [ -f "$APK" ]; then
    # OxygenOS 10/11 on phones such as the Nord N100 looks for a JAR (v1) signature.
    signed="${APK%.apk}-signed.apk"
    "$APKSIGNER" sign --ks "$HOME/.android/debug.keystore" --ks-key-alias androiddebugkey \
        --ks-pass pass:android --key-pass pass:android \
        --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
        --out "$signed" "$APK"
    mv "$signed" "$APK"
fi
echo "android/app/build/outputs/apk/debug/app-debug.apk"
echo "Release: ./gradlew assembleRelease, then sign with apksigner."
