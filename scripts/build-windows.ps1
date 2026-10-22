# Build one Windows executable. On Windows this uses the installed Rust toolchain.
# From Linux, use scripts/build-windows.sh instead.
# The official amd64 wintun.dll is compiled into the executable from
# third_party/wintun/amd64/wintun.dll and written beside the exe on startup.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not (Test-Path "third_party\wintun\amd64\wintun.dll")) {
    throw "third_party\wintun\amd64\wintun.dll is missing. Download the official build from https://www.wintun.net/"
}
cargo build -p fox-desktop --release
New-Item -ItemType Directory -Force -Path dist | Out-Null
Copy-Item target\release\fox-desktop.exe dist\Fox-VPN.exe
Write-Host "dist\Fox-VPN.exe"
Write-Host "Sign with: signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\Fox-VPN.exe"
