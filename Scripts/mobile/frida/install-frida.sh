#!/bin/bash

: <<'ENDBlock'
# Summary:
# ------------------------------
# Example: bash install-frida.sh
#
# Download and install frida-server on connected Android Device (based on current frida version).
#
# Authors:
#     Nick Serra
#
# Resources:
#   https://github.com/frida/frida/releases
ENDBlock

# Variables:
version="$(frida --version)"
download_path="$(pwd)/frida-server"
download_dir="$(dirname \"${download_path}\")"
target_CPU_arch="$(adb shell getprop ro.product.cpu.abi)"
download_url="https://github.com/frida/frida/releases/download/${version}/frida-server-${version}-android-x86.xz"
# download_url="https://github.com/frida/frida/releases/download/${version}/frida-server-${version}-ios-arm64.xz"

echo "Frida Version: ${version}"
echo "Target CPU Architecture: ${target_CPU_arch}"

mkdir -P "${download_dir}"
cd "${download_dir}"
# Download frida server
wget -O "${download_path}.xz" "${download_url}"
# uncompress frida-server
unxz "./frida-server.xz"
# Echo Check ADB Devices
adb devices -l
# adb root # might be required
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
sleep 3

# Check that frida server is running
frida-ps -U
