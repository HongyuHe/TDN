#!/bin/sh
set -eu
assets=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
target=$1
test -n "$target"
test ! -e "$target"
mkdir -p "$target"
cd "$target"
curl -fL -o wpa_supplicant-2.12.tar.gz https://w1.fi/releases/wpa_supplicant-2.12.tar.gz
echo '08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6  wpa_supplicant-2.12.tar.gz' | sha256sum -c -
tar -xzf wpa_supplicant-2.12.tar.gz
cd wpa_supplicant-2.12
patch -p1 < "$assets/final.patch"
cp "$assets/wpa_supplicant.config" wpa_supplicant/.config
make -C wpa_supplicant -j4
wpa_supplicant/wpa_supplicant -v
sha256sum wpa_supplicant/wpa_supplicant
ldd wpa_supplicant/wpa_supplicant
