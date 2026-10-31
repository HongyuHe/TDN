set -e
env ASSUME_ALWAYS_YES=yes pkg bootstrap -f
env ASSUME_ALWAYS_YES=yes pkg install -y botan3 gmake pkgconf
mkdir -p /root/tdn-freebsd-v3
cd /root/tdn-freebsd-v3
fetch -o strongswan-6.0.3.tar.bz2 https://download.strongswan.org/strongswan-6.0.3.tar.bz2
sha256 strongswan-6.0.3.tar.bz2
test "$(sha256 -q strongswan-6.0.3.tar.bz2)" = 288f2111f5c9f6ec85fc08fa835bf39232f5c4044969bb4de7b4335163b1efa9
tar -xjf strongswan-6.0.3.tar.bz2
cd strongswan-6.0.3
./configure --help > configure-help.txt
./configure --prefix=/usr/local --sysconfdir=/usr/local/etc --disable-defaults --enable-charon --enable-swanctl --enable-vici --enable-ikev2 --enable-kernel-pfkey --enable-kernel-pfroute --enable-socket-default --enable-botan --enable-random --enable-nonce --enable-pem --enable-x509 --enable-constraints --enable-revocation --enable-pubkey --enable-pkcs1 --enable-pkcs8 --enable-counters
gmake -j2
gmake install
uname -a
pkg info botan3
/usr/local/sbin/swanctl --version || test -x /usr/local/sbin/swanctl
ldd /usr/local/lib/ipsec/plugins/libstrongswan-botan.so
