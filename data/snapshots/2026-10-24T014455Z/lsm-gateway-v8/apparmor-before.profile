#include <tunables/global>
profile tdn-lsm-device-v8 flags=(attach_disconnected) {
  / r,
  /** rwklm,
  /{,usr/}{bin,sbin}/** ix,
  /usr/lib/ipsec/charon px -> tdn-lsm-gateway-v8,
  /usr/sbin/swanctl px -> tdn-lsm-gateway-v8,
  audit deny /etc/swanctl/private/** rwklm,
  deny /proc/*/mem rwklm,
  deny /proc/*/fd/** rwklm,
  deny /proc/*/map_files/** rwklm,
  network,
  capability,
  signal,
  deny ptrace,
}
profile tdn-lsm-gateway-v8 flags=(attach_disconnected) {
  file,
  network,
  capability,
  signal,
  deny ptrace,
}
