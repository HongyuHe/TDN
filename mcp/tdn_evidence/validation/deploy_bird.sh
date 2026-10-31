#!/usr/bin/env bash
set -euo pipefail
#* Run on a worker after building Twinet images/bird as tdn-evidence-bird:validation.
#* The names and subnet are reserved for this validation; existing MSC devices stay intact.
sudo -n docker network inspect tdn-evidence-bird >/dev/null 2>&1 || sudo -n docker network create --subnet 172.30.231.0/24 tdn-evidence-bird
for node in a b; do
  if [[ "$node" == a ]]; then index=1; peer=2; else index=2; peer=1; fi
  sudo -n docker inspect "tdn-evidence-bird-$node" >/dev/null 2>&1 || sudo -n docker run -d --name "tdn-evidence-bird-$node" --cap-add NET_ADMIN --network tdn-evidence-bird --ip "172.30.231.$((index+10))" tdn-evidence-bird:validation
  config=$(mktemp)
  cat > "$config" <<CONFIG
router id 10.77.$index.1;
protocol device {}
protocol direct { ipv4; interface "lo"; }
protocol kernel { ipv4 { import none; export filter { if net = 10.77.$peer.0/24 then accept; reject; }; }; }
protocol bgp peer { local as $((65000+index)); neighbor 172.30.231.$((peer+10)) as $((65000+peer)); ipv4 { import all; export filter { if net = 10.77.$index.0/24 then accept; reject; }; }; }
CONFIG
  sudo -n docker cp "$config" "tdn-evidence-bird-$node:/etc/bird/bird.conf"
  rm "$config"
  sudo -n docker exec "tdn-evidence-bird-$node" ip address replace "10.77.$index.1/24" dev lo
  sudo -n docker exec "tdn-evidence-bird-$node" sh -c 'birdc -r show status >/dev/null 2>&1 || bird -c /etc/bird/bird.conf'
done
