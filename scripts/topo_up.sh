#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root privileges required.' >&2; exit 1; }
names=(sg-client sg-r1 sg-r2 sg-gateway sg-backend)
existing=0
for ns in "${names[@]}"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then existing=$((existing+1)); fi
done
if (( existing )); then
  if (( existing == ${#names[@]} )) && bash "$(dirname "$0")/verify_topo.sh"; then
    echo 'Existing topology verified; no changes made.'; exit 0
  fi
  echo 'Project namespaces already exist but are incomplete or failed verification; no changes made.' >&2; exit 1
fi
created=()
cleanup() { for ns in "${created[@]}"; do ip netns del "$ns" || true; done; }
trap cleanup ERR
for ns in "${names[@]}"; do ip netns add "$ns"; created+=("$ns"); ip -n "$ns" link set lo up; done
link() {
  local a=$1 b=$2 na=$3 nb=$4 aa=$5 ab=$6
  ip link add "$a" type veth peer name "$b"
  ip link set "$a" netns "$na"; ip link set "$b" netns "$nb"
  ip -n "$na" addr add "$aa" dev "$a"; ip -n "$nb" addr add "$ab" dev "$b"
  ip -n "$na" link set "$a" up; ip -n "$nb" link set "$b" up
}
link sg-c0 sg-r10 sg-client sg-r1 10.10.1.10/24 10.10.1.1/24
link sg-r11 sg-r20 sg-r1 sg-r2 10.10.2.1/24 10.10.2.2/24
link sg-r21 sg-g0 sg-r2 sg-gateway 10.10.3.1/24 10.10.3.10/24
link sg-g1 sg-b0 sg-gateway sg-backend 10.10.4.1/24 10.10.4.10/24
for ns in sg-r1 sg-r2; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1; done
for ns in sg-client sg-gateway sg-backend; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=0; done
ip -n sg-client route add default via 10.10.1.1
ip -n sg-r1 route add 10.10.3.0/24 via 10.10.2.2
ip -n sg-r2 route add 10.10.1.0/24 via 10.10.2.1
ip -n sg-gateway route add 10.10.1.0/24 via 10.10.3.1
ip -n sg-backend route add default via 10.10.4.1
trap - ERR
echo 'Topology created.'
