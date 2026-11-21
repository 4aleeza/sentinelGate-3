#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required' >&2; exit 1; }
mode=${1:-up}
mapfile -t addresses < <(python -c 'import json; print("\n".join(c["source_ip"] for c in json.load(open("tests/security_cases.json")))); print("10.10.1.250")')
for addr in "${addresses[@]}"; do
  [[ $addr =~ ^10\.10\.1\.[0-9]+$ ]] || { echo "Invalid case address $addr" >&2; exit 1; }
  if [[ $mode == up ]]; then
    ip -n sg-client -o -4 addr show dev sg-c0 | grep -Fq " $addr/24 " || ip -n sg-client addr add "$addr/24" dev sg-c0
  elif [[ $mode == down ]]; then
    if ip netns list | awk '{print $1}' | grep -Fxq sg-client && ip -n sg-client -o -4 addr show dev sg-c0 | grep -Fq " $addr/24 "; then ip -n sg-client addr del "$addr/24" dev sg-c0; fi
  else echo 'Usage: sg-case-addresses.sh up|down' >&2; exit 2; fi
done