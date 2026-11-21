#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p evidence/routing
exec > >(tee evidence/routing/stage3_address_verification.txt) 2>&1
echo 'COMMAND: date -u'; date -u
cleanup() { bash scripts/sg-case-addresses.sh down || true; bash scripts/stage2_down.sh || true; bash scripts/topo_down.sh || true; }
trap cleanup EXIT
echo 'COMMAND: bash scripts/stage2_up.sh'; bash scripts/stage2_up.sh
echo 'COMMAND: bash scripts/sg-case-addresses.sh up (idempotence check)'; bash scripts/sg-case-addresses.sh up
echo 'COMMAND: ip -n sg-client -4 addr show dev sg-c0'; ip -n sg-client -4 addr show dev sg-c0
mapfile -t addresses < <(python -c 'import json; print("\n".join(c["source_ip"] for c in json.load(open("tests/security_cases.json")))); print("10.10.1.250")')
for addr in "${addresses[@]}"; do
  echo "COMMAND: ip netns exec sg-client ping -c 1 -W 2 -I $addr 10.10.3.10"
  ip netns exec sg-client ping -c 1 -W 2 -I "$addr" 10.10.3.10
  echo "COMMAND: ip netns exec sg-client curl --noproxy '*' --interface $addr -fsS http://10.10.3.10:8000/health"
  ip netns exec sg-client curl --noproxy '*' --interface "$addr" -fsS http://10.10.3.10:8000/health; echo
done
echo 'COMMAND: bash scripts/sg-case-addresses.sh down'; bash scripts/sg-case-addresses.sh down
echo 'COMMAND: bash scripts/sg-case-addresses.sh down (idempotence check)'; bash scripts/sg-case-addresses.sh down
for addr in "${addresses[@]}"; do if ip -n sg-client -o -4 addr show dev sg-c0 | grep -Fq " $addr/24 "; then echo "FAIL address remains: $addr"; exit 1; fi; done
echo 'COMMAND: bash scripts/stage2_down.sh'; bash scripts/stage2_down.sh
echo 'COMMAND: bash scripts/topo_down.sh'; bash scripts/topo_down.sh
if ip netns list | grep -Eq '^sg-'; then echo 'FAIL sg namespace remains'; exit 1; fi
if ip -o link show | grep -Eq '[0-9]+: sg-'; then echo 'FAIL sg interface remains'; exit 1; fi
trap - EXIT
echo 'PASS: case addresses removed; no sg namespaces or root interfaces remain'