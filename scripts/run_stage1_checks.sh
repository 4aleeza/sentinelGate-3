#!/usr/bin/env bash
set -Eeuo pipefail
stamp=$(date -u +%Y%m%dT%H%M%SZ-%N)
mkdir -p evidence/logs evidence/routing
echo 'COMMAND: bash scripts/preflight.sh' | tee evidence/logs/preflight-$stamp.txt
bash scripts/preflight.sh 2>&1 | tee -a evidence/logs/preflight-$stamp.txt
echo 'COMMAND: bash scripts/topo_up.sh' | tee evidence/routing/topology-$stamp.txt
date -u | tee -a evidence/routing/topology-$stamp.txt
bash scripts/topo_up.sh 2>&1 | tee -a evidence/routing/topology-$stamp.txt
trap 'bash scripts/topo_down.sh || true' EXIT
echo 'COMMAND: bash scripts/verify_topo.sh' | tee -a evidence/routing/topology-$stamp.txt
bash scripts/verify_topo.sh 2>&1 | tee -a evidence/routing/topology-$stamp.txt
echo 'COMMAND: bash scripts/topo_up.sh (idempotence)' | tee -a evidence/routing/topology-$stamp.txt
bash scripts/topo_up.sh 2>&1 | tee -a evidence/routing/topology-$stamp.txt
echo 'COMMAND: bash scripts/topo_down.sh' | tee evidence/routing/cleanup-$stamp.txt
date -u | tee -a evidence/routing/cleanup-$stamp.txt
bash scripts/topo_down.sh 2>&1 | tee -a evidence/routing/cleanup-$stamp.txt
echo 'COMMAND: bash scripts/topo_down.sh (idempotence)' | tee -a evidence/routing/cleanup-$stamp.txt
bash scripts/topo_down.sh 2>&1 | tee -a evidence/routing/cleanup-$stamp.txt
echo 'COMMAND: ip netns list; ip -o link show' | tee -a evidence/routing/cleanup-$stamp.txt
ip netns list | tee -a evidence/routing/cleanup-$stamp.txt
ip -o link show | tee -a evidence/routing/cleanup-$stamp.txt
if ip netns list | awk '{print $1}' | grep -Eq '^sg-(client|r1|r2|gateway|backend)$'; then echo 'FAIL: namespace remains' | tee -a evidence/routing/cleanup-$stamp.txt; exit 1; fi
if ip -o link show | grep -Eq ': sg-(c0|r10|r11|r20|r21|g0|g1|b0)(@|:)'; then echo 'FAIL: interface remains' | tee -a evidence/routing/cleanup-$stamp.txt; exit 1; fi
echo 'Cleanup verification passed.' | tee -a evidence/routing/cleanup-$stamp.txt
trap - EXIT
