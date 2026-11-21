#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p evidence/archive evidence/logs evidence/captures/stage3 evidence/routing
stamp=$(date -u +%Y%m%dT%H%M%SZ)
archive="evidence/archive/$stamp"
[[ ! -e "$archive" ]] || { echo 'Archive already exists' >&2; exit 1; }
mkdir "$archive"
cp -a evidence/logs evidence/routing evidence/captures "$archive/"
export SENTINELGATE_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SG_BAN_BASE_SECONDS=10 SG_BUCKET_REFILL_PER_SECOND=0.001
log=evidence/logs/stage3_run.txt
exec > >(tee "$log") 2>&1
echo 'COMMAND: date -u'; date -u
echo 'Overrides: SG_BAN_BASE_SECONDS=10 SG_BUCKET_REFILL_PER_SECOND=0.001'
cleanup() { bash scripts/sg-case-addresses.sh down || true; bash scripts/stage2_down.sh || true; bash scripts/topo_down.sh || true; }
trap cleanup EXIT
echo 'COMMAND: bash scripts/stage2_up.sh'; bash scripts/stage2_up.sh
echo 'COMMAND: ip netns exec sg-client python scripts/stage3_cases.py'; ip netns exec sg-client python scripts/stage3_cases.py
status=$?
echo 'COMMAND: bash scripts/sg-case-addresses.sh down'; bash scripts/sg-case-addresses.sh down
echo 'COMMAND: bash scripts/stage2_down.sh'; bash scripts/stage2_down.sh
echo 'COMMAND: bash scripts/topo_down.sh'; bash scripts/topo_down.sh
echo 'COMMAND: ip netns list; ip -o link show'; ip netns list; ip -o link show
if ip netns list | grep -Eq '^sg-'; then echo 'FAIL namespace remains'; exit 1; fi
if ip -o link show | grep -Eq '[0-9]+: sg-'; then echo 'FAIL interface remains'; exit 1; fi
echo 'COMMAND: bash scripts/run_stage1_checks.sh'; bash scripts/run_stage1_checks.sh
trap - EXIT
exit "$status"