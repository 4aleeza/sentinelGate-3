#!/usr/bin/env bash
set -Eeuo pipefail
cd /work
export SENTINELGATE_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SG_BUCKET_REFILL_PER_SECOND=0.001
export SG_BAN_BASE_SECONDS=30
mkdir -p evidence/captures/stage5 evidence/routing/stage5
stamp=$(date -u +%Y%m%dT%H%M%SZ)
export STAGE5_DIR="evidence/captures/stage5/$stamp"
mkdir -p "$STAGE5_DIR"
exec > >(tee "$STAGE5_DIR/run.txt") 2>&1
echo 'COMMAND: date -u'; date -u
mkdir -p "$STAGE5_DIR/prior_service_logs"
for file in evidence/logs/gateway.log evidence/logs/backend.log; do
  [[ ! -f $file ]] || cp -p "$file" "$STAGE5_DIR/prior_service_logs/"
done
echo 'COMMAND: bash scripts/stage2_up.sh'
echo 'Overrides: SG_BUCKET_REFILL_PER_SECOND=0.001 SG_BAN_BASE_SECONDS=30'
cleanup() { bash scripts/sg-case-addresses.sh down || true; bash scripts/stage2_down.sh || true; bash scripts/topo_down.sh || true; }
trap cleanup EXIT
bash scripts/stage2_up.sh
echo 'COMMAND: python scripts/stage5_capture.py'
status=0
python scripts/stage5_capture.py || status=$?
if (( status == 0 )); then
  echo 'COMMAND: python scripts/stage5_analyze.py $STAGE5_DIR'
  python scripts/stage5_analyze.py "$STAGE5_DIR" || status=$?
fi
echo 'COMMAND: bash scripts/sg-case-addresses.sh down'; bash scripts/sg-case-addresses.sh down || status=$?
echo 'COMMAND: bash scripts/stage2_down.sh'; bash scripts/stage2_down.sh || status=$?
echo 'COMMAND: bash scripts/topo_down.sh'; bash scripts/topo_down.sh || status=$?
echo 'COMMAND: ip netns list'; ip netns list
echo 'COMMAND: ip -o link show'; ip -o link show
echo 'COMMAND: ip -o addr show'; ip -o addr show
echo 'COMMAND: pgrep -a -f "[d]umpcap|[t]shark"'; pgrep -a -f '[d]umpcap|[t]shark' || true
if ip netns list | grep -Eq '^sg-' || ip -o link show | grep -Eq '[0-9]+: sg-' || pgrep -f '[d]umpcap|[t]shark' >/dev/null; then echo 'FAIL: cleanup remnants'; status=1; else echo 'PASS: no sg namespaces, interfaces or capture processes'; fi
echo 'COMMAND: grep -a -rFl -- "$SENTINELGATE_JWT_SECRET" evidence'
if grep -a -rFl -- "$SENTINELGATE_JWT_SECRET" evidence; then echo 'FAIL: run secret found'; status=1; else rc=$?; if (( rc == 1 )); then echo 'PASS: run secret absent from evidence including binary captures'; else echo "FAIL: grep error $rc"; status=1; fi; fi
echo 'COMMAND: python -m pytest -q'
{ echo 'COMMAND: python -m pytest -q'; date -u; python -m pytest -q; } > "$STAGE5_DIR/pytest.txt" 2>&1 || status=$?
cat "$STAGE5_DIR/pytest.txt"
unset SENTINELGATE_JWT_SECRET
trap - EXIT
exit "$status"
