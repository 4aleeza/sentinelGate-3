#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p evidence/logs
export SENTINELGATE_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SG_RUN_TOKEN_VALID="$(python scripts/mint_token.py valid)"
export SG_RUN_TOKEN_MONITOR="$(python scripts/mint_token.py monitor)"
export SG_RUN_TOKEN_WRONG_SIGNATURE="$(python scripts/mint_token.py wrong-signature)"
export SG_BUCKET_REFILL_PER_SECOND=0.001 SG_BAN_BASE_SECONDS=2
exec > >(tee evidence/logs/stage4_run.txt) 2>&1
echo 'COMMAND: date -u'; date -u
echo 'Overrides: SG_BUCKET_REFILL_PER_SECOND=0.001 SG_BAN_BASE_SECONDS=2'
cleanup() { bash scripts/sg-case-addresses.sh down || true; bash scripts/stage2_down.sh || true; bash scripts/topo_down.sh || true; }
trap cleanup EXIT
result=0
echo 'COMMAND: bash scripts/stage2_up.sh'
bash scripts/stage2_up.sh || result=$?
if (( result == 0 )); then
  echo 'COMMAND: ip netns exec sg-client python scripts/stage4_live.py'
  ip netns exec sg-client python scripts/stage4_live.py || result=$?
  echo 'COMMAND: ip netns exec sg-client python scripts/stage4_extended.py'
  ip netns exec sg-client python scripts/stage4_extended.py || result=$?
fi
echo 'COMMAND: bash scripts/sg-case-addresses.sh down'; bash scripts/sg-case-addresses.sh down || result=$?
echo 'COMMAND: bash scripts/stage2_down.sh'; bash scripts/stage2_down.sh || result=$?
echo 'COMMAND: bash scripts/topo_down.sh'; bash scripts/topo_down.sh || result=$?
echo 'COMMAND: bash scripts/run_stage1_checks.sh'; bash scripts/run_stage1_checks.sh || result=$?
trap - EXIT
scan_result=0
{
  echo 'COMMAND: grep -rFlI -- "$credential" . (for the run secret and each minted token, after teardown and Stage 1 cleanup)'
  date -u
  for credential in "$SENTINELGATE_JWT_SECRET" "$SG_RUN_TOKEN_VALID" "$SG_RUN_TOKEN_MONITOR" "$SG_RUN_TOKEN_WRONG_SIGNATURE"; do
    grep -rFlI -- "$credential" . && scan_result=1 || { code=$?; if (( code != 1 )); then echo "grep error: $code"; scan_result=1; fi; }
  done
  if (( scan_result == 0 )); then echo 'PASS: no run secret or minted token found in repository, including evidence and logs'; else echo 'FAIL: credential found or grep failed'; fi
} > evidence/logs/stage4_secret_scan.txt
cat evidence/logs/stage4_secret_scan.txt
unset credential SENTINELGATE_JWT_SECRET SG_RUN_TOKEN_VALID SG_RUN_TOKEN_MONITOR SG_RUN_TOKEN_WRONG_SIGNATURE
(( scan_result == 0 )) || result=1
exit "$result"
