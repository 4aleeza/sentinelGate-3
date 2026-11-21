#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required.' >&2; exit 1; }
mkdir -p evidence/logs
export SENTINELGATE_JWT_SECRET="${SENTINELGATE_JWT_SECRET:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"
bash scripts/topo_up.sh
bash scripts/sg-case-addresses.sh up
start_one() {
  local name=$1 ns=$2 addr=$3 port=$4 module=$5 pidfile="evidence/logs/$1.pid"
  if [[ -f $pidfile ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    echo "$name already running; checking health"
  else
    rm -f "$pidfile"
    { echo 'COMMAND: date -u'; date -u; echo "COMMAND: ip netns exec $ns /opt/venv/bin/uvicorn $module --host $addr --port $port --no-proxy-headers --forwarded-allow-ips '' --workers 1"; } >"evidence/logs/$name.log"
    ip netns exec "$ns" /opt/venv/bin/uvicorn "$module" --host "$addr" --port "$port" --no-proxy-headers --forwarded-allow-ips '' --workers 1 >>"evidence/logs/$name.log" 2>&1 &
    echo $! > "$pidfile"
  fi
  for i in {1..50}; do
    if [[ $name == backend ]]; then ip netns exec "$ns" ss -ltnH "sport = :$port" | grep -q . && { echo "$name listening"; return 0; }; else ip netns exec sg-client curl --interface 10.10.1.250 --noproxy '*' -fsS "http://$addr:$port/health" >/dev/null 2>&1 && { echo "$name healthy"; return 0; }; fi
    sleep 0.2
  done
  echo "$name failed health check; see evidence/logs/$name.log" >&2; return 1
}
start_one backend sg-backend "${SG_BACKEND_HOST:-10.10.4.10}" "${SG_BACKEND_PORT:-9000}" backend.app:app
start_one gateway sg-gateway "${SG_GATEWAY_HOST:-10.10.3.10}" "${SG_GATEWAY_PORT:-8000}" gateway.app:app
