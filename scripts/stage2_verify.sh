#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p evidence/logs evidence/captures/stage2
export SENTINELGATE_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export SG_BUCKET_CAPACITY=100 SG_BUCKET_REFILL_PER_SECOND=100
token="$(python scripts/mint_token.py valid)"
log=evidence/logs/stage2_integration.txt
exec > >(tee "$log") 2>&1
echo 'COMMAND: date -u'; date -u
echo 'Overrides: SG_BUCKET_CAPACITY=100 SG_BUCKET_REFILL_PER_SECOND=100'
echo 'Credentials are generated in memory; client-side captures use snaplen 64.'
echo 'COMMAND: pytest -q'
{ echo 'COMMAND: date -u'; date -u; echo 'COMMAND: pytest -q'; python -m pytest -q; } 2>&1 | tee evidence/logs/stage2_pytest.txt
echo 'COMMAND: bash scripts/stage2_up.sh'; bash scripts/stage2_up.sh
cleanup() { bash scripts/stage2_down.sh || true; bash scripts/topo_down.sh || true; }
trap cleanup EXIT
for path in health ready api/info; do
  echo "COMMAND: ip netns exec sg-client curl -i http://10.10.3.10:8000/$path"
  if [[ $path == health ]]; then source_ip=10.10.1.250; else source_ip=10.10.1.10; fi
  ip netns exec sg-client curl --interface "$source_ip" --noproxy '*' -isS -H "Authorization: Bearer $token" "http://10.10.3.10:8000/$path"
done
info=$(ip netns exec sg-client curl --noproxy '*' -fsS -H "Authorization: Bearer $token" http://10.10.3.10:8000/api/info)
echo "COMMAND: verify /api/info peer and X-Forwarded-For with jq; response: $info"
jq -e '.peer_host == "10.10.4.1" and .x_forwarded_for == "10.10.1.10"' <<<"$info"
echo 'COMMAND: ip netns exec sg-client curl -i -X POST -H Content-Type:application/json -d {"test":true} http://10.10.3.10:8000/api/echo'
ip netns exec sg-client curl --noproxy '*' -isS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"test":true}' http://10.10.3.10:8000/api/echo
echo 'COMMAND: ip netns exec sg-client curl --connect-timeout 3 http://10.10.4.10:9000/health (failure expected)'
if ip netns exec sg-client curl --noproxy '*' --connect-timeout 3 -sS http://10.10.4.10:9000/health; then echo 'FAIL backend reachable'; exit 1; else echo 'PASS direct backend connection failed'; fi
for ns in sg-client sg-r1 sg-r2 sg-gateway; do echo "COMMAND: ip netns exec $ns sysctl net.ipv4.ip_forward"; ip netns exec "$ns" sysctl net.ipv4.ip_forward; done
echo 'COMMAND: ip netns exec sg-client sysctl net.ipv4.ip_default_ttl'; ip netns exec sg-client sysctl net.ipv4.ip_default_ttl
for ns in sg-client sg-gateway; do [[ $(ip netns exec "$ns" sysctl -n net.ipv4.ip_forward) == 0 ]]; done
for ns in sg-r1 sg-r2; do [[ $(ip netns exec "$ns" sysctl -n net.ipv4.ip_forward) == 1 ]]; done
echo 'COMMAND: ip netns exec sg-client python scripts/concurrency.py'
ip netns exec sg-client python scripts/concurrency.py | tee evidence/logs/stage2_concurrency.json
jq -e '.total_ms < 5000 and (.results | length == 50 and all(.status == 200))' evidence/logs/stage2_concurrency.json
cap=evidence/captures/stage2
echo 'COMMAND: tshark captures on sg-r1/sg-r11, sg-gateway/sg-g0, sg-gateway/sg-g1'
ip netns exec sg-r1 tshark -i sg-r11 -s 64 -f tcp -a duration:30 -w "$cap/inter-router.pcapng" >"$cap/inter-router-capture.log" 2>&1 & p1=$!
ip netns exec sg-gateway tshark -i sg-g0 -s 64 -f tcp -a duration:30 -w "$cap/gateway-client.pcapng" >"$cap/gateway-client-capture.log" 2>&1 & p2=$!
ip netns exec sg-gateway tshark -i sg-g1 -f tcp -a duration:30 -w "$cap/gateway-backend.pcapng" >"$cap/gateway-backend-capture.log" 2>&1 & p3=$!
for i in {1..100}; do
  if grep -q 'Capturing on' "$cap/inter-router-capture.log" && grep -q 'Capturing on' "$cap/gateway-client-capture.log" && grep -q 'Capturing on' "$cap/gateway-backend-capture.log"; then break; fi
  sleep 0.1
done
for file in inter-router gateway-client gateway-backend; do grep -q 'Capturing on' "$cap/$file-capture.log" || { echo "Capture $file did not start" >&2; exit 1; }; done
sleep 2
echo 'COMMAND: ip netns exec sg-client curl http://10.10.3.10:8000/api/info'
ip netns exec sg-client curl --noproxy '*' -fsS -H "Authorization: Bearer $token" http://10.10.3.10:8000/api/info; echo
sleep 2
kill -INT "$p1" "$p2" "$p3"
wait "$p1" || true; wait "$p2" || true; wait "$p3" || true
for file in inter-router gateway-client gateway-backend; do
  echo 'COMMAND: date -u' >"$cap/$file-summary.txt"; date -u >>"$cap/$file-summary.txt"
  echo "COMMAND: tshark -r $cap/$file.pcapng -T fields -E header=y -E separator=, -e frame.time -e ip.src -e ip.dst -e ip.ttl -e tcp.srcport -e tcp.dstport -e tcp.stream -e tcp.flags -e http.request.method -e http.request.uri -e http.response.code" >>"$cap/$file-summary.txt"
  tshark -r "$cap/$file.pcapng" -T fields -E header=y -E separator=, -e frame.time -e ip.src -e ip.dst -e ip.ttl -e tcp.srcport -e tcp.dstport -e tcp.stream -e tcp.flags -e http.request.method -e http.request.uri -e http.response.code >>"$cap/$file-summary.txt" 2>>"$cap/$file-summary.txt"
  cat "$cap/$file-capture.log"
done
echo 'COMMAND: inspect routed and backend TCP packets (streams may already be open)'
tshark -r "$cap/inter-router.pcapng" -Y 'ip.src==10.10.1.10 && ip.dst==10.10.3.10 && tcp.dstport==8000' -T fields -e ip.ttl -e tcp.stream
tshark -r "$cap/gateway-backend.pcapng" -Y 'ip.src==10.10.4.1 && ip.dst==10.10.4.10 && tcp.dstport==9000' -T fields -e ip.src -e ip.dst -e tcp.stream
[[ -n $(tshark -r "$cap/inter-router.pcapng" -Y 'ip.src==10.10.1.10 && ip.dst==10.10.3.10 && tcp.dstport==8000 && ip.ttl < 64' -T fields -e ip.ttl 2>/dev/null) ]] || { echo 'FAIL: no routed packet with reduced TTL'; exit 1; }
[[ -n $(tshark -r "$cap/gateway-client.pcapng" -Y 'ip.src==10.10.1.10 && ip.dst==10.10.3.10 && tcp.dstport==8000' -T fields -e ip.src 2>/dev/null) ]] || { echo 'FAIL: gateway client-side capture lacks request'; exit 1; }
[[ -n $(tshark -r "$cap/gateway-backend.pcapng" -Y 'ip.src==10.10.4.1 && ip.dst==10.10.4.10 && tcp.dstport==9000 && http.request.method=="GET"' -T fields -e http.request.method 2>/dev/null) ]] || { echo 'FAIL: backend capture lacks forwarded HTTP request'; exit 1; }
if tshark -r "$cap/gateway-backend.pcapng" -Y 'ip.src==10.10.1.10' -T fields -e ip.src 2>/dev/null | grep -q .; then echo 'FAIL client source seen on backend link'; exit 1; fi
echo 'COMMAND: grep -rFl -- "$SENTINELGATE_JWT_SECRET" . and grep -rFl -- "$token" . (matches not printed)'
if grep -rFl -- "$SENTINELGATE_JWT_SECRET" . >/dev/null || grep -rFl -- "$token" . >/dev/null; then
  echo 'FAIL: run credential detected in project files'; exit 1
fi
echo 'PASS: run credential strings absent from searched files'
echo 'COMMAND: bash scripts/stage2_down.sh'; bash scripts/stage2_down.sh
echo 'COMMAND: bash scripts/topo_down.sh'; bash scripts/topo_down.sh
echo 'COMMAND: ip netns list; ip -o link show'; ip netns list; ip -o link show
if ip netns list | grep -Eq '^sg-(client|r1|r2|gateway|backend)( |$)'; then echo 'FAIL namespaces remain'; exit 1; fi
echo 'Stage 2 cleanup passed.'
trap - EXIT
