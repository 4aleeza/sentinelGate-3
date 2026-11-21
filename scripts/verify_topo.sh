#!/usr/bin/env bash
set -euo pipefail
echo 'COMMAND: date -u'; date -u
for ns in sg-client sg-r1 sg-r2 sg-gateway sg-backend; do
  echo "COMMAND: ip -n $ns address show"; ip -n "$ns" address show
  echo "COMMAND: ip -n $ns route show"; ip -n "$ns" route show
done
for ns in sg-r1 sg-r2 sg-gateway; do echo "COMMAND: ip netns exec $ns sysctl net.ipv4.ip_forward"; ip netns exec "$ns" sysctl net.ipv4.ip_forward; done
[[ $(ip netns exec sg-r1 sysctl -n net.ipv4.ip_forward) == 1 ]]
[[ $(ip netns exec sg-r2 sysctl -n net.ipv4.ip_forward) == 1 ]]
[[ $(ip netns exec sg-gateway sysctl -n net.ipv4.ip_forward) == 0 ]]
echo 'COMMAND: ip netns exec sg-client ping -c 3 -W 2 10.10.3.10'
ip netns exec sg-client ping -c 3 -W 2 10.10.3.10
echo 'COMMAND: ip netns exec sg-client traceroute -n -q 1 -w 2 10.10.3.10'
trace=$(ip netns exec sg-client traceroute -n -q 1 -w 2 10.10.3.10); printf '%s\n' "$trace"
grep -Eq '^ *1 +10\.10\.1\.1 ' <<<"$trace"
grep -Eq '^ *2 +10\.10\.2\.2 ' <<<"$trace"
grep -Eq '^ *3 +10\.10\.3\.10 ' <<<"$trace"
echo 'COMMAND: ip netns exec sg-client ping -c 2 -W 2 10.10.4.10 (failure expected)'
if ip netns exec sg-client ping -c 2 -W 2 10.10.4.10; then echo 'FAIL: backend reachable' >&2; exit 1; else echo 'PASS: backend did not respond to ping.'; fi
echo 'Topology verification passed.'
