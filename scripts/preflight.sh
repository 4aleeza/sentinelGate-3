#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required.' >&2; exit 1; }
echo 'COMMAND: date -u'; date -u
echo 'COMMAND: uname -a'; uname -a
for ns in sg-preflight; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then echo "$ns already exists; refusing." >&2; exit 1; fi
done
for dev in sg-p0 sg-p1; do if ip link show "$dev" >/dev/null 2>&1; then echo "$dev exists; refusing." >&2; exit 1; fi; done
created_ns=0; created_link=0
cleanup() { if ((created_link)); then ip link del sg-p0 || true; fi; if ((created_ns)); then ip netns del sg-preflight || true; fi; }
trap cleanup EXIT
echo 'COMMAND: ip netns add sg-preflight'; ip netns add sg-preflight; created_ns=1
echo 'COMMAND: ip link add sg-p0 type veth peer name sg-p1'; ip link add sg-p0 type veth peer name sg-p1; created_link=1
ip link set sg-p1 netns sg-preflight
ip link set sg-p0 up; ip -n sg-preflight link set lo up; ip -n sg-preflight link set sg-p1 up
echo 'COMMAND: tc qdisc add dev sg-p0 root netem loss 1%'; tc qdisc add dev sg-p0 root netem loss 1%
echo 'COMMAND: tc -s qdisc show dev sg-p0'; tc -s qdisc show dev sg-p0
ip address add 10.99.0.1/24 dev sg-p0; ip -n sg-preflight address add 10.99.0.2/24 dev sg-p1
echo 'COMMAND: timeout 8 tcpdump -n -i sg-p0 -c 1 arp (then ping 10.99.0.2)'
timeout 8 tcpdump -n -i sg-p0 -c 1 arp > /tmp/sg-preflight-tcpdump.log 2>&1 & capture_pid=$!
sleep 1
ping -c 1 -W 2 10.99.0.2 || true
wait "$capture_pid"; cat /tmp/sg-preflight-tcpdump.log
echo 'Preflight passed.'
