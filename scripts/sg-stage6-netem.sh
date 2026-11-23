#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required' >&2; exit 1; }
mode=${1:?usage: sg-stage6-netem.sh apply LOSS | remove | show}
case "$mode" in
 apply)
  loss=${2:?loss required}
  [[ $loss == 0 || $loss == 2 || $loss == 5 ]] || { echo 'loss must be 0, 2 or 5' >&2; exit 2; }
  ip netns exec sg-r1 tc qdisc del dev sg-r11 root 2>/dev/null || true
  ip netns exec sg-r1 tc qdisc add dev sg-r11 root netem loss "$loss%"
  ;;
 remove) ip netns exec sg-r1 tc qdisc del dev sg-r11 root ;;
 show) ip netns exec sg-r1 tc -s qdisc show dev sg-r11 ;;
 *) echo 'invalid mode' >&2; exit 2 ;;
esac
