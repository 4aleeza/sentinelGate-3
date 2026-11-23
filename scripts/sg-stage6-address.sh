#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required' >&2; exit 1; }
mode=${1:?usage: sg-stage6-address.sh up|down}
case "$mode" in
 up) ip -n sg-client -o -4 addr show dev sg-c0 | grep -Fq ' 10.10.1.200/24 ' || ip -n sg-client addr add 10.10.1.200/24 dev sg-c0 ;;
 down) if ip -n sg-client -o -4 addr show dev sg-c0 | grep -Fq ' 10.10.1.200/24 '; then ip -n sg-client addr del 10.10.1.200/24 dev sg-c0; fi ;;
 *) echo 'invalid mode' >&2; exit 2 ;;
esac
