#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root privileges required.' >&2; exit 1; }
names=(sg-client sg-r1 sg-r2 sg-gateway sg-backend)
for ns in "${names[@]}"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns" && [[ -n $(ip netns pids "$ns") ]]; then
    echo "Processes still running in $ns; stop them first." >&2; exit 1
  fi
done
for ns in "${names[@]}"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then ip netns del "$ns"; fi
done
echo 'Project namespaces removed or already absent.'
