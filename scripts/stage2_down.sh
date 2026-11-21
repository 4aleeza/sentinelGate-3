#!/usr/bin/env bash
set -euo pipefail
for name in gateway backend; do
  file="evidence/logs/$name.pid"
  if [[ -f $file ]]; then
    pid=$(cat "$file")
    if kill -0 "$pid" 2>/dev/null; then
      cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline")
      [[ $cmd == *"$name.app:app"* && $cmd == *uvicorn* ]] || { echo "PID $pid does not match $name; refusing to kill" >&2; exit 1; }
      kill "$pid"
      for i in {1..50}; do kill -0 "$pid" 2>/dev/null || break; [[ $(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true) == Z ]] && break; sleep 0.1; done
      if kill -0 "$pid" 2>/dev/null && [[ $(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true) != Z ]]; then echo "$name did not stop" >&2; exit 1; fi
    fi
    rm -f "$file"
  fi
done
for pair in 'sg-gateway 8000' 'sg-backend 9000'; do
  read -r ns port <<< "$pair"
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    if ip netns exec "$ns" ss -ltnH "sport = :$port" | grep -q .; then echo "Port $port still in use in $ns" >&2; exit 1; fi
    echo "$ns port $port free"
  fi
done
