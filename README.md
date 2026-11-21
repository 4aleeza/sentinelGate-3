# SentinelGate — lab and Stage 1 reproduction

See [ROADMAP.md](ROADMAP.md) and [architecture](docs/architecture.md). The Ubuntu container needs privileged access because network namespaces, veth interfaces and traffic control modify its Linux networking environment. Use it only for this lab. The host project directory is mounted to persist actual evidence.

From PowerShell in the project directory:

```powershell
docker build -t sentinelgate-stage1 .
docker run --rm -it --privileged --network none --mount "type=bind,source=${PWD},target=/work" sentinelgate-stage1 bash
```

Inside the container, save outputs and their exit codes:

```bash
bash scripts/run_stage1_checks.sh
```

This writes timestamped preflight, topology, and cleanup files under `evidence/logs` and `evidence/routing`. A successful exit indicates all checks completed.

Do not run later stages if preflight or topology verification fails. `topo_up.sh` verifies a complete existing topology and otherwise refuses to overwrite existing namespaces; `topo_down.sh` can be repeated and refuses to remove a namespace containing processes. Only named project namespaces are deleted. The backend ping test demonstrates lack of ICMP reachability, alongside the recorded routes and disabled gateway forwarding; it is not a general security proof.

For Stage 2 commands and Command Prompt syntax, see [Stage 2 reproduction](docs/stage2_readme.md). Stage 1 evidence files now use timestamped names.

Run the promoted test suite in Docker from Windows Command Prompt:

```bat
docker run --rm -v "%cd%:/work" -w /work sentinelgate:latest pytest
```


## Stage 4 monitoring

From Windows Command Prompt in the project directory:

```bat
docker run --rm -v "%cd%:/work" -w /work sentinelgate:latest pytest
docker run --rm --privileged -v "%cd%:/work" -w /work sentinelgate:latest bash scripts/stage4_verify.sh
```

Use `scripts/mint_token.py monitor` with the current lab secret to obtain a monitor-only token. Never persist the token or use real credentials. Monitoring returns completed-request counters before the monitoring request itself is recorded.

