# Stage 2 reproduction

From Windows Command Prompt:

```cmd
cd /d C:\CN-SentinelGate-3
docker build --progress=plain -t sentinelgate-stage2 .
docker run --rm -it --privileged --network none --mount "type=bind,source=%cd%,target=/work" sentinelgate-stage2 bash
```

In PowerShell, replace `%cd%` with `${PWD}` in the mount argument. In the container:

```bash
bash scripts/stage2_verify.sh
```

The Stage 2 runner writes test, integration, process logs, and captures under `evidence`; archive them before rerunning because Stage 2 output names are fixed. It runs cleanup on exit. Topology-only evidence uses timestamped names through `scripts/run_stage1_checks.sh`. It starts services only inside the disposable privileged container. The bind addresses and ports are configurable through `SG_GATEWAY_HOST`, `SG_GATEWAY_PORT`, `SG_BACKEND_HOST` and `SG_BACKEND_PORT`; upstream URL and source, timeouts, and body limit have `SG_` environment settings in `gateway/app.py`.
