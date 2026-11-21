# SentinelGate engineering roadmap

SentinelGate is a local FastAPI reverse proxy that authenticates and screens API requests before forwarding accepted traffic to a protected backend. The project must demonstrate networking as well as application security. This roadmap describes planned work; no measurements or captures are claimed yet.

## Architecture

Use Ubuntu 22.04/24.04 and Linux network namespaces connected by veth pairs. Configure static IPv4 routes and IP forwarding on two router namespaces. Place the client and gateway on opposite ends of the routed path; the gateway communicates with the backend on a separate fourth subnet. This keeps the HTTP proxy boundary explicit.

```text
client -- 10.10.1.0/24 -- R1 -- 10.10.2.0/24 -- R2 -- 10.10.3.0/24 -- gateway -- 10.10.4.0/24 -- backend
 .10                       .1  .1                 .2  .1                 .10       .1                 .10
                                                                         TCP 8000                     TCP 9000
```

The gateway is an application proxy, not a third IP router. R1 and R2 have routes to both endpoint subnets; the client and gateway have appropriate return routes. Apply `tc netem` to a router-facing inter-router egress interface, recording direction, seed, configuration and counters. Capture at the inter-router link and both application sides as needed. Do not expose the backend to the client route.

## Work stages and acceptance criteria

1. **Topology foundation:** create and tear down only project namespaces; configure addresses and static routes. Save routing tables, ping and traceroute showing R1 and R2. Verify cleanup and provide a complete addressing/port diagram.
2. **Basic POC:** implement a minimal backend and asynchronous gateway forwarding with health endpoints; verify traffic traverses the routed topology.
3. **Security:** implement JWT validation, request validation, per-IP rate limiting, risk scoring, reputation recovery and expiring bans. Document thresholds and exercise allow, reject, limit and ban cases, including expiry.
4. **Observability:** provide protected read-only monitoring and structured event counters. Clearly label the deterministic rules and in-memory state as a lab POC.
5. **Packet evidence:** capture real protocol exchanges in `.pcapng` and annotate screenshots with addresses, ports and relevant TCP/HTTP fields. Include successful and rejected traffic and routing evidence. Never fabricate captures.
6. **Experiments:** run baseline, 2% and 5% configured loss on a router link, at least three independent runs per condition. Record each request outcome, latency, success rate, goodput and predefined security case outcomes; report per-run values and mean plus sample standard deviation or range. Retain raw data, commands, qdisc counters and traces; distinguish configured loss from observed loss.
7. **Submission:** assemble a 6–10 page report, reproducible README, diagram, packet evidence, experiment table, live-demo script and truthful AI-use disclosure. Validate claims and exports against actual results.

## First implementation priorities

- Build and test the isolated namespace topology before implementing application logic.
- Use a Python virtual environment and a small, pinned dependency set; avoid cloud services, paid tools and API keys.
- Preserve evidence and scripts as reproducible artifacts, with real execution dates and no invented results.
- Clarify the conflicting team-size instructions with the instructor: the pasted requirements say both maximum three and two members, whereas the proposal names three. Confirm the final team and individual contributions before submission.

## Environment constraint

Linux networking requires root or appropriate capabilities, and `ip`, `tc`, `traceroute`, packet capture tools and Python. The current Windows session did not permit access to WSL or Docker; the topology and real experiments must be validated in an accessible Ubuntu environment. No evidence of successful execution exists yet.
