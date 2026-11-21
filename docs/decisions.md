# Stage 2 design decisions

- **Shared AsyncClient:** one connection pool is created at startup and closed at shutdown. Reusing it avoids repeated connection setup and lets concurrent requests await network I/O rather than serializing the gateway.
- **Liveness and readiness:** `/health` reports the gateway process is alive; `/ready` checks the backend. Combining them would make a backend outage look like a dead gateway and hide where the fault lies.
- **Hop-by-hop headers:** connection-specific headers and those nominated by `Connection` are removed in both directions. They describe a single connection and can corrupt or misrepresent the separate upstream connection if copied.
- **Bind addresses:** the gateway listens on 10.10.3.10 and the backend on 10.10.4.10; upstream sockets use 10.10.4.1. This makes the intended boundary observable; binding all interfaces would expose services on interfaces not intended for them.
- **Screening hook:** The former allow-all placeholder was replaced by the integrated Stage 3 security engine; Stage 4 also handles monitoring locally.
- **Request identity:** a syntactically valid client request ID is retained; otherwise a new ID is generated. The forwarded client address is built from the socket peer rather than trusting a supplied forwarding header.

# Stage 3a decisions

- Ban, bucket, structure, JWT and forwarding are evaluated in that order. Banned requests are not parsed; rejecting floods before crypto saves work.
- A token bucket allows bursts and needs constant state per IP. Its weakness is that it allows a burst followed by the refill rate, unlike a strict sliding-window maximum.
- Recovery is linear and lazy; successful traffic gives no additional credit, preventing attackers from erasing risk simply by sending good requests.
- Banned requests do not add risk or extend bans; expiry is lazy and restores a probation score. Repeat bans inside the memory window escalate.
- Identity is the TCP peer supplied by the adapter, never a client-provided X-Forwarded-For. Without this boundary a client could evade per-IP state by forging a header.
- JWT verification fixes HS256 in the allowlist. Untrusted token headers never choose the verification algorithm.
- All state updates are synchronous and require a single worker. Multiple workers would each maintain inconsistent independent state.
- If all tracked IPs are active or risky at the memory limit, the library returns `state_capacity` with 503 rather than evicting one of them. That behavior is a lab policy for an unspecified saturation case.
- `/health` and `/ready` are exempt from structural validation and JWT, but still undergo the ban and rate checks. Exact threshold 40 is elevated and exact threshold 70 begins a ban; at the exact expiry instant the ban ends.
- Suspicious content adds risk but is not itself a rejection. If that increment reaches the ban threshold, the triggering request still completes its remaining checks; subsequent requests are banned.
- Monotonic time controls buckets and bans; a separately injectable Unix wall clock validates JWT dates. This is necessary because JWT timestamps are epoch-based, not monotonic.


- Gateway health polling uses the dedicated 10.10.1.250 client address so it does not consume a case client's tokens or alter its score; the address verification performs a single health request per case address before restarting the gateway.

## Stage 4 decisions

- A separate `monitor:read` scope prevents ordinary API credentials from reading monitoring data and prevents monitor-only credentials from calling APIs.
- Fixed-key counters and a 200-entry ring bound memory; unbounded keys or event history could exhaust the process.
- Monitoring requests have their own counter so observer traffic does not distort API traffic counts, while bans and rate limits still apply.
- IP snapshots calculate decay without mutating other clients' stored state. Unknown paths are redacted in events to avoid retaining credentials in URL paths.

- Request IDs use the strict format [A-Za-z0-9-]{8,64}; invalid, empty, oversized and JWT-like IDs are replaced with generated IDs. Format validation does not establish that a valid ID contains no secret, so clients must not put credentials in IDs.
- The security decision record describes the screening result before forwarding; the final-outcome record describes the final HTTP status after handling, with upstream result and latency. A pre-forward allow is not evidence of upstream success.
- The latency_ms histogram includes all completed decisions, including monitoring and health requests. api_latency_ms separately measures completed API decisions, including rejected API requests. Both histograms are cumulative; exclusive bucket counts are obtained by subtraction. A monitoring response excludes its own measurement until completion.
