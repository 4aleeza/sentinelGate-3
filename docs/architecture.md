# Stage 1 architecture

```text
client -- 10.10.1.0/24 -- R1 -- 10.10.2.0/24 -- R2 -- 10.10.3.0/24 -- gateway -- 10.10.4.0/24 -- backend
 .10                       .1   .1                .2   .1                 .10       .1                .10
                                                                         TCP 8000                    TCP 9000
```

The client uses R1 as its default route; R1 and R2 have static routes for the opposite client and gateway subnets. R2 is the gateway's return path to the client. The gateway is a dual-homed application proxy, with kernel forwarding disabled; it is not an IP router. The backend's gateway points to that host, but the client has no path through the proxy to the backend. Stage 2 implements the gateway on TCP 8000 and backend on TCP 9000. Netem will be applied later to R1's `sg-r11` egress, toward R2. Each namespace and interface created uses the `sg-` prefix.

# Stage 2 request flow

1. The client at 10.10.1.10 opens TCP to 10.10.3.10:8000 through R1 and R2.
2. The gateway process accepts that TCP connection and receives an HTTP request.
3. The gateway screens requests with the integrated security engine, removes connection-specific headers, creates a safe request ID if needed and sets `X-Forwarded-For` from the actual client socket.
4. A shared asynchronous HTTP client opens or reuses a separate TCP connection sourced from 10.10.4.1 to the backend process at 10.10.4.10:9000.
5. The backend returns its response on the backend connection; the gateway relays it over the original client connection. The gateway does not route IP packets between its interfaces.

`tcp.stream` identifiers are local to each capture file: identical numbers in two files do not imply a shared TCP connection. Compare endpoint addresses and ports instead.

# Stage 4 observability

After peer ban and rate checks, monitoring requests require the `monitor:read` scope and are handled locally by the gateway. API scopes do not grant monitoring access, and monitoring scope does not grant API access. GET `/monitor/summary`, `/monitor/ips`, and `/monitor/events` expose in-memory lab state and never forward to the backend. A response reflects completed requests before that response is recorded. This is a single-worker lab POC; restarting clears state.

