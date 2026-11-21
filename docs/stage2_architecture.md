# Stage 2 request flow

1. The client at 10.10.1.10 opens TCP to 10.10.3.10:8000 through R1 and R2.
2. The gateway process accepts that TCP connection and receives an HTTP request.
3. The gateway calls the currently allow-all screening hook, removes connection-specific headers, creates a request ID if needed and sets `X-Forwarded-For` from the actual client socket.
4. A shared asynchronous HTTP client opens or reuses a separate TCP connection sourced from 10.10.4.1 to the backend process at 10.10.4.10:9000.
5. The backend returns its response on the backend connection; the gateway relays it over the original client connection. The gateway does not route IP packets between its interfaces.

`tcp.stream` identifiers are local to each capture file: identical numbers in two files do not imply a shared TCP connection. Compare endpoint addresses and ports instead.
