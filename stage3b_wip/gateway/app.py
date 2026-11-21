import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from .security import SecurityEngine
from .security_adapter import screen_request

UPSTREAM = os.getenv("SG_UPSTREAM_URL", "http://10.10.4.10:9000").rstrip("/")
LOCAL_ADDRESS = os.getenv("SG_UPSTREAM_SOURCE", "10.10.4.1")
BODY_CAP = int(os.getenv("SG_BODY_CAP", "65536"))
CONNECT_TIMEOUT = float(os.getenv("SG_CONNECT_TIMEOUT", "2"))
READ_TIMEOUT = float(os.getenv("SG_READ_TIMEOUT", "5"))
WRITE_TIMEOUT = float(os.getenv("SG_WRITE_TIMEOUT", "5"))
POOL_TIMEOUT = float(os.getenv("SG_POOL_TIMEOUT", "2"))
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"}
REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
logger = logging.getLogger("sentinelgate.gateway")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())


def strip_hop(headers):
    connection = headers.get("connection", "")
    excluded = HOP | {part.strip().lower() for part in connection.split(",") if part.strip()}
    return {key: value for key, value in headers.items() if key.lower() not in excluded and not key.lower().startswith("proxy-")}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.security = SecurityEngine.from_environment()
    logger.info(json.dumps({'event': 'security_config', 'config': asdict(app.state.security.config), 'secret': '[REDACTED]'}))
    transport = httpx.AsyncHTTPTransport(local_address=LOCAL_ADDRESS, limits=httpx.Limits(max_connections=100, max_keepalive_connections=50))
    timeout = httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=WRITE_TIMEOUT, pool=POOL_TIMEOUT)
    async with httpx.AsyncClient(transport=transport, timeout=timeout, trust_env=False) as client:
        app.state.client = client
        yield


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def log_request(request: Request, call_next):
    supplied = request.headers.get("x-request-id", "")
    request.state.request_id = supplied if REQUEST_ID.fullmatch(supplied) else uuid.uuid4().hex
    request.state.upstream_ms = None
    status = 500
    try:
        if request.url.path in ('/health', '/ready') or request.url.path.startswith('/api/'):
            try:
                decision, body = await screen_request(request, request.app.state.security)
            except ValueError:
                status = 400
                return JSONResponse({'error': 'bad_request', 'request_id': request.state.request_id}, status_code=status)
            if not decision.allow:
                status = decision.status
                return JSONResponse({'error': decision.reason, 'request_id': request.state.request_id}, status_code=status, headers=decision.headers)
            request._body = body
        response = await call_next(request)
        status = response.status_code
        response.headers["X-Request-ID"] = request.state.request_id
        return response
    finally:
        logger.info(json.dumps({"request_id": request.state.request_id,
            "client_ip": request.client.host if request.client else None, "method": request.method,
            "path": request.url.path, "status": status, "upstream_latency_ms": request.state.upstream_ms}))


@app.get("/health")
async def health():
    return {"status": "ok", "service": "gateway"}


@app.get("/ready")
async def ready(request: Request):
    try:
        result = await request.app.state.client.get(UPSTREAM + "/health", timeout=CONNECT_TIMEOUT)
        if result.status_code != 200:
            raise httpx.HTTPError("Unhealthy backend")
        return {"status": "ready"}
    except httpx.HTTPError as exc:
        logger.warning("readiness upstream error: %r", exc)
        return JSONResponse({"status": "not ready"}, status_code=503)


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > BODY_CAP:
            raise HTTPException(413, "Request body too large")
        chunks.append(chunk)
    headers = strip_hop(request.headers)
    for key in list(headers):
        if key.lower() in {"host", "x-forwarded-for", "x-request-id", "cookie", "authorization", "content-length"}:
            headers.pop(key)
    headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    headers["X-Request-ID"] = request.state.request_id
    start = time.perf_counter()
    try:
        response = await request.app.state.client.request(request.method, UPSTREAM + "/api/" + path,
            params=request.query_params, headers=headers, content=b"".join(chunks))
        response_headers = strip_hop(response.headers)
        for key in list(response_headers):
            if key.lower() in {"content-length", "content-encoding", "set-cookie"}:
                response_headers.pop(key)
        return Response(content=response.content, status_code=response.status_code, headers=response_headers)
    except httpx.TimeoutException as exc:
        logger.warning("upstream timeout: %r", exc)
        return JSONResponse({"detail": "Upstream timeout"}, status_code=504)
    except httpx.RequestError as exc:
        logger.warning("upstream connection error: %r", exc)
        return JSONResponse({"detail": "Upstream unavailable"}, status_code=502)
    finally:
        request.state.upstream_ms = (time.perf_counter() - start) * 1000
