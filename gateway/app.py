import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from dataclasses import asdict
from .security import SecurityEngine
from .security_adapter import screen_request
from .observability import Observability

UPSTREAM = os.getenv("SG_UPSTREAM_URL", "http://10.10.4.10:9000").rstrip("/")
LOCAL_ADDRESS = os.getenv("SG_UPSTREAM_SOURCE", "10.10.4.1")
BODY_CAP = int(os.getenv("SG_BODY_CAP", "65536"))
CONNECT_TIMEOUT = float(os.getenv("SG_CONNECT_TIMEOUT", "2"))
READ_TIMEOUT = float(os.getenv("SG_READ_TIMEOUT", "5"))
WRITE_TIMEOUT = float(os.getenv("SG_WRITE_TIMEOUT", "5"))
POOL_TIMEOUT = float(os.getenv("SG_POOL_TIMEOUT", "2"))
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"}
REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")
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
    app.state.observability = Observability()
    logger.info(json.dumps({'event': 'security_config', 'config': asdict(app.state.security.config), 'secret': '[redacted]'}))
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
    request.state.upstream_result = 'not_forwarded'
    stats = getattr(request.app.state, 'observability', None)
    if stats is None:
        stats = request.app.state.observability = Observability()
    started = stats.clock()
    decision = None
    status = 500
    try:
        decision, body = await screen_request(request, request.app.state.security)
        if not decision.allow:
            response = JSONResponse({'error': decision.reason, 'request_id': request.state.request_id}, status_code=decision.status, headers=decision.headers)
        else:
            request.state.screened_body = body
            response = await call_next(request)
        status = response.status_code
        response.headers['X-Request-ID'] = request.state.request_id
        return response
    finally:
        if decision is not None:
            safe_paths = {'/health','/ready','/api/info','/api/echo','/api/slow','/monitor/summary','/monitor/ips','/monitor/events'}
            safe_path = request.url.path if request.url.path in safe_paths else '/[redacted]'
            request_id = request.state.request_id
            safe_method = request.method if request.method in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'} else '[redacted]'
            logger.info(json.dumps({'event':'final_outcome', 'request_id':request_id,
                'client_ip':decision.client_ip, 'method':safe_method, 'path':safe_path[:256],
                'status':status, 'upstream_result':request.state.upstream_result,
                'upstream_latency_ms':request.state.upstream_ms}))
            tier = 'banned' if decision.ban_remaining else ('elevated' if decision.score_after >= request.app.state.security.config.elevated_threshold else 'normal')
            stats.record(request_id=request_id, client_ip=decision.client_ip, method=safe_method, path=safe_path,
                         decision='allow' if decision.allow else 'reject', reason=decision.reason, status=status,
                         score_after=decision.score_after, tier=tier, latency_ms=max(0.0,(stats.clock()-started)*1000),
                         monitor=request.url.path.startswith('/monitor/'), api=request.url.path.startswith('/api/'))


def monitor_envelope(request):
    return request.app.state.observability.envelope()


@app.get('/monitor/summary')
async def monitor_summary(request: Request):
    stats = request.app.state.observability
    store = request.app.state.security.store
    config = asdict(request.app.state.security.config)
    secret = request.app.state.security.secret
    auth = request.headers.get('authorization', '').split()
    token = auth[-1] if auth else ''
    for key, value in config.items():
        if isinstance(value, str) and ((secret and secret in value) or (token and token in value)):
            config[key] = '[redacted]'
    return {**monitor_envelope(request), 'total_requests':stats.total_requests, 'monitor_requests':stats.monitor_requests,
            'api_requests':stats.api_requests, 'allowed':stats.allowed, 'rejected':stats.rejected,
            'reasons':dict(stats.reasons), 'statuses':dict(stats.statuses), 'upstream_errors':stats.upstream_errors,
            'active_bans':sum(1 for state in store.clients.values() if state.ban_until > store.clock()),
            'bans_issued':store.bans_issued, 'ban_expiries':store.ban_expiries, 'rate_limited':stats.rate_limited,
            'latency_ms':{'count':stats.latency_count,'sum':stats.latency_sum_ms,'max':stats.latency_max_ms,'buckets':dict(stats.buckets)},
            'api_latency_ms':stats.api_latency, 'thresholds':config}


@app.get('/monitor/ips')
async def monitor_ips(request: Request):
    store = request.app.state.security.store
    now = store.clock(); config = store.config; items=[]
    for ip, state in store.clients.items():
        remaining = max(0, __import__('math').ceil(state.ban_until-now))
        if remaining:
            score = state.score
        elif state.ban_until:
            score = max(0.0, config.probation_score-max(0.0,now-state.ban_until)*config.decay_per_second)
        else:
            score = max(0.0,state.score-max(0.0,now-state.score_at)*config.decay_per_second)
        items.append({'ip':ip,'score':score,'tier':'banned' if remaining else ('elevated' if score >= config.elevated_threshold else 'normal'),'ban_remaining':remaining})
    items.sort(key=lambda item:(-item['score'],item['ip']))
    return {**monitor_envelope(request), 'ips':items[:20]}


@app.get('/monitor/events')
async def monitor_events(request: Request):
    return {**monitor_envelope(request), 'events':list(request.app.state.observability.events)}


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


@app.api_route("/api/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    body = request.state.screened_body
    headers = strip_hop(request.headers)
    for key in list(headers):
        if key.lower() in {"host", "x-forwarded-for", "x-request-id", "cookie", "authorization", "content-length"}:
            headers.pop(key)
    headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
    headers["X-Request-ID"] = request.state.request_id
    start = time.perf_counter()
    try:
        response = await request.app.state.client.request(request.method, UPSTREAM + "/api/" + path,
            params=request.query_params, headers=headers, content=body)
        request.state.upstream_result = 'ok'
        response_headers = strip_hop(response.headers)
        for key in list(response_headers):
            if key.lower() in {"content-length", "content-encoding", "set-cookie"}:
                response_headers.pop(key)
        return Response(content=response.content, status_code=response.status_code, headers=response_headers)
    except httpx.TimeoutException as exc:
        request.state.upstream_result = 'timeout'
        logger.warning("upstream timeout: %r", exc)
        return JSONResponse({"detail": "Upstream timeout"}, status_code=504)
    except httpx.RequestError as exc:
        request.state.upstream_result = 'connect_error'
        logger.warning("upstream connection error: %r", exc)
        return JSONResponse({"detail": "Upstream unavailable"}, status_code=502)
    finally:
        request.state.upstream_ms = (time.perf_counter() - start) * 1000
