import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
logger = logging.getLogger("sentinelgate.backend")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())
BODY_CAP = int(os.getenv("SG_BODY_CAP", "65536"))


def peer_info(request: Request):
    return {"peer_host": request.client.host if request.client else None,
            "peer_port": request.client.port if request.client else None,
            "host": request.headers.get("host"),
            "x_forwarded_for": request.headers.get("x-forwarded-for"),
            "x_request_id": request.headers.get("x-request-id"),
            "timestamp": datetime.now(timezone.utc).isoformat()}


@app.middleware("http")
async def log_request(request: Request, call_next):
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        logger.info(json.dumps({"request_id": request.headers.get("x-request-id"),
            "peer": request.client.host if request.client else None, "method": request.method,
            "path": request.url.path, "status": status, "duration_ms": (time.perf_counter()-start)*1000}))


@app.get("/health")
async def health():
    return {"status": "ok", "service": "backend"}


@app.get("/api/info")
async def info(request: Request):
    return peer_info(request)


@app.post("/api/echo")
async def echo(request: Request):
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > BODY_CAP:
            raise HTTPException(413, "Request body too large")
        chunks.append(chunk)
    try:
        body = json.loads(b"".join(chunks))
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid JSON")
    return {"body": body, **peer_info(request)}


@app.get("/api/slow")
async def slow(ms: int = 200):
    if not 0 <= ms <= 2000:
        raise HTTPException(422, "ms must be between 0 and 2000")
    await asyncio.sleep(ms / 1000)
    return {"slept_ms": ms}
