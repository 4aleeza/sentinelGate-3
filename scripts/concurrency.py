import asyncio
import json
import os
from mint_token import mint
from pathlib import Path
import time
from datetime import datetime, timezone
import httpx


async def main():
    token = mint('valid', os.environ['SENTINELGATE_JWT_SECRET'])
    start = time.perf_counter()
    async with httpx.AsyncClient(trust_env=False, timeout=10, limits=httpx.Limits(max_connections=100)) as client:
        async def request(index):
            then = time.perf_counter()
            response = await client.get('http://10.10.3.10:8000/api/slow?ms=200', headers={'Authorization': 'Bearer ' + token})
            return {'request': index, 'status': response.status_code, 'elapsed_ms': (time.perf_counter()-then)*1000}
        results = await asyncio.gather(*(request(i) for i in range(50)))
    total_ms = (time.perf_counter()-start)*1000
    # The generated credential stays in memory; scan all project files including pcaps.
    found = False
    for path in Path('.').rglob('*'):
        if path.is_file():
            try:
                if token.encode() in path.read_bytes():
                    found = True
                    break
            except (OSError, PermissionError):
                raise RuntimeError('Credential scan could not read a project file')
    if found:
        raise RuntimeError('Concurrency token detected in a project file')
    print(json.dumps({'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'command': 'ip netns exec sg-client python scripts/concurrency.py', 'total_ms': total_ms, 'token_scan': 'passed', 'results': results}, indent=2))
    if any(r['status'] != 200 for r in results):
        raise SystemExit(1)


asyncio.run(main())
