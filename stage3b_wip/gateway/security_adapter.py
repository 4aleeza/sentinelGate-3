"""Translate ASGI peer identity without trusting forwarded headers."""
from .security import SecurityRequest


def client_ip_from_asgi(scope):
    """Return the peer host from ASGI's client tuple; fail closed if unavailable."""
    client = scope.get('client')
    if not isinstance(client, (tuple, list)) or len(client) != 2 or not isinstance(client[0], str) or not client[0]:
        raise ValueError('ASGI TCP peer is unavailable')
    return client[0]


async def screen_request(request, engine):
    """Check ban and rate before reading a body, then complete the policy."""
    ip = client_ip_from_asgi(request.scope)
    prepared = engine.begin(ip)
    raw_path = request.scope.get('raw_path', request.url.path.encode()).decode('latin-1')
    values = dict(client_ip=ip, request_id=getattr(request.state, 'request_id', ''),
                  method=request.method, path=request.url.path, raw_path=raw_path,
                  query=request.scope.get('query_string', b'').decode('latin-1'),
                  headers=dict(request.headers), raw_headers=tuple(request.scope.get('headers', ())))
    if prepared[1] is not None:
        return engine.screen_request(SecurityRequest(**values), prechecked=prepared), b''
    data = bytearray()
    async for chunk in request.stream():
        remaining = engine.config.max_body_bytes + 1 - len(data)
        data.extend(chunk[:remaining])
        if len(data) > engine.config.max_body_bytes:
            break
    body = bytes(data)
    return engine.screen_request(SecurityRequest(**values, body=body), prechecked=prepared), body
