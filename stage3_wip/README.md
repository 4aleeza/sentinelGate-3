# Stage 3a isolated security library

This library is not connected to the Stage 2 gateway. The adapter in a future stage must construct `SecurityRequest` from the actual TCP peer, validate and safely supply request headers/body, and use the returned decision before forwarding. The in-memory store requires one worker. The lab token generator requires a disposable `SENTINELGATE_JWT_SECRET` of at least 32 bytes; never store tokens or the secret in evidence.

To test from this directory in a Python virtual environment:

```text
python -m pip install -r requirements.txt
python -m pytest -q tests
```

`SecurityEngine` accepts a monotonic clock for buckets and bans and an epoch wall clock for JWT claims. Both default to system clocks and are injected in tests. The case JSON contains token-variant labels rather than actual credentials; scripted multi-step cases need a future live harness.
