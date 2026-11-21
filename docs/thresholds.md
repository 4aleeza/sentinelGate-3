# Stage 3a thresholds and limitations

The authoritative defaults and environment names are defined in `gateway/security_config.py`: each field `name` maps to `SG_NAME` in uppercase. Values are used by an in-memory, deterministic, single-worker lab library. State disappears on restart. A shared/NAT address can represent many users; a source IP is not strong identity. HS256 uses a shared secret; there is no revocation list. HTTP is plaintext, so captures expose lab tokens: use disposable lab tokens only. Substring checks are naive heuristics, not a WAF. The security library is integrated into the gateway; Stage 4 adds local monitoring.

Exact 40 is elevated, exact 70 triggers a ban, and a ban expires when `now >= ban_until`. Accepted traffic has no score credit. Offence history can be lost if an idle entry is evicted under memory pressure. Health and readiness remain subject to bans and the rate bucket.

| Name | Default | Unit | Meaning and rationale | Environment |
|---|---:|---|---|---|
| bucket_capacity | 20 | requests | Normal burst allowance | SG_BUCKET_CAPACITY |
| bucket_refill_per_second | 10 | requests/s | Normal sustained rate | SG_BUCKET_REFILL_PER_SECOND |
| elevated_factor | 0.5 | multiplier | Halves burst and refill for elevated clients | SG_ELEVATED_FACTOR |
| elevated_threshold | 40 | points | Start tighter limits | SG_ELEVATED_THRESHOLD |
| ban_threshold | 70 | points | Begin temporary ban | SG_BAN_THRESHOLD |
| score_max | 100 | points | Bound accumulated risk | SG_SCORE_MAX |
| decay_per_second | 0.5 | points/s | Gradual reputation recovery | SG_DECAY_PER_SECOND |
| ban_base_seconds | 30 | seconds | Initial temporary ban | SG_BAN_BASE_SECONDS |
| ban_max_seconds | 240 | seconds | Limit repeat-offence ban duration | SG_BAN_MAX_SECONDS |
| offence_memory_seconds | 600 | seconds | Retain escalation history | SG_OFFENCE_MEMORY_SECONDS |
| probation_score | 30 | points | Retain risk after ban expiry | SG_PROBATION_SCORE |
| max_ips | 10000 | clients | Bound state memory | SG_MAX_IPS |
| idle_seconds | 900 | seconds | Remove eligible idle clients during eviction | SG_IDLE_SECONDS |
| max_token_bytes | 4096 | bytes | Bound token processing | SG_MAX_TOKEN_BYTES |
| max_path_bytes | 256 | bytes | Bound path length | SG_MAX_PATH_BYTES |
| max_path_pattern_chars | 200 | characters | Bound allowlisted suffix | SG_MAX_PATH_PATTERN_CHARS |
| max_query_bytes | 512 | bytes | Bound query parsing | SG_MAX_QUERY_BYTES |
| max_query_params | 20 | parameters | Bound query parsing | SG_MAX_QUERY_PARAMS |
| max_headers | 50 | headers | Bound header processing | SG_MAX_HEADERS |
| max_header_value_bytes | 2048 | bytes | Bound individual header values | SG_MAX_HEADER_VALUE_BYTES |
| max_body_bytes | 65536 | bytes | Bound JSON processing | SG_MAX_BODY_BYTES |
| jwt_leeway_seconds | 5 | seconds | Allow small clock skew | SG_JWT_LEEWAY_SECONDS |
| issuer | sentinelgate-lab | string | Expected token issuer | SG_ISSUER |
| audience | sentinelgate-api | string | Expected token audience | SG_AUDIENCE |

The following event weights are additive risk points. Larger values represent stronger lab signals; these are not calibrated threat probabilities.

| Name | Default | Unit | Meaning and rationale | Environment |
|---|---:|---|---|---|
| points_rate_limited | 5 | points | Repeated traffic beyond allowance | SG_POINTS_RATE_LIMITED |
| points_missing_token | 5 | points | Missing credentials | SG_POINTS_MISSING_TOKEN |
| points_malformed_token | 10 | points | Malformed credential | SG_POINTS_MALFORMED_TOKEN |
| points_expired_token | 5 | points | Expired credential | SG_POINTS_EXPIRED_TOKEN |
| points_bad_claims | 10 | points | Invalid or missing claim | SG_POINTS_BAD_CLAIMS |
| points_insufficient_scope | 5 | points | Scope does not authorize action | SG_POINTS_INSUFFICIENT_SCOPE |
| points_bad_request | 10 | points | Invalid structure or JSON | SG_POINTS_BAD_REQUEST |
| points_bad_method | 10 | points | Unsupported method | SG_POINTS_BAD_METHOD |
| points_bad_path | 10 | points | Invalid path | SG_POINTS_BAD_PATH |
| points_bad_content_type | 10 | points | Invalid content type | SG_POINTS_BAD_CONTENT_TYPE |
| points_body_too_large | 10 | points | Excessive body size | SG_POINTS_BODY_TOO_LARGE |
| points_suspicious_pattern | 15 | points | Naive suspicious substring signal | SG_POINTS_SUSPICIOUS_PATTERN |
| points_bad_signature | 20 | points | Invalid signature | SG_POINTS_BAD_SIGNATURE |
| points_bad_algorithm | 40 | points | Disallowed algorithm | SG_POINTS_BAD_ALGORITHM |

The deterministic suspicious substrings are `../`, `<script`, `' or 1=1`, `union select`, and `${jndi:` in decoded path, query values, and JSON string values. The secret is supplied through `SENTINELGATE_JWT_SECRET` and must be at least 32 bytes; it has no default.

| max_claim_bytes | 256 | bytes | Bound each JWT claim value | SG_MAX_CLAIM_BYTES |

## Stage 4 monitoring limits

The events ring holds the latest 200 decisions. IP views contain at most the top 20 by score; risk state remains bounded by `SG_MAX_IPS`. Latency histogram buckets are cumulative at 10, 25, 50, 100, 250, 500, 1000, 2500 ms and +Inf. Reason and status counters use fixed sets with an `other` bucket. Lab POC: deterministic rules, in-memory state, lost on restart.

