"""Configuration for the deterministic, in-memory, single-worker lab POC."""
from dataclasses import dataclass, fields
import os
import math


@dataclass(frozen=True)
class SecurityConfig:
    bucket_capacity: float = 20.0
    bucket_refill_per_second: float = 10.0
    elevated_factor: float = 0.5
    elevated_threshold: float = 40.0
    ban_threshold: float = 70.0
    score_max: float = 100.0
    decay_per_second: float = 0.5
    ban_base_seconds: float = 30.0
    ban_max_seconds: float = 240.0
    offence_memory_seconds: float = 600.0
    probation_score: float = 30.0
    max_ips: int = 10000
    idle_seconds: float = 900.0
    max_token_bytes: int = 4096
    max_claim_bytes: int = 256
    max_path_bytes: int = 256
    max_query_bytes: int = 512
    max_query_params: int = 20
    max_headers: int = 50
    max_header_value_bytes: int = 2048
    max_body_bytes: int = 65536
    max_path_pattern_chars: int = 200
    jwt_leeway_seconds: float = 5.0
    issuer: str = "sentinelgate-lab"
    audience: str = "sentinelgate-api"
    points_rate_limited: float = 5.0
    points_missing_token: float = 5.0
    points_malformed_token: float = 10.0
    points_expired_token: float = 5.0
    points_bad_claims: float = 10.0
    points_insufficient_scope: float = 5.0
    points_bad_request: float = 10.0
    points_bad_method: float = 10.0
    points_bad_path: float = 10.0
    points_bad_content_type: float = 10.0
    points_body_too_large: float = 10.0
    points_suspicious_pattern: float = 15.0
    points_bad_signature: float = 20.0
    points_bad_algorithm: float = 40.0

    @classmethod
    def from_env(cls):
        defaults = cls()
        values = {}
        for field in fields(cls):
            raw = os.getenv("SG_" + field.name.upper())
            if raw is not None:
                values[field.name] = type(getattr(defaults, field.name))(raw)
        result = cls(**values)
        for field in fields(cls):
            value = getattr(result, field.name)
            if isinstance(value, (int, float)) and (not math.isfinite(value) or value < 0):
                raise ValueError('Invalid SentinelGate security configuration')
            if field.name.startswith('max_') and value < 1:
                raise ValueError('Invalid SentinelGate security configuration')
            if field.name in ('issuer', 'audience') and not value:
                raise ValueError('Invalid SentinelGate security configuration')
        if not (result.bucket_capacity >= 1 and result.bucket_refill_per_second > 0
                and 0 < result.elevated_factor <= 1 and result.max_ips > 0
                and 0 <= result.probation_score < result.elevated_threshold < result.ban_threshold <= result.score_max
                and result.decay_per_second >= 0 and result.ban_base_seconds > 0
                and result.ban_max_seconds >= result.ban_base_seconds):
            raise ValueError("Invalid SentinelGate security configuration")
        return result
