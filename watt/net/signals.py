from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class RateLimitSignal:
    host: str
    status_code: int
    retry_after_s: Optional[float]
    headers: Dict[str, str]


@dataclass(frozen=True)
class WafSignal:
    host: str
    status_code: int
    vendor_hint: Optional[str]
    reason: str
    headers: Dict[str, str]


@dataclass(frozen=True)
class BlockSignal:
    """
    Aggregated "this request was blocked" signal.
    """

    host: str
    status_code: int
    kind: str  # "rate_limit" | "waf" | "other"
    retry_after_s: Optional[float] = None
    vendor_hint: Optional[str] = None
    reason: Optional[str] = None

