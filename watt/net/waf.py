from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class WafDetection:
    vendor_hint: Optional[str]
    reason: str


def detect_waf(headers: Dict[str, str], status_code: int, body_snippet: str | None = None) -> WafDetection | None:
    """
    Heuristic WAF/CDN block detection.

    This does NOT attempt bypass. It only labels likely blocks so WATT can:
    - reduce request pressure
    - record evidence for operator triage
    """
    h = {k.lower(): v for k, v in headers.items()}

    # Common CDN/WAF header hints
    server = h.get("server", "")
    via = h.get("via", "")
    cf_ray = h.get("cf-ray")
    ak = h.get("akamai-grn") or h.get("akamai-origin-hop")
    x_sucuri = h.get("x-sucuri-id") or h.get("x-sucuri-block")

    if cf_ray or "cloudflare" in server.lower():
        if status_code in {403, 429, 503}:
            return WafDetection(vendor_hint="cloudflare", reason="cloudflare header hint + block-like status")

    if x_sucuri:
        return WafDetection(vendor_hint="sucuri", reason="sucuri header hint")

    if "akamai" in server.lower() or ak:
        if status_code in {403, 429, 503}:
            return WafDetection(vendor_hint="akamai", reason="akamai header hint + block-like status")

    if "imperva" in server.lower() or "incapsula" in server.lower():
        if status_code in {403, 429, 503}:
            return WafDetection(vendor_hint="imperva", reason="imperva/incapsula server hint + block-like status")

    if "fastly" in server.lower() or "fastly" in via.lower():
        if status_code in {403, 429, 503}:
            return WafDetection(vendor_hint="fastly", reason="fastly hint + block-like status")

    # Body snippet hints (kept minimal and generic)
    if body_snippet:
        s = body_snippet.lower()
        if "access denied" in s and status_code in {401, 403}:
            return WafDetection(vendor_hint=None, reason="generic access denied body")
        if "request blocked" in s and status_code in {403, 406}:
            return WafDetection(vendor_hint=None, reason="generic request blocked body")

    return None

