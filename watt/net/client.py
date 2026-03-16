from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from watt.core.config import NetworkSettings
from watt.core.logging import get_logger
from watt.net.rate_limiter import PerHostLimiter
from watt.net.signals import BlockSignal
from watt.net.waf import detect_waf


@dataclass
class FetchResult:
    url: str
    status_code: Optional[int]
    headers: Dict[str, str]
    text: Optional[str]
    error: Optional[str]
    block: Optional[BlockSignal]


def _parse_retry_after(headers: Dict[str, str]) -> Optional[float]:
    ra = None
    for k, v in headers.items():
        if k.lower() == "retry-after":
            ra = v
            break
    if not ra:
        return None
    try:
        # Most common form is delta-seconds
        return float(ra.strip())
    except Exception:
        return None


class WattHttpClient:
    """
    Async HTTP client with:
    - retries + jittered exponential backoff
    - per-host concurrency limiting
    - adaptive cooldown on rate limit / block signals
    - WAF/rate-limit detection (no bypass attempts)
    """

    def __init__(self, settings: NetworkSettings) -> None:
        self.settings = settings
        self._logger = get_logger(__name__)
        self._limiter = PerHostLimiter(
            per_host_max=settings.per_host_max_concurrency,
            global_rps=settings.requests_per_second
        )
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.timeout),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=settings.max_concurrency),
            headers={"User-Agent": settings.user_agent},
            max_redirects=settings.max_redirects,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch_text(self, url: str, *, method: str = "GET", headers: Optional[Dict[str, str]] = None) -> FetchResult:
        """
        Fetch a URL as text with safeguards.

        Returns a structured result and never raises for network errors.
        """
        try:
            host = httpx.URL(url).host or "unknown"
        except Exception:
            host = "unknown"

        await self._limiter.acquire(host)
        try:
            return await self._fetch_text_inner(url, method=method, headers=headers, host=host)
        finally:
            await self._limiter.release(host)

    async def _fetch_text_inner(
        self,
        url: str,
        *,
        method: str,
        headers: Optional[Dict[str, str]],
        host: str,
    ) -> FetchResult:
        attempt = 0
        last_err: Optional[str] = None

        while attempt <= self.settings.retry_attempts:
            attempt += 1
            try:
                resp = await self._client.request(method, url, headers=headers)
                hdrs = {k: v for k, v in resp.headers.items()}

                # Small snippet for block detection without loading huge bodies
                snippet = None
                text = None
                try:
                    text = resp.text
                    snippet = text[:5000] if text else None
                except Exception:
                    text = None

                block = self._classify_block(host=host, status_code=resp.status_code, headers=hdrs, body_snippet=snippet)
                if block and block.kind == "rate_limit":
                    cooldown = block.retry_after_s if (self.settings.honor_retry_after and block.retry_after_s) else self.settings.rate_limit_cooldown_s
                    await self._limiter.block(host, cooldown)

                    # Retry on rate limit if we have remaining attempts
                    if attempt <= self.settings.retry_attempts:
                        await asyncio.sleep(self._backoff_s(attempt, base=cooldown))
                        continue

                return FetchResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=hdrs,
                    text=text,
                    error=None,
                    block=block,
                )
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
                last_err = f"{type(exc).__name__}: {exc}"
                if attempt <= self.settings.retry_attempts:
                    await asyncio.sleep(self._backoff_s(attempt, base=self.settings.retry_backoff_base))
                    continue
                return FetchResult(url=url, status_code=None, headers={}, text=None, error=last_err, block=None)
            except Exception as exc:  # noqa: BLE001
                last_err = f"{type(exc).__name__}: {exc}"
                return FetchResult(url=url, status_code=None, headers={}, text=None, error=last_err, block=None)

        return FetchResult(url=url, status_code=None, headers={}, text=None, error=last_err or "unknown error", block=None)

    def _classify_block(
        self,
        *,
        host: str,
        status_code: int,
        headers: Dict[str, str],
        body_snippet: Optional[str],
    ) -> Optional[BlockSignal]:
        retry_after_s = _parse_retry_after(headers)

        if status_code == 429:
            return BlockSignal(
                host=host,
                status_code=status_code,
                kind="rate_limit",
                retry_after_s=retry_after_s,
                reason="HTTP 429",
            )

        if status_code in {403, 503}:
            waf = detect_waf(headers, status_code, body_snippet=body_snippet)
            if waf:
                return BlockSignal(
                    host=host,
                    status_code=status_code,
                    kind="waf",
                    vendor_hint=waf.vendor_hint,
                    reason=waf.reason,
                )

        # Generic block-like statuses
        if status_code in {401, 403, 406} and body_snippet:
            s = body_snippet.lower()
            if "captcha" in s or "cf-chl" in s:
                return BlockSignal(host=host, status_code=status_code, kind="waf", vendor_hint="cloudflare", reason="challenge/captcha detected")

        return None

    def _backoff_s(self, attempt: int, *, base: float) -> float:
        # jittered exponential backoff
        exp = base * (2 ** max(0, attempt - 1))
        jitter = random.uniform(0.8, 1.2)
        return min(60.0, exp * jitter)
