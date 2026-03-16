import asyncio

import httpx
import pytest

from watt.core.config import NetworkSettings
from watt.net.client import WattHttpClient


@pytest.mark.asyncio
async def test_rate_limit_respects_retry_after_and_retries() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0.01"}, text="rate limited")
        return httpx.Response(200, text="ok")

    settings = NetworkSettings(
        timeout=5.0,
        max_concurrency=10,
        retry_attempts=2,
        retry_backoff_base=0.1,
        honor_retry_after=True,
        per_host_max_concurrency=2,
        rate_limit_cooldown_s=1.0,
    )
    client = WattHttpClient(settings)
    # Inject MockTransport
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)  # type: ignore[attr-defined]
    try:
        res = await client.fetch_text("https://example.com/test")
        assert res.status_code == 200
        assert calls["n"] == 2
        assert res.block is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_waf_detection_sets_block_signal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"Server": "cloudflare", "CF-Ray": "abc"}, text="Access denied")

    settings = NetworkSettings(timeout=5.0, retry_attempts=0)
    client = WattHttpClient(settings)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)  # type: ignore[attr-defined]
    try:
        res = await client.fetch_text("https://example.com/blocked")
        assert res.status_code == 403
        assert res.block is not None
        assert res.block.kind == "waf"
    finally:
        await client.aclose()

