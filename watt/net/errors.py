from __future__ import annotations


class WattNetError(Exception):
    """
    Base class for network-layer errors.
    """


class RateLimited(WattNetError):
    """
    Raised when a request is rate-limited and the caller opts to treat it as an error.
    """

    def __init__(self, message: str, retry_after_s: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


class BlockedByWaf(WattNetError):
    """
    Raised when a request appears blocked by a WAF/CDN.
    """

