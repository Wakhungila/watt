"""
Networking primitives for WATT.

This layer is designed to be:
- async-first
- rate-limit aware
- resilient to transient network failures

It does NOT implement bypass techniques. Instead it detects blocking,
adapts request pacing, and records evidence for human triage.
"""

from .client import WattHttpClient  # noqa: F401
from .signals import BlockSignal, RateLimitSignal, WafSignal  # noqa: F401

