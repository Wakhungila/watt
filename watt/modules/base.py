from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from watt.core.workspace import Workspace
from watt.core.config import WattConfig
from watt.core.logging import get_logger
from watt.graph.hunter_map import HunterMap


@dataclass
class ModuleContext:
    config: WattConfig
    workspace: Workspace
    map: HunterMap


class BaseModule(Protocol):
    """
    Shared base protocol for concrete modules.

    This is intentionally light for Phase 1; in later phases we will
    extend it with richer lifecycle hooks and progress reporting.
    """

    name: str
    phase: str
    ctx: ModuleContext

    async def run(self) -> None:
        ...


class SimpleModule:
    """
    Convenience base class implementing logging and context wiring.
    """

    name: str = "unnamed"
    phase: str = "unknown"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.log = get_logger(self.__class__.__name__)

    async def run(self) -> None:  # pragma: no cover - to be overridden
        raise NotImplementedError
