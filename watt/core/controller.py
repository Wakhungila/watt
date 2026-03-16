from __future__ import annotations

import asyncio
import json
import signal
from typing import Iterable, List, Set

from .config import WattConfig
from .logging import LoggerContext, configure_logging, get_logger
from .module_registry import ModuleRegistry, ModuleDescriptor
from .workspace import Workspace
from .config import WattConfig
from watt.graph.hunter_map import HunterMap
from watt.modules.base import ModuleContext


class ScanController:
    """
    High-level orchestrator for a WATT run.

    Responsibilities in Phase 1:
    - initialize workspace
    - configure logging
    - expose hooks for module registration and execution
    """

    def __init__(self, config: WattConfig, registry: ModuleRegistry | None = None) -> None:
        self.config = config
        self.workspace = Workspace(config)
        self.map = HunterMap(db_path=self.workspace.config.workspace.database_path)
        self.registry = registry or ModuleRegistry()
        self._logger = get_logger(__name__)
        self._completed_phases: Set[str] = set()
        self._stop_requested = False
        
        self._setup_signals()

    def initialize(self) -> None:
        """
        Prepare workspace and logging.

        This should be called before any modules run.
        """
        self._setup_signals()
        self.workspace.initialize()
        ctx = LoggerContext(workspace=self.config.workspace, logging=self.config.logging)
        configure_logging(ctx)
        self._logger.info("Initialized workspace at %s", self.workspace.root)
        self._logger.info("Targets: %s", ", ".join(t.raw for t in self.config.targets))
        self._load_state()

    def _setup_signals(self) -> None:
        """
        Register signal handlers for graceful shutdown.
        """
        def _handle_stop(signum, frame):
            if not self._stop_requested:
                self._logger.warning("Stop signal received! Finishing current tasks and saving state...")
                self._stop_requested = True
        
        signal.signal(signal.SIGINT, _handle_stop)
        signal.signal(signal.SIGTERM, _handle_stop)

    def build_module_context(self) -> ModuleContext:
        return ModuleContext(
            config=self.config,
            workspace=self.workspace,
            map=self.map,
        )

    def _load_state(self) -> None:
        state = self.workspace.read_state("controller", "scan_state")
        if state:
            self._completed_phases = set(state.get("completed_phases", []))
            self._logger.info("Resumed scan. Completed phases: %s", ", ".join(self._completed_phases))

    def _save_state(self) -> None:
        self.workspace.write_state(
            "controller", 
            "scan_state", 
            {"completed_phases": list(self._completed_phases)}
        )

    def _mark_phase_complete(self, phase: str) -> None:
        self._completed_phases.add(phase)
        self._save_state()

    def is_phase_complete(self, phase: str) -> bool:
        return phase in self._completed_phases

    async def run_phase(self, phase: str) -> None:
        """
        Execute all modules registered for the given phase.

        Later phases will likely introduce richer scheduling, progress
        reporting, and partial resumption. Phase 1 keeps this interface
        intentionally small.
        """
        if self._stop_requested:
            self._logger.warning("Skipping phase %s due to stop request.", phase)
            return

        if self.is_phase_complete(phase):
            self._logger.info("Skipping phase %s (already completed).", phase)
            return

        modules: List[ModuleDescriptor] = list(self.registry.iter_by_phase(phase))
        if not modules:
            self._logger.warning("No modules registered for phase %s", phase)
            return

        self._logger.info("Running phase %s with %d modules", phase, len(modules))

        async def _run_single(desc: ModuleDescriptor) -> None:
            if self._stop_requested:
                return
            try:
                self._logger.info("Starting module %s", desc.name)
                await desc.instance.run()
                self._logger.info("Completed module %s", desc.name)
            except Exception as exc:  # noqa: BLE001
                self._logger.error("Module %s failed: %s", desc.name, exc, exc_info=True)

        # Run modules concurrently
        await asyncio.gather(*[_run_single(m) for m in modules])

        if not self._stop_requested:
            self._mark_phase_complete(phase)

    async def run_all(self, phases: Iterable[str]) -> None:
        """
        Convenience method to run multiple phases sequentially.
        """
        for phase in phases:
            if self._stop_requested:
                self._logger.warning("Scan paused by user.")
                break
            await self.run_phase(phase)
        
        if self._stop_requested:
            self._logger.info("Scan stopped gracefully. Resume by re-running the command.")
        else:
            self._logger.info("Scan completed successfully.")
