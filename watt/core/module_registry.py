from __future__ import annotations

import importlib.util
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Protocol, runtime_checkable

from .logging import get_logger
from watt.modules.base import ModuleContext, SimpleModule


@runtime_checkable
class Module(Protocol):
    """
    Minimal interface for a WATT module.

    Modules are phase-specific (e.g. recon, crawler, jsintel) and will be
    registered with the controller via this interface.
    """

    name: str
    phase: str

    async def run(self) -> None:  # pragma: no cover - will be implemented in later phases
        ...


@dataclass
class ModuleDescriptor:
    name: str
    phase: str
    instance: Module


class ModuleRegistry:
    """
    Registry and lifecycle coordinator for WATT modules.

    Phase 1 focuses on:
    - registration
    - simple lookup by name/phase
    """

    def __init__(self) -> None:
        self._modules: Dict[str, ModuleDescriptor] = {}
        self._logger = get_logger(__name__)

    def register(self, module: Module) -> None:
        if module.name in self._modules:
            self._logger.warning("Module %s is already registered; overwriting", module.name)
        self._modules[module.name] = ModuleDescriptor(
            name=module.name,
            phase=module.phase,
            instance=module,
        )

    def load_plugins(self, plugins_dir: Path, ctx: ModuleContext) -> None:
        """
        Dynamically load modules from a directory.
        """
        if not plugins_dir.is_dir():
            self._logger.debug("Plugins directory not found, skipping: %s", plugins_dir)
            return

        self._logger.info("Loading plugins from: %s", plugins_dir)
        for file_path in plugins_dir.glob("*.py"):
            if file_path.name.startswith("_"):
                continue

            module_name = file_path.stem
            try:
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                if not spec or not spec.loader:
                    continue

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, SimpleModule) and obj is not SimpleModule:
                        self._logger.info("Found plugin module: %s", name)
                        plugin_instance = obj(ctx)
                        self.register(plugin_instance)
            except Exception as e:
                self._logger.error("Failed to load plugin from %s: %s", file_path, e, exc_info=True)

    def list_modules(self) -> List[ModuleDescriptor]:
        return list(self._modules.values())

    def iter_by_phase(self, phase: str) -> Iterable[ModuleDescriptor]:
        for desc in self._modules.values():
            if desc.phase == phase:
                yield desc

    def get(self, name: str) -> ModuleDescriptor | None:
        return self._modules.get(name)
