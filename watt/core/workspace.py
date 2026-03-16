from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from .config import WattConfig
from .logging import get_logger


class Workspace:
    """
    Manages on-disk state for a WATT run.

    Phase 1 responsibilities:
    - Ensure directory layout exists
    - Persist and load run configuration
    - Provide simple key/value state for modules
    """

    CONFIG_FILENAME = "config.json"

    def __init__(self, config: WattConfig) -> None:
        self._config = config
        self._root: Path = config.workspace.root
        self._logger = get_logger(__name__)

    @property
    def root(self) -> Path:
        return self._root

    @property
    def config(self) -> WattConfig:
        return self._config

    def initialize(self) -> None:
        """
        Create required directories and write initial configuration snapshot.
        """
        ws = self._config.workspace
        for d in (ws.root, ws.runs_dir, ws.logs_dir, ws.cache_dir):
            d.mkdir(parents=True, exist_ok=True)
        self._write_config_snapshot()

    def _write_config_snapshot(self) -> None:
        config_path = self._config_path()
        try:
            payload = self._config.model_dump(mode="json")
            config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            self._logger.error("Failed to persist workspace config: %s", exc)

    def _config_path(self) -> Path:
        if self._config.workspace.run_id:
            run_dir = self._config.workspace.runs_dir / self._config.workspace.run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            return run_dir / self.CONFIG_FILENAME
        return self._config.workspace.root / self.CONFIG_FILENAME

    # Simple key/value state for modules ---------------------------------

    def _kv_dir(self, namespace: str) -> Path:
        safe_ns = namespace.replace("/", "_")
        d = self._config.workspace.cache_dir / "state" / safe_ns
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_state(self, namespace: str, key: str, value: Dict[str, Any]) -> None:
        """
        Persist a JSON-serializable dictionary under a namespace/key.
        """
        path = self._kv_dir(namespace) / f"{key}.json"
        try:
            path.write_text(json.dumps(value, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            self._logger.error("Failed to write workspace state %s/%s: %s", namespace, key, exc)

    def read_state(self, namespace: str, key: str) -> Optional[Dict[str, Any]]:
        """
        Load previously persisted state if it exists.
        """
        path = self._kv_dir(namespace) / f"{key}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            self._logger.error("Failed to read workspace state %s/%s: %s", namespace, key, exc)
            return None

