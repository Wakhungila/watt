from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from .config import LoggingSettings, WorkspaceSettings


LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
WATT_HANDLER_NAME = "watt_handler"


@dataclass
class LoggerContext:
    workspace: WorkspaceSettings
    logging: LoggingSettings


def _ensure_log_dirs(workspace: WorkspaceSettings) -> None:
    workspace.logs_dir.mkdir(parents=True, exist_ok=True)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload: Dict[str, Any] = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class WattNamedHandler(logging.Handler):
    """
    Wrapper handler so we can detect if WATT logging is configured.
    """

    def __init__(self, inner: logging.Handler) -> None:
        super().__init__(inner.level)
        self.inner = inner
        self.name = WATT_HANDLER_NAME

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover
        self.inner.emit(record)


def configure_logging(ctx: LoggerContext) -> None:
    """
    Configure root logging handlers.

    This is idempotent; calling it multiple times will not attach
    duplicate handlers.
    """
    _ensure_log_dirs(ctx.workspace)

    root = logging.getLogger()
    if any(getattr(h, "name", None) == WATT_HANDLER_NAME for h in root.handlers):
        # Already configured by WATT in this process.
        return

    level = getattr(logging, ctx.logging.level.upper(), logging.INFO)
    root.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    if ctx.logging.json_logs:
        console_handler.setFormatter(JsonLogFormatter())
    else:
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    root.addHandler(WattNamedHandler(console_handler))

    # File handler
    log_file = ctx.workspace.logs_dir / "watt.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    if ctx.logging.json_logs:
        file_handler.setFormatter(JsonLogFormatter())
    else:
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    root.addHandler(WattNamedHandler(file_handler))


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Convenience accessor for loggers.

    Logging is configured by `configure_logging` before use.
    """
    return logging.getLogger(name or "watt")

