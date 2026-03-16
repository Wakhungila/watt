from pathlib import Path

from watt.core.config import WattConfig
from watt.core.logging import LoggerContext, configure_logging, get_logger
from watt.core.workspace import Workspace


def _make_config(tmp_path: Path) -> WattConfig:
    return WattConfig.from_cli(
        targets=["example.com"],
        workspace_root=tmp_path,
        log_level="INFO",
        json_logs=False,
    )


def test_workspace_initialization_creates_directories(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    ws = Workspace(cfg)
    ws.initialize()

    assert cfg.workspace.root.exists()
    assert cfg.workspace.logs_dir.exists()
    assert cfg.workspace.cache_dir.exists()
    assert cfg.workspace.runs_dir.exists()


def test_workspace_state_roundtrip(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    ws = Workspace(cfg)
    ws.initialize()

    ws.write_state("test_ns", "k1", {"value": 42})
    loaded = ws.read_state("test_ns", "k1")

    assert loaded is not None
    assert loaded["value"] == 42


def test_logging_configuration(tmp_path: Path) -> None:
    cfg = _make_config(tmp_path)
    ctx = LoggerContext(workspace=cfg.workspace, logging=cfg.logging)
    configure_logging(ctx)
    logger = get_logger("test")

    logger.info("hello from test logger")

