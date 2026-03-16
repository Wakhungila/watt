from pathlib import Path

import pytest

from watt.core.config import WattConfig


def test_config_from_cli_basic(tmp_path: Path) -> None:
    cfg = WattConfig.from_cli(
        targets=["example.com", "https://api.example.com/v1/users"],
        workspace_root=tmp_path,
        log_level="debug",
        json_logs=True,
    )

    assert len(cfg.targets) == 2
    assert cfg.targets[0].kind in {"domain", "subdomain"}
    assert cfg.targets[1].kind == "url"
    assert cfg.workspace.root == tmp_path
    assert cfg.logging.level == "DEBUG"
    assert cfg.logging.json_logs is True


def test_config_requires_targets(tmp_path: Path) -> None:
    with pytest.raises(Exception):
        WattConfig.from_cli(targets=[], workspace_root=tmp_path)

