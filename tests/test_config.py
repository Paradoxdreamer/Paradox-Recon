"""Config loading tests."""

import os
from pathlib import Path

from paradox_recon.config import Config, load_config, write_example_config


def test_defaults():
    cfg = Config()
    assert cfg.timeout == 10
    assert cfg.workers == 40
    assert "json" in cfg.formats


def test_env_override(monkeypatch):
    monkeypatch.setenv("PARADOX_TIMEOUT", "25")
    monkeypatch.setenv("PARADOX_PLUGINS", "dns,web")
    cfg = load_config()
    assert cfg.timeout == 25
    assert cfg.plugins == ["dns", "web"]


def test_cli_overrides_win():
    cfg = load_config(overrides={"timeout": 99, "quiet": True})
    assert cfg.timeout == 99
    assert cfg.quiet is True


def test_write_example(tmp_path):
    p = write_example_config(str(tmp_path / "paradox.yaml"))
    assert Path(p).exists()
    assert "timeout" in Path(p).read_text()
