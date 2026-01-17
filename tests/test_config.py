import os
from pathlib import Path
import pytest
from ands.config import Config, ANDSConfigError

def test_config_singleton():
    c1 = Config()
    c2 = Config()
    assert c1 is c2

def test_config_default_values():
    config = Config()
    assert config.get("network.timeout") is not None
    assert config.get("network.retries") == 3
    assert config.get("general.version") == 1.0

def test_config_dot_notation():
    config = Config()
    config.set("a.b.c", 123)
    assert config.get("a.b.c") == 123
    assert config.get("a.b") == {"c": 123}

def test_config_env_override(monkeypatch):
    monkeypatch.setenv("ANDS_TIMEOUT", "99")
    config = Config()
    config.load()
    assert config.get("network.timeout") == 99

def test_config_load_file(tmp_path, monkeypatch):
    config_file = tmp_path / "ands.config.yaml"
    config_file.write_text("network:\n  timeout: 123\n")

    # We need to trick Config into loading this file.
    # It looks at CWD or ANDS_CONFIG.
    monkeypatch.setenv("ANDS_CONFIG", str(config_file))

    config = Config()
    config.load()
    assert config.get("network.timeout") == 123
    # Check that defaults still exist
    assert config.get("network.retries") == 3

def test_config_deep_update():
    config = Config()
    base = {"a": {"b": 1, "c": 2}}
    update = {"a": {"b": 3}}
    config._deep_update(base, update)
    assert base == {"a": {"b": 3, "c": 2}}
