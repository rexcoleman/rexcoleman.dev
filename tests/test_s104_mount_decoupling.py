from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts/blog_publish_mount.py"


def load():
    spec = importlib.util.spec_from_file_location("s104_blog_mount", PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_production_path_is_installed_consumer_not_research_worktree(monkeypatch):
    module = load()
    monkeypatch.delenv(module.ISOLATED_MOUNT_ENV, raising=False)
    assert module.runtime_mount_path() == module.INSTALLED_RUNTIME_MOUNT
    assert "research_enforcement_activation" not in str(
        module.INSTALLED_RUNTIME_MOUNT
    )


def test_isolated_override_requires_explicit_isolated_context(monkeypatch):
    module = load()
    monkeypatch.setenv(module.ISOLATED_MOUNT_ENV, "/tmp/runtime_mount.py")
    monkeypatch.delenv(module.ISOLATED_CONTEXT_ENV, raising=False)
    with pytest.raises(RuntimeError, match="ISOLATED_HARNESS_REQUIRED"):
        module.runtime_mount_path()
