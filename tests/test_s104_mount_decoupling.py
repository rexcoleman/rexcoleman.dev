from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts/blog_publish_mount.py"


def load():
    spec = importlib.util.spec_from_file_location("s104_blog_mount", PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_production_path_is_installed_consumer_not_research_worktree():
    module = load()
    assert "research_enforcement_activation" not in str(
        module.INSTALLED_RUNTIME_MOUNT
    )
    source = PATH.read_text()
    assert "os.environ" not in source
    assert "getenv(" not in source
    assert "ISOLATED_RUNTIME_MOUNT" not in source
