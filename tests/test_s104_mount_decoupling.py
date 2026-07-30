from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts/blog_publish_mount.py"
CONTROL = ROOT / "scripts/rex_hybrid_mount.py"


def load():
    spec = importlib.util.spec_from_file_location("s104_blog_mount", PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_production_path_is_installed_authority_not_research_worktree():
    module = load()
    assert module.consume_exact_bundle.__module__ == "rex_hybrid_mount"
    wrapper_source = PATH.read_text()
    control_source = CONTROL.read_text()
    assert "research_enforcement_activation" not in wrapper_source + control_source
    assert "ISOLATED_RUNTIME_MOUNT" not in wrapper_source + control_source
    assert "INSTALLED_VERIFY_ONLY_PROVIDER" in control_source
    assert ".local/libexec/rea_enforcement/hybrid_capability_provider" in control_source
    provider_block = control_source.split(
        "INSTALLED_VERIFY_ONLY_PROVIDER =", 1
    )[1].split("CANONICAL_REPO =", 1)[0]
    assert "environ" not in provider_block
    assert "getenv(" not in provider_block
