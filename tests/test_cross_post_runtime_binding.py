import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_cross_post():
    spec = importlib.util.spec_from_file_location(
        "s111_cross_post", ROOT / "cross-post.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cross_post_uses_installed_runtime_and_forwards_exact_bytes(
    tmp_path, monkeypatch
):
    module = load_cross_post()
    runtime = tmp_path / "runtime_mount.py"
    runtime.write_text(
        "def consume_effect(**kwargs):\n"
        "    return kwargs\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "RUNTIME_MOUNT", runtime)
    monkeypatch.setenv("REA_WRITE_INTEGRITY_RUN_ID", "s111-positive")
    callback = lambda exact: {"sha": len(exact)}

    result = module.consume_distribution_effect(
        candidate=b"exact candidate",
        destination="distribution://fixture",
        effect_callback=callback,
    )

    assert result["route_id"] == "DST-02"
    assert result["surface"] == "distribution"
    assert result["candidate"] == b"exact candidate"
    assert result["run_id"] == "s111-positive:cross-post"
    assert result["effect_callback"] is callback


def test_cross_post_refuses_before_callback_when_installed_runtime_missing(
    tmp_path, monkeypatch
):
    module = load_cross_post()
    missing = tmp_path / "missing-runtime.py"
    monkeypatch.setattr(module, "RUNTIME_MOUNT", missing)
    reached = []

    with pytest.raises(FileNotFoundError):
        module.consume_distribution_effect(
            candidate=b"blocked",
            destination="distribution://fixture",
            effect_callback=lambda exact: reached.append(exact),
        )

    assert reached == []


def test_production_binding_is_installed_not_checkout():
    module = load_cross_post()
    assert module.RUNTIME_MOUNT == (
        Path.home() / ".local/libexec/rea_enforcement/runtime_mount.py"
    )
    assert "research_enforcement_activation" not in str(module.RUNTIME_MOUNT)


def test_installed_runtime_follows_disposable_home(tmp_path):
    program = (
        "import importlib.util,sys;"
        "s=importlib.util.spec_from_file_location('isolated_cross',sys.argv[1]);"
        "m=importlib.util.module_from_spec(s);"
        "s.loader.exec_module(m);"
        "print(m.RUNTIME_MOUNT)"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", program, str(ROOT / "cross-post.py")],
        capture_output=True,
        text=True,
        check=False,
        env={
            "HOME": str(tmp_path),
            "PATH": os.environ["PATH"],
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        },
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == str(
        tmp_path / ".local/libexec/rea_enforcement/runtime_mount.py"
    )
