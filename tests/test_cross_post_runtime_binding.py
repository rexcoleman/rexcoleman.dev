import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def load_cross_post():
    spec = importlib.util.spec_from_file_location(
        "s123_cross_post", ROOT / "cross-post.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cross_post_forwards_one_exact_data_only_bundle(
    tmp_path, monkeypatch
):
    module = load_cross_post()
    post = tmp_path / "exact-post.md"
    post.write_text(
        "---\ntitle: Exact\ntags: [research]\n---\n\n"
        "## Result\n\nThe bounded result reached 42% in this sample.\n",
        encoding="utf-8",
    )
    captured = []
    monkeypatch.setattr(
        module,
        "consume_exact_bundle",
        lambda **kwargs: captured.append(kwargs) or {"verdict": "EFFECT_COMMITTED"},
    )
    monkeypatch.setattr(sys, "argv", ["cross-post.py", str(post)])

    assert module.main() == 0
    assert len(captured) == 1
    call = captured[0]
    assert call["route_id"] == "DST-02"
    decoded = json.loads(call["candidate"])
    assert {
        row["path"]
        for row in decoded["members"]
        if not row["path"].startswith(".rea/")
    } == {
        "cross-posts/exact-post_devto.md",
        "cross-posts/exact-post_linkedin.txt",
        "cross-posts/exact-post_reddit.md",
    }
    assert "effect_callback" not in call


def test_production_binding_uses_installed_verify_only_provider():
    module = load_cross_post()
    assert module.consume_exact_bundle.__module__ == "rex_hybrid_mount"
    control = (ROOT / "scripts/rex_hybrid_mount.py").read_text()
    assert "research_enforcement_activation" not in control
    assert "INSTALLED_VERIFY_ONLY_PROVIDER" in control
    assert "effect_callback" not in control


def test_installed_provider_follows_disposable_home(tmp_path):
    program = (
        "import sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "import rex_hybrid_mount as m;"
        "print(m.INSTALLED_VERIFY_ONLY_PROVIDER)"
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(ROOT / "scripts"),
        ],
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
        tmp_path
        / ".local/libexec/rea_enforcement/hybrid_capability_provider"
    )
