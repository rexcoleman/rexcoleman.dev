import ast
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_PYTHON = Path("/usr/bin/python3")
ANNOTATION_MEMBERS = ("cross-post.py", ".github/write-enforcement/checkout_manifest.py")
VERIFIER = ".github/research-integrity/verify_sealed_authority.py"


def _child(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(SYSTEM_PYTHON), "-I", "-B", "-c", code],
        cwd=ROOT,
        env={
            "HOME": "/tmp/rea-s150-rex-python38-home",
            "PATH": "/usr/bin:/bin",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        text=True,
        capture_output=True,
        check=False,
    )


def _guard(raw: str, *, future: bool) -> None:
    assert ".removesuffix(" not in raw
    if future:
        assert "from __future__ import annotations" in raw


def test_signed_rex_members_import_and_suffix_semantics_under_python38():
    raw = (ROOT / VERIFIER).read_text(encoding="utf-8")
    tree = ast.parse(raw)
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "remove_suffix")
    helper_source = ast.get_source_segment(raw, helper)
    code = """
import pathlib, runpy, sys
for path in %r:
    runpy.run_path(path, run_name='s150_python38_probe')
%s
assert remove_suffix('repo.git', '.git') == 'repo'
assert remove_suffix('repo', '.git') == 'repo'
assert remove_suffix('repo', '') == 'repo'
print(sys.version_info[:2])
""" % (ANNOTATION_MEMBERS + (VERIFIER,), helper_source)
    result = _child(code)
    assert result.returncode == 0, result.stderr
    assert "(3, 8)" in result.stdout


def test_source_guard_rejects_replanted_suffix_and_future_removal():
    for path in ANNOTATION_MEMBERS:
        raw = (ROOT / path).read_text(encoding="utf-8")
        _guard(raw, future=True)
        planted = raw.replace("from __future__ import annotations", "", 1)
        try:
            _guard(planted, future=True)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"future-import plant admitted: {path}")
    raw = (ROOT / VERIFIER).read_text(encoding="utf-8")
    _guard(raw, future=False)
    try:
        _guard(raw + "\n'x'.removesuffix('x')\n", future=False)
    except AssertionError:
        pass
    else:
        raise AssertionError("removesuffix plant admitted")
    assert _child("assert not hasattr(str, 'removesuffix'); 'x'.removesuffix('x')").returncode != 0
    assert _child("def planted(value: list[str]):\n    return value\n").returncode != 0
