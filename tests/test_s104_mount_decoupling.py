from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
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


def test_exact_protected_mount_executes_honest_and_propagates_provider_refusal(
    tmp_path,
):
    site = tmp_path / "rex-site"
    scripts = site / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(PATH, scripts / PATH.name)
    shutil.copy2(CONTROL, scripts / CONTROL.name)
    runtime = tmp_path / "installed-runtime.py"
    runtime.write_text(
        "from pathlib import Path\n"
        "import hashlib, json\n"
        "class MountRefusal(Exception):\n"
        "    def __init__(self, receipt):\n"
        "        self.receipt=receipt; self.raw_exit=receipt['raw_exit']\n"
        "def atomic_write(**request):\n"
        "    candidate=request['candidate']\n"
        "    if b'UNSUPPORTED' in candidate:\n"
        "        raise MountRefusal({'schema_version':'rea.write.mount-result.v1',"
        "'verdict':'REFUSE','raw_exit':3,"
        "'reason_code':'UNKNOWN_OR_UNSUPPORTED_CLAIM',"
        "'route_id':'BLG-08','surface':'blog','mutation_authorized':False})\n"
        "    Path(request['destination']).write_bytes(candidate)\n"
        "    print(json.dumps({'schema_version':'rea.write.runtime-hybrid-result.v1',"
        "'verdict':'EFFECT_COMMITTED','route_id':'BLG-08','surface':'blog',"
        "'candidate_sha256':hashlib.sha256(candidate).hexdigest(),"
        "'mutation_authorized':True}, sort_keys=True))\n",
        encoding="ascii",
    )
    spec = importlib.util.spec_from_file_location(
        "s127_protected_blog_mount", scripts / PATH.name
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.INSTALLED_RUNTIME_MOUNT = runtime

    def invoke(candidate, destination):
        old_argv = sys.argv
        stdout, stderr = StringIO(), StringIO()
        try:
            sys.argv = [str(scripts / PATH.name), str(candidate), str(destination)]
            with redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    rc = module.main()
                except SystemExit as exc:
                    rc = int(exc.code or 0)
        finally:
            sys.argv = old_argv
        return rc, stdout.getvalue(), stderr.getvalue()

    honest = tmp_path / "honest.md"
    honest.write_bytes(b"Evidence-backed protected blog claim.\n")
    honest_target = tmp_path / "honest-target.md"
    rc, stdout, stderr = invoke(honest, honest_target)
    assert rc == 0 and stderr == ""
    assert honest_target.read_bytes() == honest.read_bytes()
    assert json.loads(stdout)["verdict"] == "EFFECT_COMMITTED"

    planted = tmp_path / "planted.md"
    planted.write_bytes(b"UNSUPPORTED planted claim.\n")
    planted_target = tmp_path / "planted-target.md"
    rc, stdout, stderr = invoke(planted, planted_target)
    assert rc == 3 and stdout == ""
    assert not planted_target.exists()
