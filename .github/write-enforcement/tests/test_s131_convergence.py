import ast
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


builder = load("build_frozen_manifest")


def test_signed_workflow_pem_loads_bind_explicit_default_backend():
    observed = 0
    for workflow in (
        TOOLS.parent / "workflows/issue-write-enforcement-attestation.yml",
        TOOLS.parent / "workflows/verify-write-enforcement.yml",
    ):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        for job in document["jobs"].values():
            for step in job.get("steps", []):
                script = step.get("run")
                if not isinstance(script, str) or "load_pem_" not in script:
                    continue
                blocks = re.findall(
                    r"python3[^\n]*<<'PY'\n(.*?)\nPY(?:\n|$)",
                    script,
                    flags=re.DOTALL,
                )
                assert blocks, workflow
                for block in blocks:
                    tree = ast.parse(block, filename=str(workflow))
                    calls = [
                        node
                        for node in ast.walk(tree)
                        if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in {
                            "load_pem_private_key", "load_pem_public_key"
                        }
                    ]
                    observed += len(calls)
                    for call in calls:
                        backend = next(
                            (
                                keyword.value
                                for keyword in call.keywords
                                if keyword.arg == "backend"
                            ),
                            None,
                        )
                        assert isinstance(backend, ast.Call), workflow
                        assert isinstance(backend.func, ast.Name), workflow
                        assert backend.func.id == "default_backend", workflow
    assert observed == 7


def test_member_population_is_complete_and_two_method_count():
    contract = load("member_contract")
    assert len(contract.EXPECTED_MEMBERS) == 244
    assert len(set(contract.EXPECTED_MEMBERS.values())) == 244
    successor = contract.successor_members()
    assert len(successor) == 247
    independent = load("independent_review")
    independently_parsed = independent.expected_members()
    assert independently_parsed == successor


def test_authenticated_immediate_predecessor_derives_epoch(tmp_path, monkeypatch):
    issue = load("issue_wea")
    private = tmp_path / "private.pem"; public = tmp_path / "public.pem"
    private_key = Ed25519PrivateKey.generate()
    private.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public.write_bytes(issue.public_bytes(private_key))
    assert issue.public_bytes(issue.load_private_key(private)) == public.read_bytes()
    payload = {
        "schema_version": "rea.write.wea.live.v2", "purpose": "LIVE_ENFORCEMENT",
        "state": "ENFORCING", "authority_epoch": 8,
        "issuer": issue.ISSUER,
    }
    monkeypatch.setattr(
        issue.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("crypto path invoked a subprocess")
        ),
    )
    signed = issue.sign_payload(payload, private)
    predecessor = tmp_path / "predecessor.json"
    predecessor.write_bytes(issue.canonical(signed) + b"\n")
    raw, verified = issue.authenticated_predecessor(predecessor, public)
    assert verified["authority_epoch"] + 1 == 9
    value = json.loads(raw); value["authority_epoch"] = 9
    predecessor.write_bytes(issue.canonical(value) + b"\n")
    try:
        issue.authenticated_predecessor(predecessor, public)
    except issue.IssuerRefusal as exc:
        assert exc.reason_code == "PREDECESSOR_WEA_INVALID"
    else:
        raise AssertionError("tampered predecessor accepted")

    predecessor.write_bytes(issue.canonical(signed) + b"\n")
    wrong = Ed25519PrivateKey.generate()
    public.write_bytes(issue.public_bytes(wrong))
    with pytest.raises(issue.IssuerRefusal) as caught:
        issue.authenticated_predecessor(predecessor, public)
    assert caught.value.reason_code == "PREDECESSOR_WEA_INVALID"


def test_system_python_fixed_path_uses_python_ed25519_backend(tmp_path):
    code = r'''
import importlib.util
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import cryptography
import sys
module_path = Path(sys.argv[1])
root = Path(sys.argv[2])
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("fixed_issue_wea", module_path)
issue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(issue)
key = Ed25519PrivateKey.generate()
private = root / "private.pem"
public = root / "public.pem"
private.write_bytes(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
))
public.write_bytes(issue.public_bytes(key))
payload = {
    "schema_version": "rea.write.wea.live.v2",
    "purpose": "LIVE_ENFORCEMENT",
    "state": "ENFORCING",
    "authority_epoch": 8,
    "issuer": issue.ISSUER,
}
issue.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
    AssertionError("crypto path invoked a subprocess")
)
signed = issue.sign_payload(payload, private)
predecessor = root / "predecessor.json"
predecessor.write_bytes(issue.canonical(signed) + b"\n")
raw, verified = issue.authenticated_predecessor(predecessor, public)
assert json.loads(raw)["authority_epoch"] == verified["authority_epoch"] == 8
print("SYSTEM_PYTHON_ED25519_PASS")
print(cryptography.__file__)
'''
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    env = {
        "HOME": str(isolated_home),
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    result = subprocess.run(
        [
            "/usr/bin/python3", "-B", "-c", code,
            str(TOOLS / "issue_wea.py"), str(tmp_path),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    lines = result.stdout.strip().splitlines()
    assert lines[0] == "SYSTEM_PYTHON_ED25519_PASS"
    assert "/usr/lib/python3/dist-packages/cryptography" in lines[1]
    assert "/home/azureuser/.local" not in lines[1]
    assert "miniconda" not in lines[1]


def test_remote_reachability_exact_sha_and_unreachable(monkeypatch):
    builder = load("build_frozen_manifest")
    class Result:
        returncode = 0; stdout = "a" * 40 + "\n"; stderr = ""
    monkeypatch.setattr(builder.subprocess, "run", lambda *a, **k: Result())
    builder.verify_remote_reachability("govML", "a" * 40)
    try:
        builder.verify_remote_reachability("govML", "b" * 40)
    except ValueError as exc:
        assert "unreachable" in str(exc)
    else:
        raise AssertionError("mismatched authoritative SHA accepted")


def test_predecessor_preflight_is_before_owner_environment_and_digest_bound():
    workflow = (TOOLS.parent / "workflows/issue-write-enforcement-attestation.yml").read_text()
    preflight = workflow.index("preflight-predecessor:")
    issue = workflow.index("issue-wea:")
    environment = workflow.index("environment: rea-write-enforcement-issuer")
    assert preflight < issue < environment
    assert "needs: preflight-predecessor" in workflow
    assert "predecessor_wea_sha256" in workflow
    assert "PREDECESSOR_RUN_IDENTITY" not in workflow  # checks are executable, not a claim label
    assert "sha256sum predecessor/write_enforcement_attestation.json" in workflow
    assert "public.verify(value, bytes.fromhex(digest))" in workflow
    assert "openssl" not in workflow
    assert "pkeyutl" not in workflow
    backend_marker = "PYTHON_ED25519_BACKEND_READY"
    renew_preflight = workflow.index("  renew-preflight:")
    renew_issue = workflow.index("  renew-wea:")
    assert workflow.count(backend_marker) == 4
    assert backend_marker in workflow[preflight:issue]
    assert backend_marker in workflow[issue:renew_preflight]
    assert backend_marker in workflow[renew_preflight:renew_issue]
    assert backend_marker in workflow[renew_issue:]
    assert workflow.index(backend_marker, preflight, issue) < environment
    assert "expired_fixture" not in workflow
    issuer = (TOOLS / "issue_wea.py").read_text()
    assert '"openssl"' not in issuer
    assert "pkeyutl" not in issuer
    assert "dispatch_digest_mismatch" in issuer
    assert "expired_fixture" not in issuer


def _candidate_roots() -> dict[str, Path]:
    names = {
        "research_enforcement_activation": "S131_ROOT_REA",
        "govML": "S131_ROOT_GOVML",
        "Moonshots_Career_Thesis_v2": "S131_ROOT_MOONSHOTS",
        "newsletter": "S131_ROOT_NEWSLETTER",
        "rexcoleman.dev": "S131_ROOT_REX",
    }
    if any(not os.environ.get(variable) for variable in names.values()):
        pytest.skip("exact S131 five-root integration environment not supplied")
    roots = {name: Path(os.environ[variable]).resolve()
             for name, variable in names.items()}
    assert len(roots) == 5 and all(root.is_dir() for root in roots.values())
    return roots


def _commit(root: Path, message: str) -> None:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-q", "-m", message],
        check=True,
    )


def _materialize_candidate_subjects(
    tmp_path: Path, source_roots: dict[str, Path], contract,
) -> dict[str, Path]:
    tmp_path.mkdir(parents=True)
    roots = {}
    for repository, specs in builder.MEMBERS.items():
        root = tmp_path / repository
        root.mkdir()
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email",
             "s131-correction5@example.invalid"], check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name",
             "S131 correction 5 fixture"], check=True,
        )
        for _member_id, relative in specs:
            source = source_roots[repository] / relative
            assert source.is_file() and not source.is_symlink(), source
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            # The frozen contract binds executable modes as well as bytes.
            # Preserve the exact candidate tree mode in this synthetic Git
            # repository so the integration test exercises that contract.
            shutil.copy2(source, destination)
        if repository == "govML":
            for subjects in contract.EXPECTED_EMITTER_RUNTIME_INSTALLATIONS.values():
                _authoring_repository, relative = subjects["authoring"]
                source = source_roots[repository] / relative
                destination = root / relative
                if not destination.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
            for _logical_id, (_repository, relative, _mode) in (
                contract.PACKAGED_BUILD_PROFILE_GATE_SOURCES.items()
            ):
                source = source_roots[repository] / relative
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                destination.chmod(0o755)
        _commit(root, "exact candidate subjects")
        roots[repository] = root
    assert set(roots) == set(contract.grouped_members())
    return roots


def _ruleset(path: Path) -> None:
    path.write_text(json.dumps({
        "id": 19564990,
        "name": "newsletter-main-integrity",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"],
                                    "exclude": []}},
        "rules": [],
        "bypass_actors": [],
    }), encoding="utf-8")


def _run_five_root_builder(monkeypatch, roots, ruleset, output):
    arguments = [
        "build_frozen_manifest.py", "--output", str(output),
        "--ruleset-json", str(ruleset),
    ]
    for repository in builder.MEMBERS:
        slug = repository.lower().replace("_", "-").replace(".", "-")
        arguments.extend(["--root-" + slug, str(roots[repository])])
    monkeypatch.setattr(sys, "argv", arguments)
    return builder.main()


def test_exact_five_candidate_roots_close_installed_runtime_population(
    tmp_path, monkeypatch,
):
    """Run the real builder and all four runtime-path negative controls."""
    contract = load("member_contract")
    source_roots = _candidate_roots()
    roots = _materialize_candidate_subjects(tmp_path / "roots", source_roots, contract)
    ruleset = tmp_path / "ruleset.json"
    _ruleset(ruleset)
    monkeypatch.setattr(builder, "verify_remote_reachability", lambda *_: None)

    honest = tmp_path / "honest" / contract.GENERATION_MANIFEST_NAME
    honest.parent.mkdir()
    assert _run_five_root_builder(monkeypatch, roots, ruleset, honest) == 0
    assert len(json.loads(honest.read_bytes())["members"]) == 244

    destination, subjects = next(iter(
        contract.EXPECTED_EMITTER_RUNTIME_INSTALLATIONS.items()
    ))
    removed_subject = tuple(subjects["installed"])
    reduced = dict(builder.EXPECTED_MEMBERS)
    removed_id = next(member_id for member_id, subject in reduced.items()
                      if subject == removed_subject)
    del reduced[removed_id]
    monkeypatch.setattr(builder, "EXPECTED_MEMBERS", reduced)
    with pytest.raises(ValueError, match="unsigned installed runtime path"):
        _run_five_root_builder(
            monkeypatch, roots, ruleset,
            tmp_path / "unsigned" / contract.GENERATION_MANIFEST_NAME,
        )
    monkeypatch.setattr(builder, "EXPECTED_MEMBERS", contract.EXPECTED_MEMBERS)

    govml = roots["govML"]
    installed_path = govml / removed_subject[1]
    installed_raw = installed_path.read_bytes()
    installed_path.unlink()
    _commit(govml, "planted missing installed runtime")
    # The frozen-population opener may refuse the removed signed member before
    # the later installation-closure classifier sees the same missing path.
    # Both are fail-closed and precede manifest emission.
    with pytest.raises(
        ValueError,
        match=(
            "missing installed runtime path|"
            "frozen population member unavailable:"
            f"{removed_id}:"
        ),
    ):
        _run_five_root_builder(
            monkeypatch, roots, ruleset,
            tmp_path / "missing" / contract.GENERATION_MANIFEST_NAME,
        )
    installed_path.write_bytes(installed_raw)
    _commit(govml, "restore missing control")

    authoring_entry = govml / "scripts/generators/gen_blog_post.py"
    authoring_raw = authoring_entry.read_bytes()
    authoring_entry.write_bytes(authoring_raw + b"\nimport s131_extra_runtime\n")
    (govml / "scripts/generators/s131_extra_runtime.py").write_text(
        "VALUE = 1\n", encoding="ascii"
    )
    (govml / "templates/build/enforcement/s131_extra_runtime.py").write_text(
        "VALUE = 1\n", encoding="ascii"
    )
    _commit(govml, "planted extra installed runtime")
    with pytest.raises(
        ValueError,
        match="runtime set mismatch.*extra|EMITTER_RUNTIME_CLOSURE_DRIFT",
    ):
        _run_five_root_builder(
            monkeypatch, roots, ruleset,
            tmp_path / "extra" / contract.GENERATION_MANIFEST_NAME,
        )
    authoring_entry.write_bytes(authoring_raw)
    (govml / "scripts/generators/s131_extra_runtime.py").unlink()
    (govml / "templates/build/enforcement/s131_extra_runtime.py").unlink()
    _commit(govml, "restore extra control")

    installed_path.write_bytes(installed_raw + b"# planted divergence\n")
    _commit(govml, "planted installed runtime divergence")
    with pytest.raises(ValueError, match="installed runtime digest divergence"):
        _run_five_root_builder(
            monkeypatch, roots, ruleset,
            tmp_path / "divergent" / contract.GENERATION_MANIFEST_NAME,
        )
    assert destination.startswith("scripts/publishing_emitters/")
