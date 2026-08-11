import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
GITHUB_DIR = ROOT.parent
sys.path.insert(0, str(ROOT))

import checkout_manifest  # noqa: E402
import issue_wea  # noqa: E402
from member_contract import (  # noqa: E402
    AUTHORITY_GENERATION,
    GENERATION_MANIFEST_NAME,
    normalize_ruleset,
)


def workflow(name: str) -> tuple[str, dict]:
    raw = (GITHUB_DIR / "workflows" / name).read_text(encoding="utf-8")
    return raw, yaml.load(raw, Loader=yaml.BaseLoader)


def test_issuer_and_verifier_workflow_syntax_and_secret_wiring():
    issuer_raw, issuer = workflow("issue-write-enforcement-attestation.yml")
    verifier_raw, verifier = workflow("verify-write-enforcement.yml")
    assert isinstance(issuer, dict) and isinstance(verifier, dict)
    assert "ubuntu-24.04" in issuer_raw and "ubuntu-latest" not in issuer_raw
    assert "ubuntu-24.04" in verifier_raw and "ubuntu-latest" not in verifier_raw
    assert "REA_BUNDLE_READ_TOKEN" in issuer_raw
    assert "REA_BUNDLE_READ_TOKEN" in verifier["on"]["workflow_call"]["secrets"]
    assert GENERATION_MANIFEST_NAME in issuer_raw
    for raw in (issuer_raw, verifier_raw):
        assert "actions/checkout@v4" not in raw
        assert "actions/upload-artifact@v4" not in raw
        assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in raw
        assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in raw


def test_manifest_loader_accepts_exact_current_generation_only(tmp_path):
    value = {
        "schema_version": "rea.write.enforcement-bundle-manifest.v1",
        "authority_generation": AUTHORITY_GENERATION,
        "ruleset_id": 19564990,
        "members": [{"member_id": "x"}],
    }
    unsigned = dict(value)
    value["manifest_digest"] = issue_wea.digest(issue_wea.canonical(unsigned))
    path = tmp_path / GENERATION_MANIFEST_NAME
    path.write_bytes(issue_wea.canonical(value))
    assert issue_wea.load_manifest(path)["authority_generation"] == 5
    value["authority_generation"] = 2
    unsigned = {key: item for key, item in value.items() if key != "manifest_digest"}
    value["manifest_digest"] = issue_wea.digest(issue_wea.canonical(unsigned))
    path.write_bytes(issue_wea.canonical(value))
    with pytest.raises(ValueError, match="manifest contract"):
        issue_wea.load_manifest(path)


def test_issuer_checksum_uses_manifest_directory_and_runs_hosted_verifier():
    issuer_raw, _ = workflow("issue-write-enforcement-attestation.yml")
    assert "(cd issuance && sha256sum -c SHA256SUMS)" in issuer_raw
    assert "sha256sum -c issuance/SHA256SUMS" not in issuer_raw
    assert "Verify issued WEA on hosted runner" in issuer_raw
    assert (
        "python3 repos/rexcoleman.dev/.github/write-enforcement/"
        "verify_hosted_wea.py"
    ) in issuer_raw
    assert "--issuance issuance --workspace repos" in issuer_raw


def test_issuer_artifact_is_closed_public_only_and_never_exports_private_key():
    issuer_raw, _ = workflow("issue-write-enforcement-attestation.yml")
    source = (ROOT / "issue_wea.py").read_text(encoding="utf-8")
    assert "PUBLIC_ONLY_ARTIFACT_PASS files=11 private_key_copy=absent" in issuer_raw
    assert "cmp -s issuance/" in issuer_raw
    assert "BEGIN ([A-Z0-9]+ )*PRIVATE KEY" in issuer_raw
    assert "hybrid_provider_private" not in source
    assert "--hybrid-private-key" not in source
    assert "hybrid_capability_authority.json" in source
    assert 'provider_path.write_bytes(loaded["hybrid-capability-provider"])' in source


def test_issuer_refuses_workflow_byte_drift_before_signing(
        monkeypatch, tmp_path):
    ruleset = {
        "id": 19564990,
        "name": "newsletter-main-integrity",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"],
                                     "exclude": []}},
        "rules": [],
        "bypass_actors": [],
    }
    ruleset_path = tmp_path / "ruleset.json"
    ruleset_path.write_text(json.dumps(ruleset), encoding="utf-8")
    manifest = {
        "normalized_ruleset_sha256": issue_wea.digest(
            issue_wea.canonical(normalize_ruleset(ruleset))
        )
    }
    monkeypatch.setattr(issue_wea, "load_manifest", lambda _path: manifest)
    monkeypatch.setattr(
        issue_wea,
        "verify_members",
        lambda _manifest, _workspace: {
            "remote-issuer-workflow": b"frozen-workflow"
        },
    )
    monkeypatch.setattr(
        issue_wea,
        "committed_bytes",
        lambda _root, _commit, _path: b"post-freeze-workflow-mutation",
    )
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setattr(sys, "argv", [
        "issue_wea.py",
        "--manifest", str(tmp_path / GENERATION_MANIFEST_NAME),
        "--workspace", str(tmp_path / "workspace"),
        "--ruleset-json", str(ruleset_path),
            "--private-key", str(tmp_path / "private.pem"),
            "--output", str(tmp_path / "output"),
            "--predecessor-wea", str(tmp_path / "predecessor.json"),
            "--predecessor-wea-sha256", "0" * 64,
        ])
    with pytest.raises(ValueError, match="workflow byte drift"):
        issue_wea.main()
    assert not (tmp_path / "output").exists()


def test_post_freeze_bound_member_mutation_refuses(monkeypatch, tmp_path):
    repository = tmp_path / "workspace" / "research_enforcement_activation"
    repository.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email",
         "s88-fixture@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "s88 fixture"],
        check=True,
    )
    relative = "protected/member.txt"
    member = repository / relative
    member.parent.mkdir()
    member.write_bytes(b"post-freeze-mutated")
    subprocess.run(["git", "-C", str(repository), "add", relative], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    monkeypatch.setattr(
        issue_wea,
        "EXPECTED_MEMBERS",
        {"protected-member": ("research_enforcement_activation", relative)},
    )
    required_classes = [
        "boundary_gate", "resolver", "readiness_consumer",
        "live_emitter_binding", "master_runner_binding",
        "project_runner_binding", "scaffold_installer", "remote_workflow",
        "invocation_receipt", "close_readiness_gate",
        "remote_ruleset", "claim_policy", "profile_registry",
        "trusted_public_key",
    ]
    manifest = {
        "required_member_classes": required_classes,
        "members": [{
            "member_id": "protected-member",
            "repository": "research_enforcement_activation",
            "commit": commit,
            "path": relative,
            "sha256": issue_wea.digest(b"pre-freeze"),
            "byte_length": len(b"pre-freeze"),
        }],
    }
    with pytest.raises(ValueError, match="member mismatch: protected-member"):
        issue_wea.verify_members(manifest, tmp_path / "workspace")


def test_private_checkout_requires_named_token_before_git(monkeypatch, tmp_path):
    calls = []
    monkeypatch.delenv(checkout_manifest.TOKEN_ENV, raising=False)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    manifest = {
        "members": [
            {"repository": name, "commit": "a" * 40}
            for name in checkout_manifest.ORIGINS
        ] + [{"repository": "rexcoleman.dev", "commit": "b" * 40}]
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["checkout_manifest.py", str(manifest_path), str(tmp_path / "repos")])
    with pytest.raises(ValueError, match=checkout_manifest.TOKEN_ENV):
        checkout_manifest.main()
    assert calls == []


def test_private_checkout_token_never_enters_git_argv_or_askpass_file(monkeypatch, tmp_path):
    token = "unit-test-sensitive-value"
    observed = []
    monkeypatch.setenv(checkout_manifest.TOKEN_ENV, token)

    def capture(command, **kwargs):
        env = kwargs["env"]
        helper = Path(env["GIT_ASKPASS"])
        observed.append((command, helper.read_text(encoding="utf-8"), env))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", capture)
    manifest = {
        "members": [
            {"repository": name, "commit": "a" * 40}
            for name in checkout_manifest.ORIGINS
        ] + [{"repository": "rexcoleman.dev", "commit": "b" * 40}]
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["checkout_manifest.py", str(manifest_path), str(tmp_path / "repos")])
    assert checkout_manifest.main() == 0
    assert len(observed) == len(checkout_manifest.ORIGINS) * 3
    for command, helper_raw, env in observed:
        assert token not in "\n".join(command)
        assert token not in helper_raw
        assert env[checkout_manifest.TOKEN_ENV] == token
        assert "GH_TOKEN" not in env and "GITHUB_TOKEN" not in env
