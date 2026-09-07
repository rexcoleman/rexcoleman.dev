"""Focused polarity and contract tests for the s212 whole-arc rail."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
TOOL = ROOT / "s212_wea_credential_recovery.py"
WRAPPER = ROOT / "s212_wea_credential_recovery.sh"
WORKFLOW = REPO / ".github/workflows/probe-wea-credentials.yml"

SPEC = importlib.util.spec_from_file_location("s212_recovery", TOOL)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def test_self_test_and_python_syntax():
    result = subprocess.run(
        [sys.executable, str(TOOL), "--self-test"],
        capture_output=True, text=True, check=False,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"second_pat_failure_has_zero_writes": true' in result.stdout


def test_owner_wrapper_is_no_argument_tty_bound_and_apply_only():
    raw = WRAPPER.read_text(encoding="utf-8")
    assert "[[ $# -ne 0 ]]" in raw
    assert "[[ ! -t 0 || ! -t 1 ]]" in raw
    assert "PYTHONDONTWRITEBYTECODE=1" in raw
    assert '"$ROOT/s212_wea_credential_recovery.py" --apply' in raw
    assert "--preflight" not in raw  # apply owns and repeats its preflight
    result = subprocess.run(
        ["bash", "-n", str(WRAPPER)], capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_apply_orders_preflight_and_reuse_probe_before_any_prompt_or_write():
    raw = TOOL.read_text(encoding="utf-8")
    body = raw[raw.index("def apply()") : raw.index("def self_test()")]
    assert body.index("preflight(active_write_probe=True") < body.index("dispatch_probe()")
    assert body.index("dispatch_probe()") < body.index("prompt_pat_pair()")
    assert body.index("prompt_pat_pair()") < body.index("place_legacy_pair(")
    assert body.index("obtain_app_pair()") < body.index("place_app_pair(")


def test_partial_app_pair_refuses_without_fallback(monkeypatch):
    monkeypatch.setenv(tool.APP_ID, "123")
    monkeypatch.delenv(tool.APP_KEY, raising=False)
    assert tool.app_state() == "PARTIAL"


def test_second_pat_failure_occurs_before_any_placement(monkeypatch):
    answers = iter(["bundle-secret", "ruleset-secret"])
    monkeypatch.setattr(tool.getpass, "getpass", lambda _prompt: next(answers))
    monkeypatch.setattr(tool, "authenticate_bundle", lambda _value: True)
    monkeypatch.setattr(tool, "authenticate_ruleset", lambda _value: False)
    writes = []
    monkeypatch.setattr(tool, "set_secret", lambda *row: writes.append(row))
    with pytest.raises(tool.Refusal, match="RULESET_PAT_AUTHENTICATION_REFUSED:no_writes"):
        tool.prompt_pat_pair()
    assert writes == []


def test_postcondition_failure_restores_new_local_env(monkeypatch):
    monkeypatch.setattr(tool, "preflight", lambda **_kwargs: {"source_commit": "a" * 40})
    monkeypatch.setattr(tool, "dispatch_probe", lambda: {
        "issuer": {"bundle": "PASS", "ruleset": "PASS"},
        "renewal": {"bundle": "PASS", "ruleset": "PASS"},
        "approver": {},
    })
    monkeypatch.setattr(tool, "obtain_app_pair", lambda: ("123", "encoded", True, None))
    monkeypatch.setattr(tool, "place_app_pair", lambda *_args: (_ for _ in ()).throw(tool.Refusal("planted")))
    restored = []
    monkeypatch.setattr(tool, "restore_env", lambda old: restored.append(old))
    with pytest.raises(tool.Refusal, match="planted"):
        tool.apply()
    assert restored == [None]


def test_app_partial_placement_forward_completes_all_six_rows(monkeypatch):
    calls = []
    failed = {2}

    def planted(name, environment, value):
        calls.append((name, environment, value))
        if len(calls) in failed:
            failed.remove(len(calls))
            raise tool.Refusal("planted")

    monkeypatch.setattr(tool, "set_secret", planted)
    with pytest.raises(tool.Refusal, match="APP_PLACEMENT_POSTCONDITION_RECOVERED_RETRY"):
        tool.place_app_pair("123", "encoded")
    recovery = calls[2:]
    assert recovery == [
        (name, environment, value)
        for environment in tool.ENVIRONMENTS
        for name, value in ((tool.APP_ID, "123"), (tool.APP_KEY, "encoded"))
    ]


def test_app_pem_requires_regular_mode_0600(monkeypatch, tmp_path):
    pem = tmp_path / "key.pem"
    pem.write_bytes(b"-----BEGIN PRIVATE KEY-----\n" + b"x" * 256)
    pem.chmod(0o644)
    answers = iter(["123", str(pem)])
    monkeypatch.setattr(tool, "local_app_credentials", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    with pytest.raises(tool.Refusal, match="APP_PRIVATE_KEY_MODE_REFUSED"):
        tool.obtain_app_pair()


def test_public_install_failure_drives_safe_transition_rollback(monkeypatch):
    monkeypatch.setattr(tool, "secret_names", lambda _environment: {})
    monkeypatch.setattr(tool, "variable_values", lambda _environment: {})
    monkeypatch.setattr(tool, "public_key_state", lambda: {
        "present": True, "valid": True, "sha256": tool.PREDECESSOR_SHA,
    })
    monkeypatch.setattr(tool, "issuer_binding", lambda: ("a" * 40, "b" * 64))
    monkeypatch.setattr(tool, "set_variable", lambda *_args: None)
    monkeypatch.setattr(tool, "set_secret", lambda *_args: None)
    monkeypatch.setattr(
        tool, "install_public_key",
        lambda *_args: (_ for _ in ()).throw(tool.Refusal("planted install postcondition")),
    )
    deleted = []
    rolled_back = []
    monkeypatch.setattr(tool, "delete_approver_principal_rows", lambda: deleted.append(True))
    monkeypatch.setattr(tool, "rollback_public_key_transition", lambda sha: rolled_back.append(sha))
    with pytest.raises(tool.Refusal, match="APPROVER_PRINCIPAL_TRANSITION_ROLLED_BACK"):
        tool.ensure_approver_principal()
    assert deleted == [True]
    assert len(rolled_back) == 1


def test_wrong_repository_set_is_a_refusal(monkeypatch):
    class Fake:
        OWNER = tool.OWNER
        REQUIRED_REPOSITORIES = frozenset({"govML"})
    fake_spec = type("Spec", (), {"loader": type("Loader", (), {
        "exec_module": staticmethod(lambda module: module.__dict__.update(Fake.__dict__))
    })()})()
    monkeypatch.setattr(tool.importlib.util, "spec_from_file_location", lambda *_args: fake_spec)
    monkeypatch.setattr(tool.importlib.util, "module_from_spec", lambda _spec: type("M", (), {})())
    with pytest.raises(tool.Refusal, match="MINTER_REPOSITORY_SET_REFUSED"):
        tool._load_minter()


def test_non_tty_refuses(monkeypatch):
    monkeypatch.setattr(tool.socket, "gethostname", lambda: "gios-dev")
    monkeypatch.setattr(tool.os, "getuid", lambda: 1000)
    monkeypatch.setattr(tool.getpass, "getuser", lambda: "azureuser")
    monkeypatch.setattr(tool.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(tool.sys.stdout, "isatty", lambda: True)
    with pytest.raises(tool.Refusal, match="OWNER_TTY_REQUIRED"):
        tool.ensure_identity(True)


def test_renewal_policy_requires_main_and_generation_tag(monkeypatch):
    environment = {
        "id": 1,
        "protection_rules": [{"type": "branch_policy"}],
        "deployment_branch_policy": {
            "protected_branches": False, "custom_branch_policies": True,
        },
    }
    policies = {
        "branch_policies": [
            {"name": "main", "type": "branch"},
            {"name": "rea-wea-generation-*", "type": "tag"},
        ],
    }
    monkeypatch.setattr(
        tool, "gh_json",
        lambda argv: policies if "deployment-branch-policies" in argv[-1] else environment,
    )
    assert tool.environment_policy(tool.ENV_RENEWAL) == environment
    policies["branch_policies"].pop()
    with pytest.raises(tool.Refusal, match="ENVIRONMENT_BRANCH_POLICY_REFUSED"):
        tool.environment_policy(tool.ENV_RENEWAL)


def test_changed_deployed_source_refuses(monkeypatch, tmp_path):
    commit_file = tmp_path / "DEPLOYED_COMMIT"
    commit_file.write_text("a" * 40 + "\n", encoding="ascii")
    monkeypatch.setattr(tool, "DEPLOYED_COMMIT", commit_file)
    monkeypatch.setattr(tool, "SOURCE_PATHS", (
        ".github/write-enforcement/s212_wea_credential_recovery.py",
    ))
    monkeypatch.setattr(tool, "remote_main", lambda _repo: "a" * 40)

    def fake_command(argv, **_kwargs):
        if "fetch" in argv:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "show" in argv:
            return SimpleNamespace(returncode=0, stdout="planted drift\n", stderr="")
        raise AssertionError(argv)

    monkeypatch.setattr(tool, "command", fake_command)
    with pytest.raises(tool.Refusal, match="DEPLOYED_SOURCE_CHANGED"):
        tool.bind_deployed_source()


def test_command_timeout_is_a_refusal(monkeypatch):
    def timed_out(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="gh", timeout=1)
    monkeypatch.setattr(tool.subprocess, "run", timed_out)
    with pytest.raises(tool.Refusal, match="COMMAND_UNAVAILABLE:gh"):
        tool.command(["gh", "api", "user"], timeout=1)


def test_hosted_probe_reports_only_status_not_secret_values(monkeypatch, capsys):
    monkeypatch.setenv(tool.BUNDLE_TOKEN, "bundle-value-must-not-print")
    monkeypatch.setenv(tool.RULESET_TOKEN, "ruleset-value-must-not-print")
    monkeypatch.setattr(tool, "app_state", lambda: "ABSENT")
    monkeypatch.setattr(tool, "authenticate_bundle", lambda _value: True)
    monkeypatch.setattr(tool, "authenticate_ruleset", lambda _value: True)
    assert tool.hosted_probe("issuer", "s212-" + "a" * 24) == 0
    output = capsys.readouterr().out
    assert "bundle=PASS ruleset=PASS" in output
    assert "bundle-value" not in output
    assert "ruleset-value" not in output


def test_approver_probe_cryptographically_binds_private_to_public_sha(monkeypatch, capsys):
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    monkeypatch.setattr(tool, "app_state", lambda: "PASS")
    monkeypatch.setenv(tool.APPROVER_PRIVATE, private_pem)
    monkeypatch.setenv(tool.APPROVER_PUBLIC_SHA, tool.digest(public))
    monkeypatch.setenv(tool.ISSUER_COMMIT, "a" * 40)
    monkeypatch.setenv(tool.ISSUER_SHA, "b" * 64)
    assert tool.hosted_probe("approver", "s212-" + "c" * 24) == 0
    assert "principal=PASS" in capsys.readouterr().out
    monkeypatch.setenv(tool.APPROVER_PUBLIC_SHA, "d" * 64)
    assert tool.hosted_probe("approver", "s212-" + "e" * 24) == 0
    assert "principal=ABSENT" in capsys.readouterr().out


def test_probe_workflow_has_exact_three_loci_and_current_source():
    raw = WORKFLOW.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    jobs = doc["jobs"]
    assert {name: jobs[name]["environment"] for name in jobs} == {
        "issuer": tool.ENV_ISSUER,
        "renewal": tool.ENV_RENEWAL,
        "approver": tool.ENV_APPROVER,
    }
    assert raw.count("persist-credentials: false") == 3
    assert raw.count("PYTHONDONTWRITEBYTECODE=1") == 3
    assert raw.count("s212_wea_credential_recovery.py") == 3


def test_no_forbidden_activation_or_mac_surface_in_rail():
    raw = TOOL.read_text(encoding="utf-8") + WRAPPER.read_text(encoding="utf-8")
    for forbidden in (
        "workflow run issue-write-enforcement-attestation",
        "git tag", "freeze_builder", "ssh mac-mini", "F3 --apply",
    ):
        assert forbidden not in raw


def test_complete_pair_precedence_is_in_current_selector():
    selector = (ROOT / "select_governed_read_credential.py").read_text(encoding="utf-8")
    assert "if app_id and app_key:" in selector
    assert "if app_id or app_key:" in selector
    assert selector.index("if app_id and app_key:") < selector.index("if app_id or app_key:")
    assert "GOVERNED_READ_APP_PAIR_PARTIAL" in selector
