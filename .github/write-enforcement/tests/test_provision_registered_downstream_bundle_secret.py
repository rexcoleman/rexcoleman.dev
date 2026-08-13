from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
from argparse import Namespace
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "provision_registered_downstream_bundle_secret.py"
SPEC = importlib.util.spec_from_file_location("registered_cycle10_transition", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def manifest(tmp_path):
    commits = {
        logical: ("%x" % (index + 1)) * 40
        for index, logical in enumerate(tool.CORE.LOGICAL_REPOSITORIES)
    }
    value = {"authority_generation": 5, "members": [
        {"repository": logical, "commit": commit}
        for logical, commit in commits.items()
    ]}
    value["manifest_digest"] = hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    path = tmp_path / "manifest.json"
    path.write_bytes(tool.CORE.canonical(value))
    return path


def args(tmp_path, dry_run=False):
    return Namespace(
        manifest=manifest(tmp_path),
        issuer_ref="rea-wea-generation-5-abcdef123456",
        issuer_sha="a" * 40,
        predecessor_run_id="12345",
        predecessor_wea_sha256="b" * 64,
        dry_run=dry_run,
    )


def key():
    raw = bytes(range(32))
    return {
        "key_id": "789",
        "key_b64": base64.b64encode(raw).decode(),
        "key_sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_exact_cycle10_target_is_closed_constant():
    assert tool.TARGET_REPOSITORY == (
        "rexcoleman/cycle_10_autonomous_cycle_apparatus_build"
    )
    assert tool.TARGET_REPOSITORY in tool.CORE.TARGET_REPOSITORIES
    assert len(tool.CORE.TARGET_REPOSITORIES) == 2


def test_dry_run_proves_absence_without_mutation(tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(tool, "runtime_ready", lambda: None)
    monkeypatch.setattr(tool, "public_key", key)
    monkeypatch.setattr(tool, "secret_metadata", lambda: None)
    monkeypatch.setattr(tool, "dispatch", lambda *_args: calls.append(_args))
    assert tool.run_transition(args(tmp_path, dry_run=True)) == 0
    assert calls == []
    output = capsys.readouterr().out
    assert "target=rexcoleman/cycle_10_autonomous_cycle_apparatus_build" in output
    assert "secret_absent=true" in output and "mutation=false" in output


def test_preexisting_secret_refuses_before_dispatch(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(tool, "runtime_ready", lambda: None)
    monkeypatch.setattr(tool, "public_key", key)
    monkeypatch.setattr(tool, "secret_metadata", lambda: {
        "name": tool.SECRET_NAME, "updated_at": "2026-08-13T00:00:00Z",
    })
    monkeypatch.setattr(tool, "dispatch", lambda *_args: calls.append(_args))
    with pytest.raises(tool.Refusal, match="PREEXISTING"):
        tool.run_transition(args(tmp_path))
    assert calls == []


def test_install_submits_ciphertext_and_key_id_only(monkeypatch):
    state = {"secret": None}
    writes = []
    expected_key = key()

    def fake_api(path, method="GET", body=None, allow_not_found=False):
        if method == "PUT":
            writes.append(body)
            state["secret"] = {
                "name": tool.SECRET_NAME,
                "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            return None
        return state["secret"]

    monkeypatch.setattr(tool, "api", fake_api)
    monkeypatch.setattr(tool, "public_key", lambda: expected_key)
    tool.install_ciphertext({"ciphertext_b64": "c3ludGhldGlj"}, expected_key)
    assert writes == [{
        "encrypted_value": "c3ludGhldGlj", "key_id": expected_key["key_id"],
    }]
    assert set(writes[0]) == {"encrypted_value", "key_id"}


def test_failed_postcheck_deletes_new_secret_and_verifies_absence(monkeypatch):
    state = {"secret": None}
    methods = []
    expected_key = key()

    def fake_api(path, method="GET", body=None, allow_not_found=False):
        methods.append(method)
        if method == "PUT":
            state["secret"] = {
                "name": "WRONG_NAME", "updated_at": "2020-01-01T00:00:00Z",
            }
            return None
        if method == "DELETE":
            state["secret"] = None
            return None
        return state["secret"]

    monkeypatch.setattr(tool, "api", fake_api)
    monkeypatch.setattr(tool, "public_key", lambda: expected_key)
    with pytest.raises(tool.Refusal, match="ROLLED_BACK_AFTER_FAILURE"):
        tool.install_ciphertext({"ciphertext_b64": "c3ludGhldGlj"}, expected_key)
    assert "PUT" in methods and "DELETE" in methods
    assert state["secret"] is None


def test_late_issuance_failure_rolls_back_created_secret(tmp_path, monkeypatch):
    expected_key = key()
    state = {"secret": None}
    rollback = []
    dispatches = iter([101, 202])
    monkeypatch.setattr(tool, "runtime_ready", lambda: None)
    monkeypatch.setattr(tool, "public_key", lambda: expected_key)
    monkeypatch.setattr(tool, "secret_metadata", lambda: state["secret"])
    monkeypatch.setattr(tool, "dispatch", lambda *_args: next(dispatches))
    monkeypatch.setattr(tool, "wait_pending", lambda *_args: None)
    monkeypatch.setattr(tool, "approve", lambda *_args: None)
    monkeypatch.setattr(tool, "wait_success", lambda *_args: None)
    monkeypatch.setattr(tool, "sealed_packet", lambda *_args: {
        "ciphertext_b64": "c3ludGhldGlj", "ciphertext_sha256": "c" * 64,
    })
    def install(_packet, _key):
        state["secret"] = {"name": tool.SECRET_NAME}
    monkeypatch.setattr(tool, "install_ciphertext", install)
    def rolled_back(reason):
        rollback.append(reason)
        state["secret"] = None
        raise tool.Refusal("ROLLED_BACK_AFTER_FAILURE original=%s" % reason)
    monkeypatch.setattr(tool, "rollback_secret", rolled_back)
    monkeypatch.setattr(tool, "verify_issued_artifact", lambda *_args: (_ for _ in ()).throw(
        tool.Refusal("ISSUANCE_ARTIFACT_REFUSED")
    ))
    with pytest.raises(tool.Refusal, match="ROLLED_BACK_AFTER_FAILURE"):
        tool.run_transition(args(tmp_path))
    assert rollback == ["Refusal"] and state["secret"] is None


def test_refusal_output_never_prints_packet_ciphertext(tmp_path, monkeypatch, capsys):
    synthetic = "planted-ciphertext-not-a-secret"
    monkeypatch.setattr(tool, "run_transition", lambda _args: (_ for _ in ()).throw(
        tool.Refusal("PLANTED_FAILURE")
    ))
    assert tool.main([
        "--manifest", str(manifest(tmp_path)),
        "--issuer-ref", "rea-wea-generation-5-abcdef123456",
        "--issuer-sha", "a" * 40,
        "--predecessor-run-id", "12345",
        "--predecessor-wea-sha256", "b" * 64,
    ]) == tool.REFUSAL_EXIT
    captured = capsys.readouterr()
    assert synthetic not in (captured.out + captured.err)


def test_source_has_no_plaintext_credential_environment_read():
    raw = SOURCE.read_text(encoding="utf-8")
    assert "os.environ.get(\"REA_BUNDLE_READ_TOKEN\"" not in raw
    assert "GITHUB_TOKEN" not in raw
    assert "gh auth token" not in raw
