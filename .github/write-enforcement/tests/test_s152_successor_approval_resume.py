from __future__ import annotations

import importlib.util
import io
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "s152_successor_approval_resume.py"
SPEC = importlib.util.spec_from_file_location("s152_successor_approval_resume", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class TTY(io.StringIO):
    def isatty(self):
        return True


def ready(monkeypatch):
    monkeypatch.setenv("REA_S152_CHECKED_WRAPPER", tool.MARKER)
    monkeypatch.setattr(tool.socket, "gethostname", lambda: "gios-dev")
    monkeypatch.setattr(tool.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(tool.sys, "stdin", TTY())
    monkeypatch.setattr(tool.sys, "stdout", TTY())
    monkeypatch.setattr(tool.sys, "stderr", TTY())
    monkeypatch.setattr(tool, "command", lambda *_args, **_kwargs: "")


def test_preflight_is_nonmutating(monkeypatch):
    ready(monkeypatch)
    mutations = []
    snapshot = {"run_id": 12, "epoch": 4}
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: snapshot)
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **_kwargs: None)
    monkeypatch.setattr(tool, "run_state", lambda _run: {
        "status": "completed", "conclusion": "success",
        "headSha": tool.REVIEW_WORKFLOW_SHA, "headBranch": "main",
    })
    monkeypatch.setattr(tool, "verify_issuer_tag", lambda: None)
    monkeypatch.setattr(tool, "approve", lambda *_args: mutations.append("approve"))
    monkeypatch.setattr(tool, "create_tag", lambda: mutations.append("tag"))
    assert tool.preflight() == 0
    assert mutations == []


def test_full_arc_order(monkeypatch):
    ready(monkeypatch)
    order = []
    predecessor = {"run_id": 12, "wea_sha256": "a" * 64}
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: predecessor)
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda *args, **kwargs: order.append(
        "verify-%s" % kwargs.get("require_open")))
    monkeypatch.setattr(tool, "run_state", lambda _run: {
        "status": "completed", "conclusion": "success",
        "headSha": tool.REVIEW_WORKFLOW_SHA, "headBranch": "main",
    })
    monkeypatch.setattr(tool, "approve", lambda run, purpose: order.append("approve-%s" % run))
    monkeypatch.setattr(tool, "wait_success", lambda run, head, attempts, purpose: {
        "headBranch": "main" if run == tool.REVIEW_RUN_ID else tool.ISSUER_TAG,
        "headSha": head,
    })
    monkeypatch.setattr(tool, "merge_manifest_pr", lambda: order.append("merge"))
    monkeypatch.setattr(tool, "create_tag", lambda: order.append("tag"))
    monkeypatch.setattr(tool, "dispatch_issuer", lambda snapshot: 999)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda run: order.append("wait-owner"))
    monkeypatch.setattr(tool, "verify_artifact", lambda run: order.append("artifact"))
    assert tool.run() == 0
    assert order == ["verify-False", "tag", "wait-owner", "approve-999", "artifact"]


def test_predecessor_advance_between_preflight_and_execution_is_accepted(monkeypatch):
    ready(monkeypatch)
    snapshots = [
        {"run_id": 10, "epoch": 3, "wea_sha256": "a" * 64},
        {"run_id": 11, "epoch": 4, "wea_sha256": "b" * 64},
        {"run_id": 11, "epoch": 4, "wea_sha256": "b" * 64},
    ]
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **_kwargs: None)
    monkeypatch.setattr(tool, "verify_issuer_tag", lambda: None)
    monkeypatch.setattr(tool, "run_state", lambda run: {
        "status": "completed", "conclusion": "success",
        "headSha": tool.REVIEW_WORKFLOW_SHA, "headBranch": "main",
    })
    monkeypatch.setattr(tool, "create_tag", lambda: None)
    dispatched = []
    monkeypatch.setattr(tool, "dispatch_issuer", lambda snap: dispatched.append(snap) or 99)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda _run: None)
    monkeypatch.setattr(tool, "approve", lambda *_args: None)
    monkeypatch.setattr(tool, "wait_success", lambda *_args: {
        "headBranch": tool.ISSUER_TAG,
    })
    monkeypatch.setattr(tool, "verify_artifact", lambda _run: None)
    assert tool.preflight() == 0
    assert tool.run() == 0
    assert dispatched[0]["run_id"] == 11


def test_predecessor_drift_after_review_before_dispatch_refuses(monkeypatch):
    ready(monkeypatch)
    snapshots = [
        {"run_id": 11, "epoch": 4, "wea_sha256": "b" * 64},
        {"run_id": 12, "epoch": 5, "wea_sha256": "c" * 64},
    ]
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **_kwargs: None)
    monkeypatch.setattr(tool, "run_state", lambda run: {
        "status": "completed", "conclusion": "success",
        "headSha": tool.REVIEW_WORKFLOW_SHA, "headBranch": "main",
    })
    monkeypatch.setattr(tool, "create_tag", lambda: None)
    dispatched = []
    monkeypatch.setattr(tool, "dispatch_issuer", lambda snap: dispatched.append(snap))
    try:
        tool.run()
    except tool.Refusal as exc:
        assert str(exc) == "PREDECESSOR_DRIFT_REFUSED"
    else:
        raise AssertionError("predecessor drift admitted")
    assert dispatched == []


def test_malformed_predecessor_receipt_refuses(monkeypatch, tmp_path):
    monkeypatch.setattr(tool, "INSTALLED", tmp_path)
    for name in (
        "write_enforcement_attestation.json", "enforcement_bundle_manifest.json",
        "predecessor_write_enforcement_attestation.json",
    ):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    (tmp_path / "issuance_receipt.json").write_text("not-json", encoding="utf-8")
    try:
        tool.predecessor_snapshot()
    except tool.Refusal as exc:
        assert str(exc) == "PREDECESSOR_JSON_REFUSED"
    else:
        raise AssertionError("malformed predecessor admitted")


def test_old_wrapper_is_structural_tombstone():
    old = ROOT / "s152_successor_approval_checked_wrapper.sh"
    value = old.read_text(encoding="utf-8")
    assert "WITHDRAWN_DYNAMIC_PREDECESSOR_REQUIRED" in value
    assert "s152_successor_approval_resume.py" not in value


def valid_status_receipt():
    digest = "a" * 64
    status = {
        "verdict": "PASS", "state": "ENFORCING", "authority_generation": 4,
        "predecessor_verified": True, "remote_issued": True,
        "state_digest": digest, "enforcement_bundle_manifest_digest": "b" * 64,
        "workflow_run_id": 11, "authority_epoch": 20,
        "issued_at": "2026-08-12T02:47:35Z",
    }
    receipt = {
        "schema_version": tool.RECEIPT_SCHEMA, "event": "workflow_dispatch",
        "issuer": tool.ISSUER_URL, "workflow_repository": tool.REPOSITORY,
        "workflow_run_attempt": 1, "workflow_run_id": 11,
        "wea_sha256": digest, "manifest_sha256": "b" * 64,
        "issued_at": status["issued_at"], "workflow_sha": "c" * 40,
        "workflow_blob_sha256": "d" * 64,
    }
    return status, receipt


def test_wrong_predecessor_wea_hash_refuses():
    status, receipt = valid_status_receipt()
    receipt["wea_sha256"] = "e" * 64
    try:
        tool.validate_status_receipt(status, receipt, "a" * 64, "b" * 64)
    except tool.Refusal as exc:
        assert str(exc) == "PREDECESSOR_RECEIPT_REFUSED"
    else:
        raise AssertionError("wrong predecessor hash admitted")


def test_wrong_predecessor_epoch_refuses():
    status, receipt = valid_status_receipt()
    status["authority_epoch"] = 0
    try:
        tool.validate_status_receipt(status, receipt, "a" * 64, "b" * 64)
    except tool.Refusal as exc:
        assert str(exc) == "PREDECESSOR_VERIFIER_STATUS_REFUSED"
    else:
        raise AssertionError("wrong predecessor epoch admitted")


def test_wrong_generation4_tag_refuses(monkeypatch):
    try:
        tool.verify_generation4_tag({"workflow_ref": "refs/tags/wrong"})
    except tool.Refusal as exc:
        assert str(exc) == "PREDECESSOR_TAG_REFUSED"
    else:
        raise AssertionError("wrong predecessor tag admitted")


def test_direct_helper_refuses(monkeypatch):
    monkeypatch.delenv("REA_S152_CHECKED_WRAPPER", raising=False)
    try:
        tool.runtime_ready()
    except tool.Refusal as exc:
        assert str(exc) == "CHECKED_WRAPPER_REQUIRED"
    else:
        raise AssertionError("direct helper admitted")


def test_pending_environment_requires_exact_approvable_gate(monkeypatch):
    monkeypatch.setattr(tool, "api", lambda path: [{
        "environment": {"id": 8, "name": tool.ENVIRONMENT},
        "current_user_can_approve": False,
    }])
    assert tool.pending_environment(7) is None


def test_wait_success_rejects_wrong_head(monkeypatch):
    monkeypatch.setattr(tool, "run_state", lambda run: {
        "status": "completed", "conclusion": "success", "headSha": "0" * 40,
    })
    try:
        tool.wait_success(7, "1" * 40, 1, "PLANTED")
    except tool.Refusal as exc:
        assert "PLANTED_FAILED" in str(exc)
    else:
        raise AssertionError("wrong head admitted")


def test_constants_bind_public_successor():
    assert tool.ISSUER_TAG == "rea-wea-generation-5-" + tool.MANIFEST_HEAD[:12]
    assert len(tool.MANIFEST_FILE_SHA256) == 64
    assert len(tool.MANIFEST_DIGEST) == 64
