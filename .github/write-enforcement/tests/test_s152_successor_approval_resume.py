from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import io
import json
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
        "status": "waiting", "conclusion": "",
        "headSha": tool.REVIEW_WORKFLOW_SHA, "headBranch": "main",
    })
    monkeypatch.setattr(tool, "pending_environment", lambda _run: 7)
    monkeypatch.setattr(tool, "downstream_public_key", lambda: {
        "key_id": "9", "key_b64": "x", "key_sha256": "a" * 64,
    })
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
        "status": "waiting", "conclusion": "",
        "headSha": tool.REVIEW_WORKFLOW_SHA, "headBranch": "main",
    })
    monkeypatch.setattr(tool, "approve", lambda run, purpose: order.append("approve-%s" % run))
    monkeypatch.setattr(tool, "wait_success", lambda run, head, attempts, purpose: {
        "headBranch": "main" if run == tool.REVIEW_RUN_ID else tool.ISSUER_TAG,
        "headSha": head,
    })
    monkeypatch.setattr(tool, "merge_manifest_pr", lambda: order.append("merge"))
    monkeypatch.setattr(tool, "create_tag", lambda: order.append("tag"))
    key = {"key_id": "9", "key_b64": "x", "key_sha256": "a" * 64}
    monkeypatch.setattr(tool, "downstream_public_key", lambda: key)
    runs = iter([100, 200])
    monkeypatch.setattr(tool, "dispatch_workflow", lambda *args: next(runs))
    monkeypatch.setattr(tool, "sealed_packet", lambda *_args: {
        "ciphertext_b64": "YQ==", "ciphertext_sha256": "b" * 64,
    })
    monkeypatch.setattr(tool, "submit_ciphertext", lambda *_args: order.append("submit"))
    monkeypatch.setattr(tool, "wait_owner_gate", lambda run: order.append("wait-owner"))
    monkeypatch.setattr(tool, "verify_artifact", lambda run: order.append("artifact"))
    assert tool.run() == 0
    assert order == ["approve-%s" % tool.REVIEW_RUN_ID, "verify-True", "merge",
                     "tag", "wait-owner", "approve-100", "submit",
                     "wait-owner", "approve-200", "artifact"]


def test_predecessor_advance_between_preflight_and_execution_is_accepted(monkeypatch):
    ready(monkeypatch)
    snapshots = [
        {"run_id": 10, "epoch": 3, "wea_sha256": "a" * 64},
        {"run_id": 11, "epoch": 4, "wea_sha256": "b" * 64},
        {"run_id": 11, "epoch": 4, "wea_sha256": "b" * 64},
        {"run_id": 11, "epoch": 4, "wea_sha256": "b" * 64},
    ]
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **_kwargs: None)
    monkeypatch.setattr(tool, "pending_environment", lambda _run: 7)
    monkeypatch.setattr(tool, "downstream_public_key", lambda: {
        "key_id": "9", "key_b64": "x", "key_sha256": "a" * 64,
    })
    monkeypatch.setattr(tool, "run_state", lambda run: {
        "status": "waiting", "conclusion": "",
        "headSha": tool.REVIEW_WORKFLOW_SHA, "headBranch": "main",
    })
    monkeypatch.setattr(tool, "create_tag", lambda: None)
    dispatched = []
    monkeypatch.setattr(tool, "dispatch_workflow", lambda snap, *_args: dispatched.append(snap) or 99)
    monkeypatch.setattr(tool, "sealed_packet", lambda *_args: {
        "ciphertext_b64": "YQ==", "ciphertext_sha256": "b" * 64,
    })
    monkeypatch.setattr(tool, "submit_ciphertext", lambda *_args: None)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda _run: None)
    monkeypatch.setattr(tool, "approve", lambda *_args: None)
    monkeypatch.setattr(tool, "wait_success", lambda run, *_args: {
        "headBranch": "main" if run == tool.REVIEW_RUN_ID else tool.ISSUER_TAG,
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
    monkeypatch.setattr(tool, "dispatch_workflow", lambda snap, *_args: dispatched.append(snap))
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


def test_public_key_drift_refuses_before_secret_write(monkeypatch):
    first = {"key_id": "1", "key_b64": "a", "key_sha256": "b" * 64}
    second = {"key_id": "2", "key_b64": "c", "key_sha256": "d" * 64}
    monkeypatch.setattr(tool, "downstream_public_key", lambda: second)
    writes = []
    monkeypatch.setattr(tool, "api", lambda *args, **kwargs: writes.append(args))
    try:
        tool.submit_ciphertext({"ciphertext_b64": "e", "ciphertext_sha256": "f" * 64}, first)
    except tool.Refusal as exc:
        assert str(exc) == "DOWNSTREAM_PUBLIC_KEY_DRIFT"
    else:
        raise AssertionError("key drift admitted")
    assert writes == []


def test_secret_put_empty_json_response_is_accepted(monkeypatch):
    key = {"key_id": "1", "key_b64": "a", "key_sha256": "b" * 64}
    monkeypatch.setattr(tool, "downstream_public_key", lambda: key)
    calls = []
    def fake_api(path, method="GET", body=None):
        calls.append((path, method, body))
        if method == "PUT":
            return {}
        return {"name": tool.SECRET_NAME, "updated_at": dt.datetime.now(
            dt.timezone.utc).isoformat()}
    monkeypatch.setattr(tool, "api", fake_api)
    tool.submit_ciphertext({"ciphertext_b64": "x"}, key)
    assert calls[0][1] == "PUT"


def test_sealed_packet_rejects_ciphertext_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(tool.tempfile, "TemporaryDirectory", lambda **_kwargs: (
        _Temporary(tmp_path)
    ))
    monkeypatch.setattr(tool, "api", lambda *_args, **_kwargs: {
        "artifacts": [{"name": "rea-downstream-sealed-secret-7", "expired": False,
                       "workflow_run": {"id": 7}}],
    })
    (tmp_path / "sealed-transfer.json").write_text(
        '{"ciphertext_sha256":"wrong"}', encoding="utf-8"
    )
    monkeypatch.setattr(tool, "command", lambda *_args, **_kwargs: "")
    try:
        tool.sealed_packet(7, {"key_id": "1", "key_sha256": "a" * 64})
    except tool.Refusal as exc:
        assert str(exc) == "SEALED_PACKET_REFUSED"
    else:
        raise AssertionError("ciphertext substitution admitted")


def test_immutable_manifest_ignores_stale_worktree_path(monkeypatch, tmp_path):
    stale = tmp_path / "frozen_bundle_manifest.generation-5.json"
    stale.write_text('{"manifest_digest":"9881"}', encoding="utf-8")
    exact = {"authority_generation": 5, "manifest_digest": tool.MANIFEST_DIGEST,
             "members": [{}] * 247}
    raw = json.dumps(exact, separators=(",", ":")).encode()
    monkeypatch.setattr(tool, "MANIFEST_FILE_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(tool, "api", lambda *_args, **_kwargs: {
        "content": base64.b64encode(raw).decode("ascii"),
    })
    assert tool.immutable_manifest_bytes() == raw
    assert tool.immutable_manifest_bytes() != stale.read_bytes()


def test_coach_resume_uses_preserved_seal_and_stops_at_owner_gate(monkeypatch):
    monkeypatch.setattr(tool, "coach_runtime_ready", lambda: None)
    predecessor = {"run_id": 12, "wea_sha256": "a" * 64}
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: predecessor)
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **kwargs: None)
    monkeypatch.setattr(tool, "verify_issuer_tag", lambda: None)
    monkeypatch.setattr(tool, "run_state", lambda run: {
        "status": "completed", "conclusion": "success",
        "headSha": tool.REVIEW_WORKFLOW_SHA if run == tool.REVIEW_RUN_ID else tool.MANIFEST_HEAD,
        "headBranch": "main" if run == tool.REVIEW_RUN_ID else tool.ISSUER_TAG,
    })
    key = {"key_id": "1", "key_b64": "x", "key_sha256": "b" * 64}
    packet = {"ciphertext_b64": "e", "ciphertext_sha256": "c" * 64}
    monkeypatch.setattr(tool, "downstream_public_key", lambda: key)
    monkeypatch.setattr(tool, "sealed_packet", lambda run, observed: packet)
    calls = []
    monkeypatch.setattr(tool, "submit_ciphertext", lambda *_args: calls.append("submit"))
    monkeypatch.setattr(tool, "dispatch_workflow", lambda *_args: calls.append("dispatch") or 99)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda run: calls.append("wait"))
    monkeypatch.setattr(tool, "approve", lambda *_args: calls.append("approve"))
    assert tool.coach_resume_sealed() == 0
    assert calls == ["submit", "dispatch", "wait"]


def test_capability_approval_is_exact_run_only(monkeypatch):
    ready(monkeypatch)
    calls = []
    monkeypatch.setattr(tool, "run_state", lambda run: {
        "status": "waiting", "conclusion": "", "headSha": tool.MANIFEST_HEAD,
        "headBranch": tool.ISSUER_TAG,
    })
    monkeypatch.setattr(tool, "pending_environment", lambda run: tool.CAPABILITY_ENVIRONMENT_ID)
    monkeypatch.setattr(tool, "capability_job", lambda: {
        "status": "waiting", "conclusion": None,
    })
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: {
        "run_id": tool.CAPABILITY_PREDECESSOR_RUN_ID,
        "wea_sha256": tool.CAPABILITY_PREDECESSOR_WEA_SHA256,
    })
    monkeypatch.setattr(tool, "preserved_packet_identity", lambda: calls.append(("packet", tool.PRESERVED_SEAL_RUN_ID)))
    monkeypatch.setattr(tool, "approve", lambda run, purpose: calls.append(("approve", run)))
    monkeypatch.setattr(tool, "wait_success", lambda run, *_args: {
        "headBranch": tool.ISSUER_TAG,
    })
    job_calls = iter([
        {"status": "waiting", "conclusion": None},
        {"status": "completed", "conclusion": "success"},
    ])
    monkeypatch.setattr(tool, "capability_job", lambda: next(job_calls))
    monkeypatch.setattr(tool, "verify_artifact", lambda run: calls.append(("artifact", run)))
    assert tool.approve_capability_run() == 0
    assert calls == [("packet", tool.PRESERVED_SEAL_RUN_ID),
                     ("approve", tool.CAPABILITY_RUN_ID),
                     ("artifact", tool.CAPABILITY_RUN_ID)]


def test_capability_preflight_refuses_predecessor_drift(monkeypatch):
    ready(monkeypatch)
    monkeypatch.setattr(tool, "run_state", lambda _run: {
        "status": "waiting", "conclusion": "", "headSha": tool.MANIFEST_HEAD,
        "headBranch": tool.ISSUER_TAG,
    })
    monkeypatch.setattr(tool, "pending_environment", lambda _run: tool.CAPABILITY_ENVIRONMENT_ID)
    monkeypatch.setattr(tool, "capability_job", lambda: {
        "status": "waiting", "conclusion": None,
    })
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: {
        "run_id": tool.CAPABILITY_PREDECESSOR_RUN_ID + 1,
        "wea_sha256": tool.CAPABILITY_PREDECESSOR_WEA_SHA256,
    })
    monkeypatch.setattr(tool, "preserved_packet_identity", lambda: None)
    try:
        tool.preflight_capability_run()
    except tool.Refusal as exc:
        assert str(exc) == "CAPABILITY_OWNER_GATE_REFUSED"
    else:
        raise AssertionError("drifted predecessor admitted")


class _Temporary:
    def __init__(self, path):
        self.path = path
    def __enter__(self):
        return str(self.path)
    def __exit__(self, *_args):
        return False


def test_direct_helper_refuses(monkeypatch):
    monkeypatch.delenv("REA_S152_CHECKED_WRAPPER", raising=False)
    try:
        tool.runtime_ready()
    except tool.Refusal as exc:
        assert str(exc) == "CHECKED_WRAPPER_REQUIRED"
    else:
        raise AssertionError("direct helper admitted")


def test_withdrawn_v3_marker_refuses(monkeypatch):
    monkeypatch.setenv("REA_S152_CHECKED_WRAPPER", "rea-s152-sealed-successor-approval-v3")
    monkeypatch.setattr(tool.socket, "gethostname", lambda: tool.HOST)
    monkeypatch.setattr(tool.os, "geteuid", lambda: 1000)
    try:
        tool.runtime_ready()
    except tool.Refusal as exc:
        assert str(exc) == "CHECKED_WRAPPER_REQUIRED"
    else:
        raise AssertionError("withdrawn v3 marker admitted")


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
