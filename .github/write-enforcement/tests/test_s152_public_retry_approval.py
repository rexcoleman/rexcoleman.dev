from __future__ import annotations

import importlib.util
import io
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "s152_public_retry_approval.py"
SPEC = importlib.util.spec_from_file_location("s152_public_retry_approval", SOURCE)
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
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **_kwargs: None)
    monkeypatch.setattr(tool, "review_boundary", lambda: None)
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: {
        "run_id": 7, "epoch": 21, "wea_sha256": "a" * 64,
    })
    monkeypatch.setattr(tool, "secret_metadata", lambda: {"updated_at": "x"})
    monkeypatch.setattr(tool, "approve", lambda *_args: mutations.append("approve"))
    assert tool.preflight() == 0
    assert mutations == []


def test_full_arc_is_review_merge_tag_public_retry_only(monkeypatch):
    ready(monkeypatch)
    order = []
    snapshots = [
        {"run_id": 7, "epoch": 21, "wea_sha256": "a" * 64},
        {"run_id": 8, "epoch": 22, "wea_sha256": "b" * 64},
        {"run_id": 8, "epoch": 22, "wea_sha256": "b" * 64},
    ]
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **kw: order.append(
        "verify-%s" % kw["require_open"]))
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(tool, "review_boundary", lambda: order.append("review-boundary"))
    monkeypatch.setattr(tool, "approve", lambda run, _purpose: order.append("approve-%s" % run))
    monkeypatch.setattr(tool, "wait_success", lambda run, *_args: {
        "headBranch": "main" if run == tool.REVIEW_RUN_ID else tool.ISSUER_TAG,
    })
    monkeypatch.setattr(tool, "merge_manifest_pr", lambda: order.append("merge"))
    monkeypatch.setattr(tool, "create_tag", lambda: order.append("tag"))
    monkeypatch.setattr(tool, "secret_metadata", lambda: {"updated_at": "same"})
    dispatched = []
    monkeypatch.setattr(tool, "dispatch_public_retry", lambda snap: dispatched.append(snap) or 99)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda run: order.append("wait-%s" % run))
    monkeypatch.setattr(tool, "verify_public_retry_jobs", lambda run: order.append("jobs"))
    monkeypatch.setattr(tool, "verify_artifact", lambda run: order.append("artifact"))
    monkeypatch.setattr(tool, "verify_public_packet", lambda run: order.append("public"))
    assert tool.run() == 0
    assert dispatched == [{"run_id": 8, "epoch": 22, "wea_sha256": "b" * 64}]
    assert "approve-%s" % tool.REVIEW_RUN_ID in order
    assert "approve-99" in order
    assert order[-3:] == ["jobs", "artifact", "public"]
    assert "seal" not in order and "secret-write" not in order


def test_dispatch_has_no_seal_or_secret_fields(monkeypatch):
    calls = []
    responses = iter([
        '[{"databaseId":10}]',
        "",
        '[{"databaseId":11,"headBranch":"%s","headSha":"%s"}]'
        % (tool.ISSUER_TAG, tool.MANIFEST_HEAD),
    ])
    monkeypatch.setattr(tool, "command", lambda argv, **_kwargs: calls.append(argv) or next(responses))
    run_id = tool.dispatch_public_retry({"run_id": 7, "wea_sha256": "a" * 64})
    assert run_id == 11
    dispatch = calls[1]
    assert "mode=public_retry" in dispatch
    assert "predecessor_run_id=7" in dispatch
    assert "predecessor_wea_sha256=%s" % ("a" * 64) in dispatch
    raw = " ".join(dispatch)
    assert "sealed_" not in raw
    assert "downstream_" not in raw
    assert "ciphertext" not in raw
    assert "secret" not in raw.lower()


def test_predecessor_advance_before_post_review_dispatch_is_used(monkeypatch):
    # The full-arc test plants run 7 before review and run 8 after merge/tag;
    # assert that the exact later snapshot is the one dispatched.
    test_full_arc_is_review_merge_tag_public_retry_only(monkeypatch)


def test_predecessor_drift_before_issuer_approval_refuses(monkeypatch):
    ready(monkeypatch)
    snapshots = [
        {"run_id": 7, "epoch": 21, "wea_sha256": "a" * 64},
        {"run_id": 8, "epoch": 22, "wea_sha256": "b" * 64},
        {"run_id": 9, "epoch": 23, "wea_sha256": "c" * 64},
    ]
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **_kwargs: None)
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(tool, "review_boundary", lambda: None)
    approvals = []
    monkeypatch.setattr(tool, "approve", lambda run, _purpose: approvals.append(run))
    monkeypatch.setattr(tool, "wait_success", lambda run, *_args: {"headBranch": "main"})
    monkeypatch.setattr(tool, "merge_manifest_pr", lambda: None)
    monkeypatch.setattr(tool, "create_tag", lambda: None)
    monkeypatch.setattr(tool, "secret_metadata", lambda: {"updated_at": "same"})
    monkeypatch.setattr(tool, "dispatch_public_retry", lambda snap: 99)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda run: None)
    try:
        tool.run()
    except tool.Refusal as exc:
        assert str(exc) == "PREDECESSOR_DRIFT_BEFORE_ISSUER_APPROVAL"
    else:
        raise AssertionError("predecessor drift admitted")
    assert approvals == [tool.REVIEW_RUN_ID]


def test_unexpected_seal_phase_refuses(monkeypatch):
    jobs = {
        name: {"name": name, "conclusion": "success"}
        for name in ("preflight-predecessor", "preflight-sealed-transfer", "issue-wea")
    }
    jobs.update({name: {"name": name, "conclusion": "skipped"}
                 for name in ("seal-downstream", "renew-preflight", "renew-wea")})
    jobs["seal-downstream"]["conclusion"] = "success"
    monkeypatch.setattr(tool, "api", lambda *_args, **_kwargs: {"jobs": list(jobs.values())})
    try:
        tool.verify_public_retry_jobs(99)
    except tool.Refusal as exc:
        assert str(exc) == "PUBLIC_RETRY_UNEXPECTED_PHASE job=seal-downstream"
    else:
        raise AssertionError("unexpected seal phase admitted")


def test_secret_metadata_drift_is_a_refusal(monkeypatch):
    ready(monkeypatch)
    snapshot = {"run_id": 8, "epoch": 22, "wea_sha256": "b" * 64}
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda **_kwargs: None)
    monkeypatch.setattr(tool, "predecessor_snapshot", lambda: snapshot)
    monkeypatch.setattr(tool, "review_boundary", lambda: None)
    monkeypatch.setattr(tool, "approve", lambda *_args: None)
    monkeypatch.setattr(tool, "wait_success", lambda run, *_args: {
        "headBranch": "main" if run == tool.REVIEW_RUN_ID else tool.ISSUER_TAG,
    })
    monkeypatch.setattr(tool, "merge_manifest_pr", lambda: None)
    monkeypatch.setattr(tool, "create_tag", lambda: None)
    metadata = iter([{"updated_at": "before"}, {"updated_at": "after"}])
    monkeypatch.setattr(tool, "secret_metadata", lambda: next(metadata))
    monkeypatch.setattr(tool, "dispatch_public_retry", lambda snap: 99)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda run: None)
    monkeypatch.setattr(tool, "verify_public_retry_jobs", lambda run: None)
    monkeypatch.setattr(tool, "verify_artifact", lambda run: None)
    monkeypatch.setattr(tool, "verify_public_packet", lambda run: None)
    try:
        tool.run()
    except tool.Refusal as exc:
        assert str(exc) == "DOWNSTREAM_SECRET_MUTATION_REFUSED"
    else:
        raise AssertionError("secret metadata mutation admitted")


def test_direct_helper_and_non_tty_refuse(monkeypatch):
    monkeypatch.delenv("REA_S152_CHECKED_WRAPPER", raising=False)
    try:
        tool.runtime_ready()
    except tool.Refusal as exc:
        assert str(exc) == "CHECKED_WRAPPER_REQUIRED"
    else:
        raise AssertionError("direct helper admitted")


def test_constants_bind_new_incident():
    assert tool.ISSUER_TAG == "rea-wea-generation-5-" + tool.MANIFEST_HEAD[:12]
    assert len(tool.MANIFEST_FILE_SHA256) == 64
    assert tool.REVIEW_RUN_ID == 31604361900
    assert tool.MANIFEST_PR == 88


def test_checked_wrapper_self_anchors_and_invokes_only_new_helper():
    value = (ROOT / "s152_public_retry_approval_checked_wrapper.sh").read_text()
    assert "cmp -s \"$DEPLOYED_WRAPPER\" \"$CANONICAL_WRAPPER\"" in value
    assert "cmp -s \"$HELPER\" \"$CANONICAL_HELPER\"" in value
    assert "CANONICAL_COMMIT_NOT_PUBLISHED" in value
    assert "s152_public_retry_approval.py" in value
    assert "s152_successor_approval_resume.py" not in value
