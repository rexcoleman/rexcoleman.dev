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
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda: None)
    monkeypatch.setattr(tool, "pending_environment", lambda run: 7)
    monkeypatch.setattr(tool, "approve", lambda *_args: mutations.append("approve"))
    assert tool.preflight() == 0
    assert mutations == []


def test_full_arc_order(monkeypatch):
    ready(monkeypatch)
    order = []
    monkeypatch.setattr(tool, "verify_manifest_pr", lambda *args, **kwargs: order.append("verify"))
    monkeypatch.setattr(tool, "approve", lambda run, purpose: order.append("approve-%s" % run))
    monkeypatch.setattr(tool, "wait_success", lambda run, head, attempts, purpose: {
        "headBranch": "main" if run == tool.REVIEW_RUN_ID else tool.ISSUER_TAG,
        "headSha": head,
    })
    monkeypatch.setattr(tool, "merge_manifest_pr", lambda: order.append("merge"))
    monkeypatch.setattr(tool, "create_tag", lambda: order.append("tag"))
    monkeypatch.setattr(tool, "predecessor_digest", lambda: "a" * 64)
    monkeypatch.setattr(tool, "dispatch_issuer", lambda digest: 999)
    monkeypatch.setattr(tool, "wait_owner_gate", lambda run: order.append("wait-owner"))
    monkeypatch.setattr(tool, "verify_artifact", lambda run: order.append("artifact"))
    assert tool.run() == 0
    assert order == ["verify", "approve-%s" % tool.REVIEW_RUN_ID, "verify",
                     "merge", "tag", "wait-owner", "approve-999", "artifact"]


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
