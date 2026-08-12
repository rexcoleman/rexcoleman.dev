from __future__ import annotations

import importlib.util
import io
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "s152_billing_resume.py"
SPEC = importlib.util.spec_from_file_location("s152_billing_resume", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class TTY(io.StringIO):
    def isatty(self):
        return True


def ready(monkeypatch, tmp_path):
    monkeypatch.setenv("REA_S152_CHECKED_WRAPPER", tool.MARKER)
    monkeypatch.setattr(tool.socket, "gethostname", lambda: "gios-dev")
    monkeypatch.setattr(tool.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(tool.sys, "stdin", TTY())
    monkeypatch.setattr(tool, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(tool, "exact_pr", lambda: {
        "state": "open", "merged": False,
        "head": {"sha": tool.HEAD_SHA}, "base": {"ref": "main"}, "draft": False,
    })
    monkeypatch.setattr(tool, "billing_annotation", lambda _run: None)


def test_first_run_presents_exact_billing_gate_without_remote_mutation(
        monkeypatch, tmp_path, capsys):
    ready(monkeypatch, tmp_path)
    mutations = []
    monkeypatch.setattr(tool, "rerun_and_wait", lambda: mutations.append("rerun"))
    monkeypatch.setattr(tool, "merge_pr", lambda: mutations.append("merge"))
    assert tool.run() == 2
    output = capsys.readouterr().out
    assert tool.BILLING_URL in output and "SAME row" in output
    assert mutations == [] and tool.STATE.is_file()


def test_preflight_proves_exact_gate_without_local_or_remote_mutation(
        monkeypatch, tmp_path, capsys):
    ready(monkeypatch, tmp_path)
    assert tool.preflight() == 0
    output = capsys.readouterr().out
    assert "billing_failure=exact" in output
    assert "state_mutation=false remote_mutation=false" in output
    assert not tool.STATE.exists()


def test_second_run_reruns_exact_failures_then_merges(monkeypatch, tmp_path, capsys):
    ready(monkeypatch, tmp_path)
    tool.write_presented_state()
    order = []
    monkeypatch.setattr(tool, "rerun_and_wait", lambda: order.append("rerun"))
    monkeypatch.setattr(tool, "merge_pr", lambda: order.append("merge"))
    assert tool.run() == 0
    assert order == ["rerun", "merge"]
    assert "BILLING_RECOVERY_PASS" in capsys.readouterr().out


def test_malformed_state_refuses_before_rerun(monkeypatch, tmp_path):
    ready(monkeypatch, tmp_path)
    tool.STATE.write_text("{}\n", encoding="ascii")
    rerun = []
    monkeypatch.setattr(tool, "rerun_and_wait", lambda: rerun.append(True))
    try:
        tool.run()
    except tool.Refusal as exc:
        assert str(exc) == "BILLING_STATE_MISMATCH"
    else:
        raise AssertionError("malformed state admitted")
    assert rerun == []


def test_direct_or_wrong_host_refuses_before_github(monkeypatch):
    monkeypatch.delenv("REA_S152_CHECKED_WRAPPER", raising=False)
    try:
        tool.run()
    except tool.Refusal as exc:
        assert str(exc) == "CHECKED_WRAPPER_REQUIRED"
    else:
        raise AssertionError("direct helper admitted")


def test_non_billing_annotation_refuses(monkeypatch):
    values = iter([
        {"id": tool.RUN_IDS[0], "head_sha": tool.HEAD_SHA, "event": "push",
         "status": "completed", "conclusion": "failure", "run_attempt": 1},
        {"jobs": [{"id": 7, "name": tool.REQUIRED_CHECK,
                   "conclusion": "failure", "steps": []}]},
        [{"message": "ordinary code failure"}],
    ])
    monkeypatch.setattr(tool, "api", lambda _path: next(values))
    try:
        tool.billing_annotation(tool.RUN_IDS[0])
    except tool.Refusal as exc:
        assert "NON_BILLING_CHECK_FAILURE" in str(exc)
    else:
        raise AssertionError("ordinary failure treated as billing")


def test_check_state_requires_both_exact_reruns_success(monkeypatch):
    values = iter([
        {"id": tool.RUN_IDS[0], "head_sha": tool.HEAD_SHA, "event": "push",
         "status": "completed", "conclusion": "success", "run_attempt": 2},
        {"id": tool.RUN_IDS[1], "head_sha": tool.HEAD_SHA,
         "event": "pull_request", "status": "completed",
         "conclusion": "failure", "run_attempt": 2},
    ])
    monkeypatch.setattr(tool, "api", lambda _path: next(values))
    assert tool.check_state() is False


def test_check_state_accepts_both_exact_reruns_success(monkeypatch):
    values = iter([
        {"id": tool.RUN_IDS[0], "head_sha": tool.HEAD_SHA, "event": "push",
         "status": "completed", "conclusion": "success", "run_attempt": 2},
        {"id": tool.RUN_IDS[1], "head_sha": tool.HEAD_SHA,
         "event": "pull_request", "status": "completed",
         "conclusion": "success", "run_attempt": 2},
    ])
    monkeypatch.setattr(tool, "api", lambda _path: next(values))
    assert tool.check_state() is True
