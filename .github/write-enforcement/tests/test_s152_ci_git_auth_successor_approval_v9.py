from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "s152_ci_git_auth_successor_approval_v9.py"
WRAPPER = ROOT / "s152_ci_git_auth_successor_approval_v9_checked_wrapper.sh"
V8_WRAPPER = ROOT / "s152_ci_git_auth_successor_approval_v8_checked_wrapper.sh"
SPEC = importlib.util.spec_from_file_location("s152_v9", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def test_v9_binds_actual_remote_full_sha_and_fresh_review():
    base = tool.BASE
    assert base.REVIEW_RUN_ID == 31612726051
    assert base.REVIEW_JOB_ID == 94167879518
    assert base.MANIFEST_PR == 94
    assert base.MANIFEST_HEAD == "8bc4c88a3d43c5f0a96b49762602a4db44e09ca0"
    assert base.REVIEW_EXPECTED_HEAD == base.MANIFEST_HEAD
    assert base.ISSUER_TAG == "rea-wea-generation-5-8bc4c88a3d43"
    assert "PREDECESSOR_RUN_ID" not in SOURCE.read_text(encoding="utf-8")


def test_v9_full_sha_suffix_mismatch_refuses():
    actual = tool.BASE.MANIFEST_HEAD
    planted = actual[:-1] + ("1" if actual[-1] != "1" else "2")
    with pytest.raises(tool.BASE.Refusal, match="REVIEW_EXPECTED_HEAD_MISMATCH"):
        tool.BASE.validate_review_subject(planted)


def test_v9_wrapper_checks_transitive_chain_and_v8_is_tombstoned():
    wrapper = WRAPPER.read_text(encoding="ascii")
    assert "OWNER_TTY_REQUIRED" in wrapper
    assert "CANONICAL_COMMIT_NOT_PUBLISHED" in wrapper
    assert "V8_DIGEST_MISMATCH" in wrapper
    assert "SAFE_TO_PASTE_BACK=true secret_bytes_printed=false" in wrapper
    tombstone = V8_WRAPPER.read_text(encoding="ascii")
    assert "WITHDRAWN_PREFLIGHT_IDENTITY_MISMATCH" in tombstone
    assert "exit 2" in tombstone
