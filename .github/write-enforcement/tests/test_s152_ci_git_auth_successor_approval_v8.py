from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "s152_ci_git_auth_successor_approval_v8.py"
WRAPPER = ROOT / "s152_ci_git_auth_successor_approval_v8_checked_wrapper.sh"
V7_WRAPPER = ROOT / "s152_ci_decoder_successor_approval_v7_checked_wrapper.sh"
SPEC = importlib.util.spec_from_file_location("s152_v8", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def test_v8_exact_identity_and_dynamic_predecessor_contract():
    base = tool.BASE
    assert base.REVIEW_RUN_ID == 31612053165
    assert base.REVIEW_JOB_ID == 94165574632
    assert base.MANIFEST_PR == 94
    assert base.MANIFEST_HEAD == "8bc4c88624ce85e5a91385bea3212114c2aa2ba8"
    assert base.MANIFEST_DIGEST == (
        "2ac8c65a61603da0b8182adf7ba8b019d7ec0ad8e684d85cafa115ff09ab1e3e"
    )
    assert base.ISSUER_TAG == "rea-wea-generation-5-8bc4c88624ce"
    source = SOURCE.read_text(encoding="utf-8")
    assert "PREDECESSOR_RUN_ID" not in source
    assert "public_retry" in base.dispatch_public_retry.__name__


def test_v8_one_nibble_subject_mismatch_refuses():
    planted = "9" + tool.BASE.MANIFEST_HEAD[1:]
    with pytest.raises(tool.BASE.Refusal, match="REVIEW_EXPECTED_HEAD_MISMATCH"):
        tool.BASE.validate_review_subject(planted)


def test_v8_wrapper_is_tombstoned_and_v7_remains_tombstoned():
    wrapper = WRAPPER.read_text(encoding="ascii")
    assert "WITHDRAWN_PREFLIGHT_IDENTITY_MISMATCH" in wrapper
    assert "exit 2" in wrapper
    assert "SAFE_TO_PASTE_BACK=true secret_bytes_printed=false" in wrapper
    assert "WITHDRAWN_CONSUMED_SUCCESS" in V7_WRAPPER.read_text(encoding="ascii")
