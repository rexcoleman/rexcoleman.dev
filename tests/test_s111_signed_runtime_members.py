from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".github/write-enforcement"
sys.path.insert(0, str(TOOLS))

import issue_wea  # noqa: E402
import member_contract  # noqa: E402


SIGNED_RUNTIME_MEMBERS = {
    "gate-invocation-receipt": (
        "govML",
        "templates/build/enforcement/gate_invocation_receipt.py",
    ),
    "enforcement-fired-gate": (
        "govML",
        "templates/build/enforcement/enforcement_fired_gate.sh",
    ),
}
REQUIRED_CLASSES = {
    "boundary_gate",
    "resolver",
    "readiness_consumer",
    "live_emitter_binding",
    "master_runner_binding",
    "project_runner_binding",
    "scaffold_installer",
    "invocation_receipt",
    "close_readiness_gate",
    "remote_workflow",
    "remote_ruleset",
    "claim_policy",
    "profile_registry",
    "trusted_public_key",
}


def test_generation4_contract_registers_all_runtime_consumers_exactly_once():
    assert len(member_contract.EXPECTED_MEMBERS) == 106
    assert {
        key: member_contract.EXPECTED_MEMBERS[key]
        for key in SIGNED_RUNTIME_MEMBERS
    } == SIGNED_RUNTIME_MEMBERS
    assert len(set(member_contract.EXPECTED_MEMBERS.values())) == 106


def test_issuer_refuses_manifest_missing_signed_runtime_consumers(tmp_path):
    manifest = {
        "required_member_classes": sorted(REQUIRED_CLASSES),
        "members": [
            {
                "member_id": member_id,
                "repository": repository,
                "path": path,
            }
            for member_id, (repository, path) in member_contract.EXPECTED_MEMBERS.items()
            if member_id not in SIGNED_RUNTIME_MEMBERS
        ]
    }
    with pytest.raises(
        issue_wea.IssuerRefusal, match="BUNDLE_MEMBER_SET_MISMATCH"
    ) as captured:
        issue_wea.verify_members(manifest, tmp_path)
    for member_id in SIGNED_RUNTIME_MEMBERS:
        assert member_id in captured.value.detail


@pytest.mark.parametrize("member_id", sorted(SIGNED_RUNTIME_MEMBERS))
def test_issuer_refuses_tampered_signed_runtime_member(tmp_path, member_id):
    repository, path = SIGNED_RUNTIME_MEMBERS[member_id]
    raw = b"signed-runtime-member\n"
    row = {
        "member_id": member_id,
        "repository": repository,
        "commit": "1" * 40,
        "path": path,
        "sha256": hashlib.sha256(raw + b"tampered").hexdigest(),
        "byte_length": len(raw),
    }
    with (
        mock.patch.object(issue_wea, "EXPECTED_MEMBERS", {member_id: (repository, path)}),
        mock.patch.object(issue_wea, "committed_bytes", return_value=raw),
        pytest.raises(ValueError, match=f"member mismatch: {member_id}"),
    ):
        issue_wea.verify_members(
            {
                "required_member_classes": sorted(REQUIRED_CLASSES),
                "members": [row],
            },
            tmp_path,
        )


def test_manifest_builder_and_issuer_require_same_runtime_classes():
    builder = (TOOLS / "build_frozen_manifest.py").read_text(encoding="utf-8")
    issuer = (TOOLS / "issue_wea.py").read_text(encoding="utf-8")
    for member_class in (
        "invocation_receipt",
        "close_readiness_gate",
    ):
        assert builder.count(f'"{member_class}"') == 1
        assert issuer.count(f'"{member_class}"') == 1
