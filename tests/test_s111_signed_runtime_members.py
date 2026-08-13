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
SIGNED_QUALITY_RUNTIME_MEMBERS = {
    "quality-loop": ("govML", "scripts/quality_loop.sh"),
    "quality-semantic-review": ("govML", "scripts/semantic_review.py"),
    "quality-findings-audit-generator": (
        "govML",
        "scripts/generators/gen_findings_audit.py",
    ),
}
REQUIRED_CLASSES = set(member_contract.REQUIRED_MEMBER_CLASSES)


def test_generation4_contract_registers_all_runtime_consumers_exactly_once():
    production = member_contract.EXPECTED_MEMBERS
    staged = member_contract.staged_nonproduction_members()
    assert len(production) == 244
    assert len(staged) == 249
    assert set(staged) - set(production) == (
        set(member_contract.SUCCESSOR_ADDITIONAL_MEMBERS)
        | {"staged-nonproduction-trusted-public-key"}
    )
    assert {
        key: production[key]
        for key in SIGNED_RUNTIME_MEMBERS
    } == SIGNED_RUNTIME_MEMBERS
    assert {
        key: production[key]
        for key in SIGNED_QUALITY_RUNTIME_MEMBERS
    } == SIGNED_QUALITY_RUNTIME_MEMBERS
    assert len(set(production.values())) == len(production)
    assert len(set(staged.values())) == len(staged)


def test_ci_materializer_is_successor_only_and_generation4_stays_exact():
    production = member_contract.EXPECTED_MEMBERS
    successor = member_contract.successor_members()
    added = member_contract.SUCCESSOR_ADDITIONAL_MEMBERS
    assert len(production) == 244
    assert len(successor) == 248
    assert set(successor) - set(production) == set(added)
    assert successor["ci-enforcement-materializer"] == added[
        "ci-enforcement-materializer"
    ]
    assert len(set(successor.values())) == len(successor)


def test_manifest_marker_selects_one_closed_contract_without_subset_fallback():
    old = {
        "authority_generation": member_contract.HISTORICAL_AUTHORITY_GENERATION,
        "members": [
            {"member_id": member_id}
            for member_id in member_contract.EXPECTED_MEMBERS
        ]
    }
    successor = {
        "authority_generation": member_contract.AUTHORITY_GENERATION,
        "members": [
            {"member_id": member_id}
            for member_id in member_contract.successor_members()
        ]
    }
    planted_partial = {
        "authority_generation": member_contract.AUTHORITY_GENERATION,
        "members": [{"member_id": "ci-enforcement-materializer"}]
    }
    assert member_contract.production_members_for_manifest(old) == (
        member_contract.EXPECTED_MEMBERS
    )
    assert member_contract.production_members_for_manifest(successor) == (
        member_contract.successor_members()
    )
    # Presence of the marker selects the complete successor set.  It does not
    # make a one-row or subset manifest acceptable to the issuer.
    assert member_contract.production_members_for_manifest(planted_partial) == (
        member_contract.successor_members()
    )
    with pytest.raises(issue_wea.IssuerRefusal, match="BUNDLE_MEMBER_SET_MISMATCH"):
        issue_wea.verify_members(
            {
                "authority_generation": member_contract.AUTHORITY_GENERATION,
                "required_member_classes": sorted(REQUIRED_CLASSES),
                "members": [{
                    "member_id": "ci-enforcement-materializer",
                    "repository": "govML",
                    "path": "templates/build/enforcement/ci_materialize_enforcement.py",
                }],
            },
            Path("/tmp/unused-successor-contract-negative"),
        )


def test_successor_contract_registers_exact_nine_write_boundary_policy_members():
    assert len(member_contract.WRITE_BOUNDARY_POLICY_MEMBERS) == 9
    observed = {
        member_id: member_contract.EXPECTED_MEMBERS[member_id]
        for member_id, _path in member_contract.WRITE_BOUNDARY_POLICY_MEMBERS
    }
    assert observed["write-boundary-engine"] == (
        "govML",
        "templates/build/enforcement/signed_authoring/write_boundary_engine.py",
    )
    assert {
        member_id: subject
        for member_id, subject in observed.items()
        if member_id != "write-boundary-engine"
    } == {
        member_id: ("research_enforcement_activation", path)
        for member_id, path in member_contract.WRITE_BOUNDARY_POLICY_MEMBERS
        if member_id != "write-boundary-engine"
    }
    assert dict(member_contract.WRITE_BOUNDARY_POLICY_MEMBERS)[
        "write-boundary-engine"
    ] == "write_integrity/write_boundary/boundary_engine.py"


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
    assert "list(REQUIRED_MEMBER_CLASSES)" in builder
    assert "set(REQUIRED_MEMBER_CLASSES)" in issuer
    assert len(REQUIRED_CLASSES) == 14
