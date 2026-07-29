import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from issue_wea import IssuerRefusal, verify_members, verify_trust_roots  # noqa: E402
from member_contract import (  # noqa: E402
    AUTHORITY_GENERATION,
    EXPECTED_MEMBERS,
    FACE_A_MEMBER_IDS,
    FACE_B_MEMBER_IDS,
    FACE_B_ISOLATED_FIXTURE_MEMBER_IDS,
    GENERATION_MANIFEST_NAME,
    ROUTE_OWNED_MEMBER_IDS,
    S88_BUNDLE_MEMBER_IDS,
    generation_tag,
    normalize_ruleset,
)


REQUIRED_CLASSES = [
    "boundary_gate", "resolver", "readiness_consumer", "live_emitter_binding",
    "master_runner_binding", "project_runner_binding", "scaffold_installer",
    "invocation_receipt", "close_readiness_gate",
    "remote_workflow", "remote_ruleset", "claim_policy", "profile_registry",
    "trusted_public_key",
]


def complete_manifest():
    return {
        "required_member_classes": REQUIRED_CLASSES,
        "members": [
            {"member_id": member_id, "repository": repository, "path": path,
             "commit": "a" * 40, "sha256": "b" * 64, "byte_length": 1}
            for member_id, (repository, path) in EXPECTED_MEMBERS.items()
        ],
    }


def test_removed_member_refuses_before_signing(tmp_path):
    manifest = complete_manifest()
    removed = manifest["members"].pop()
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert removed["member_id"] in captured.value.detail


def test_retargeted_member_refuses_before_signing(tmp_path):
    manifest = complete_manifest()
    manifest["members"][0]["path"] = "forged/path"
    with pytest.raises(IssuerRefusal, match="BUNDLE_MEMBER_SET_MISMATCH"):
        verify_members(manifest, tmp_path)


def test_extra_member_refuses_before_signing(tmp_path):
    manifest = complete_manifest()
    manifest["members"].append({
        "member_id": "caller-added",
        "repository": "research_enforcement_activation",
        "path": "forged/path",
        "commit": "a" * 40,
        "sha256": "b" * 64,
        "byte_length": 1,
    })
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert "caller-added" in captured.value.detail


@pytest.mark.parametrize("member_id", sorted(S88_BUNDLE_MEMBER_IDS))
def test_each_s88_bundle_member_omission_refuses_before_signing(
        tmp_path, member_id):
    manifest = complete_manifest()
    manifest["members"] = [
        row for row in manifest["members"] if row["member_id"] != member_id
    ]
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert member_id in captured.value.detail


def test_contract_contains_exact_accepted_22_route_owned_files():
    assert len(ROUTE_OWNED_MEMBER_IDS) == 22
    assert ROUTE_OWNED_MEMBER_IDS < set(EXPECTED_MEMBERS)
    pairs = [EXPECTED_MEMBERS[member_id] for member_id in ROUTE_OWNED_MEMBER_IDS]
    assert len(pairs) == len(set(pairs)) == 22


def test_contract_covers_complete_s88_face_a_and_face_b_bundle_sets():
    assert len(EXPECTED_MEMBERS) == 110
    assert len(set(EXPECTED_MEMBERS.values())) == 110
    assert len(FACE_A_MEMBER_IDS) == 11
    assert len(FACE_B_MEMBER_IDS) == 9
    assert FACE_A_MEMBER_IDS < set(EXPECTED_MEMBERS)
    assert FACE_B_MEMBER_IDS < set(EXPECTED_MEMBERS)
    assert FACE_A_MEMBER_IDS.isdisjoint(FACE_B_MEMBER_IDS)
    pairs = [EXPECTED_MEMBERS[member_id]
             for member_id in FACE_A_MEMBER_IDS | FACE_B_MEMBER_IDS]
    assert len(pairs) == len(set(pairs)) == 20
    assert S88_BUNDLE_MEMBER_IDS == (
        FACE_A_MEMBER_IDS
        | FACE_B_MEMBER_IDS
        | {
            "authority-library", "verify-only-resolver", "wea-lifetime-library",
            "coverage-registry-library", "close-accounting-gate",
        }
    )


def test_face_b_fixture_is_labeled_isolated_not_protected_production():
    assert FACE_B_ISOLATED_FIXTURE_MEMBER_IDS == {
        "successor-subject-isolated-fixture",
        "successor-subject-face-a-b5-isolated-helper",
    }
    assert EXPECTED_MEMBERS["successor-subject-isolated-fixture"] == (
        "research_enforcement_activation",
        "write_integrity/authority/successor_subject/run_fixture.py",
    )
    assert EXPECTED_MEMBERS[
        "successor-subject-face-a-b5-isolated-helper"
    ] == (
        "research_enforcement_activation",
        "write_integrity/authority/successor_subject/face_a_b5_fixture.py",
    )
    assert "successor-subject-protected-entrypoint" not in EXPECTED_MEMBERS


def test_retargeted_face_b_helper_refuses_before_signing(tmp_path):
    manifest = complete_manifest()
    for row in manifest["members"]:
        if row["member_id"] == "successor-subject-face-a-b5-isolated-helper":
            row["path"] = (
                "write_integrity/authority/successor_subject/run_fixture.py"
            )
            break
    else:
        raise AssertionError("Face-B helper missing from complete manifest")
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert "successor-subject-face-a-b5-isolated-helper" in captured.value.detail


def test_divergent_pinned_public_key_copy_refuses():
    public = b"one remote public key"
    loaded = {"trusted-public-key": public, "newsletter-trusted-public-key": b"different"}
    with pytest.raises(IssuerRefusal) as captured:
        verify_trust_roots(loaded, public)
    assert captured.value.reason_code == "TRUST_ROOT_COPY_MISMATCH"


def test_generation_4_constants_and_tag_derivation_are_exact():
    commit = "a" * 40
    assert AUTHORITY_GENERATION == 4
    assert GENERATION_MANIFEST_NAME == "frozen_bundle_manifest.generation-4.json"
    assert generation_tag(commit) == "rea-wea-generation-4-" + "a" * 12
    with pytest.raises(ValueError):
        generation_tag("a" * 39)


def test_generation_4_member_contract_covers_lifetime_reach_and_close_gate():
    required = {
        "wea-lifetime-library",
        "r4-plan-builder",
        "r4-matrix-harness",
        "coverage-registry-library",
        "close-accounting-gate",
    }
    assert required <= set(EXPECTED_MEMBERS)


def test_runner_adapter_complete_fixed_canonical_dependency_closure_is_signed():
    expected = {
        "runner-adapter": (
            "research_enforcement_activation",
            "write_integrity/runners/runner_adapter.py",
        ),
        "authority-library": (
            "research_enforcement_activation",
            "write_integrity/authority/authority_lib.py",
        ),
        "authority-generated-constants": (
            "research_enforcement_activation",
            "write_integrity/authority/generated_constants.py",
        ),
        "subject-runner": (
            "research_enforcement_activation",
            "write_integrity/runners/subject_runner.py",
        ),
        "wea-consumer": (
            "research_enforcement_activation",
            "write_integrity/attestation/wea_consumer.py",
        ),
        "verify-only-resolver": (
            "research_enforcement_activation",
            "write_integrity/attestation/wea_verifier.py",
        ),
        "runner-adapter-launcher": (
            "govML",
            "templates/build/enforcement/runner_adapter_launcher.py",
        ),
    }
    assert {
        member_id: EXPECTED_MEMBERS[member_id]
        for member_id in expected
    } == expected


def test_ruleset_response_refuses_capability_elision():
    complete = {
        "id": 19564990,
        "name": "newsletter-main-integrity",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [],
        "bypass_actors": [],
    }
    assert normalize_ruleset(complete)["bypass_actors"] == []
    del complete["bypass_actors"]
    with pytest.raises(ValueError, match="capability-gated"):
        normalize_ruleset(complete)
