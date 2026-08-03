import json
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
    SIGNED_SCAFFOLD_MEMBER_IDS,
    S88_BUNDLE_MEMBER_IDS,
    WRITE_BOUNDARY_POLICY_MEMBERS,
    derive_write_boundary_route_surface_bindings,
    generation_tag,
    normalize_ruleset,
    write_boundary_policy_digest,
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
    assert len(EXPECTED_MEMBERS) == 226
    assert len(set(EXPECTED_MEMBERS.values())) == 226
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


def test_signed_scaffold_installer_closes_all_transitive_comparison_inputs():
    core = {
        "scaffold-hybrid-core-atomic-consumer": "write_integrity/consumer/atomic_consumer.py",
        "scaffold-hybrid-core-package-init": "write_integrity/hybrid/__init__.py",
        "scaffold-hybrid-core-durable-spend": "write_integrity/hybrid/durable_spend.py",
        "scaffold-hybrid-core-protocol": "write_integrity/hybrid/protocol.py",
        "scaffold-hybrid-core-authorized-mapping-schema": "write_integrity/hybrid/schemas/authorized_mapping.schema.json",
        "scaffold-hybrid-core-external-evidence-receipt-schema": "write_integrity/hybrid/schemas/external_evidence_receipt.schema.json",
        "scaffold-hybrid-core-claim-lineage-schema": "write_integrity/hybrid/schemas/hybrid_claim_lineage.schema.json",
        "scaffold-hybrid-core-project-close-receipt-schema": "write_integrity/hybrid/schemas/project_close_receipt.schema.json",
        "scaffold-hybrid-core-revocation-registry-schema": "write_integrity/hybrid/schemas/revocation_registry.schema.json",
        "scaffold-hybrid-core-route-neutral-capability-schema": "write_integrity/hybrid/schemas/route_neutral_capability.schema.json",
        "scaffold-hybrid-core-trusted-issuer-schema": "write_integrity/hybrid/schemas/trusted_issuer.schema.json",
        "scaffold-hybrid-core-runtime-mount": "write_integrity/mounts/runtime_mount.py",
        "scaffold-hybrid-core-provisioning-package-init": "write_integrity/provisioning/__init__.py",
        "scaffold-hybrid-core-provisioning-boundary": "write_integrity/provisioning/boundary.py",
        "scaffold-hybrid-core-provisioning-fixed-adapter": "write_integrity/provisioning/fixed_adapter.py",
        "scaffold-hybrid-core-provisioning-prp": "write_integrity/provisioning/prp.py",
        "scaffold-hybrid-core-write-boundary-engine": "write_integrity/write_boundary/boundary_engine.py",
        "scaffold-hybrid-core-corpus-honest": "write_integrity/write_boundary/corpus/honest.jsonl",
        "scaffold-hybrid-core-corpus-manifest": "write_integrity/write_boundary/corpus/manifest.json",
        "scaffold-hybrid-core-corpus-planted": "write_integrity/write_boundary/corpus/planted.jsonl",
        "scaffold-hybrid-core-protected-receive": "write_integrity/write_boundary/protected_receive.py",
        "scaffold-hybrid-core-row-complete-verifier": "write_integrity/write_boundary/row_complete_verifier.py",
        "scaffold-hybrid-core-row-registry": "write_integrity/write_boundary/row_registry.json",
        "scaffold-hybrid-core-ledger-schema": "write_integrity/write_boundary/schemas/ledger.schema.json",
        "scaffold-hybrid-core-parent-admission-schema": "write_integrity/write_boundary/schemas/parent_admission.schema.json",
        "scaffold-hybrid-core-receipt-schema": "write_integrity/write_boundary/schemas/receipt.schema.json",
        "scaffold-hybrid-core-request-schema": "write_integrity/write_boundary/schemas/request.schema.json",
        "scaffold-hybrid-core-seam-registry": "write_integrity/write_boundary/seam_registry.json",
        "scaffold-hybrid-core-transform-registry": "write_integrity/write_boundary/transform_registry.json",
        "scaffold-hybrid-core-trusted-admission": "write_integrity/write_boundary/trusted_admission.py",
    }
    expected = {
        "scaffold-hybrid-route-consumer": (
            "govML",
            "templates/build/enforcement/hybrid_route_consumer.py",
        ),
        "scaffold-hybrid-install-manifest": (
            "govML",
            "templates/build/enforcement/hybrid_install_manifest.json",
        ),
        **{
            member_id: (
                "govML", f"templates/build/enforcement/hybrid_core/{path}"
            )
            for member_id, path in core.items()
        },
        "scaffold-report-surface": (
            "govML", "templates/build/enforcement/report_surface.py",
        ),
        "scaffold-report-auditor-generator": (
            "govML", "scripts/generators/gen_report_auditor.py",
        ),
        "canonical-exact-byte-handoff": (
            "govML", "templates/build/enforcement/exact_byte_handoff.py",
        ),
        "scaffold-report-orchestrator": (
            "govML", "scripts/generators/orchestrate.py",
        ),
        "scaffold-wea-consumer": (
            "govML",
            "templates/build/enforcement/write_enforcement_consumer.py",
        ),
    }
    assert SIGNED_SCAFFOLD_MEMBER_IDS == set(expected)
    assert {
        member_id: EXPECTED_MEMBERS[member_id]
        for member_id in SIGNED_SCAFFOLD_MEMBER_IDS
    } == expected
    assert len(SIGNED_SCAFFOLD_MEMBER_IDS) == 37
    assert len(EXPECTED_MEMBERS) - len(SIGNED_SCAFFOLD_MEMBER_IDS) == 189
    assert "scaffold_installer" in REQUIRED_CLASSES


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


def boundary_registry_fixture():
    actors = [
        "RPT-01", "BLG-01", "BLG-02", "BLG-03", "BLG-04", "BLG-05",
        "BLG-06", "BLG-07", "BLG-08", "BLG-09", "BLG-10", "PUB-01A",
        "PUB-01B", "PUB-01C", "PUB-02", "PUB-03", "PUB-04", "DST-01",
        "DST-02", "DST-03", "DST-04", "DST-05A", "DST-05B", "DST-06",
        "DST-07", "DST-08", "DST-09", "DST-10", "DST-11",
    ]
    seam_paths = {f"F{number}" for number in range(22, 32)}
    rows = []
    actor_index = 0
    for number in range(22, 66):
        path_id = f"F{number}"
        if path_id in seam_paths:
            surface, row_actors = "report", []
        elif actor_index < len(actors):
            actor = actors[actor_index]
            actor_index += 1
            surface = "blog" if actor == "DST-02" else (
                "report" if actor == "PUB-04" else "distribution"
            )
            row_actors = [actor]
        else:
            surface, row_actors = "publication", ["PUB-04"]
        rows.append({
            "path_id": path_id, "surface": surface,
            "operation": f"operation-{path_id}", "actor_ids": row_actors,
            "coverage": "registered",
        })
    row_registry = {
        "schema_version": "rea.write-boundary.row-registry.v1",
        "population": {
            "first_path_id": "F22", "last_path_id": "F65", "expected_count": 44,
        },
        "canonical_actor_ids": actors,
        "aliases": {"RPT-01A": "RPT-01"},
        "rows": rows,
    }
    seam_registry = {
        "schema_version": "rea.write-boundary.seam-registry.v1",
        "seams": [
            {
                "path_id": path_id, "seam_id": f"seam-{path_id}",
                "design_section": path_id, "description": path_id,
            }
            for path_id in sorted(seam_paths)
        ],
    }
    return (
        json.dumps(row_registry).encode(), json.dumps(seam_registry).encode()
    )


def test_write_boundary_policy_is_exact_nine_verified_member_closure():
    assert len(WRITE_BOUNDARY_POLICY_MEMBERS) == 9
    assert dict(WRITE_BOUNDARY_POLICY_MEMBERS) == {
        member_id: EXPECTED_MEMBERS[member_id][1]
        for member_id, _relative in WRITE_BOUNDARY_POLICY_MEMBERS
    }
    loaded = {
        member_id: f"verified-commit-bytes:{member_id}".encode()
        for member_id, _relative in WRITE_BOUNDARY_POLICY_MEMBERS
    }
    baseline = write_boundary_policy_digest(loaded)
    loaded["unrelated-mutable-workspace-byte"] = b"ignored"
    assert write_boundary_policy_digest(loaded) == baseline
    changed = dict(loaded)
    changed[WRITE_BOUNDARY_POLICY_MEMBERS[0][0]] += b"changed"
    assert write_boundary_policy_digest(changed) != baseline
    del changed[WRITE_BOUNDARY_POLICY_MEMBERS[1][0]]
    with pytest.raises(ValueError, match="policy member unavailable"):
        write_boundary_policy_digest(changed)


@pytest.mark.parametrize(
    "member_id", [member_id for member_id, _ in WRITE_BOUNDARY_POLICY_MEMBERS]
)
def test_each_write_boundary_policy_member_omission_refuses_before_signing(
        tmp_path, member_id):
    manifest = complete_manifest()
    manifest["members"] = [
        row for row in manifest["members"] if row["member_id"] != member_id
    ]
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert member_id in captured.value.detail


def test_route_bindings_are_exact_44_row_29_actor_10_seam_closure():
    row_raw, seam_raw = boundary_registry_fixture()
    bindings = derive_write_boundary_route_surface_bindings(row_raw, seam_raw)
    assert len(bindings) == 39
    assert "RPT-01A" not in bindings
    assert bindings["PUB-04"] == ["publication", "report"]
    assert bindings["DST-02"] == "blog"
    assert len([route for route in bindings if route.startswith("SEAM:")]) == 10


def test_route_bindings_refuse_narrowed_rows_aliases_and_seams():
    row_raw, seam_raw = boundary_registry_fixture()
    row_registry = json.loads(row_raw)
    seam_registry = json.loads(seam_raw)
    row_registry["rows"].pop()
    with pytest.raises(ValueError, match="registry closure"):
        derive_write_boundary_route_surface_bindings(
            json.dumps(row_registry).encode(), seam_raw
        )
    row_registry = json.loads(row_raw)
    row_registry["aliases"]["RPT-01A"] = "PUB-04"
    with pytest.raises(ValueError, match="registry closure"):
        derive_write_boundary_route_surface_bindings(
            json.dumps(row_registry).encode(), seam_raw
        )
    seam_registry["seams"].pop()
    with pytest.raises(ValueError, match="registry closure"):
        derive_write_boundary_route_surface_bindings(
            row_raw, json.dumps(seam_registry).encode()
        )
