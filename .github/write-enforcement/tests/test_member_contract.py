import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from issue_wea import IssuerRefusal, verify_members, verify_trust_roots  # noqa: E402
import issue_wea as issue_module  # noqa: E402
import build_frozen_manifest as build_module  # noqa: E402
import member_contract as contract_module  # noqa: E402
from member_contract import (  # noqa: E402
    AUTHORITY_GENERATION,
    COMPLETE_CHAIN_DEPENDENCIES,
    EXPECTED_MEMBERS,
    EXACT_MEMBER_BYTE_ALIASES,
    EXPECTED_EMITTER_RUNTIME_INSTALLATIONS,
    EXTERNAL_FREEZE_PROCEDURE_SUBJECT,
    EXTERNAL_GENERATION4_OWNER_RUNBOOK_SUBJECT,
    EXTERNAL_EMITTER_AUTHORING_SUBJECTS,
    FACE_A_MEMBER_IDS,
    FACE_B_MEMBER_IDS,
    FACE_B_ISOLATED_FIXTURE_MEMBER_IDS,
    GENERATION_MANIFEST_NAME,
    MANAGED_LIVE_MEMBER_ALIASES,
    ROUTE_OWNED_MEMBER_IDS,
    ROW_COMPLETE_PACKAGE_MEMBER_IDS,
    SIGNED_COMPLETE_CHAIN_MEMBER_IDS,
    SIGNED_SCAFFOLD_MEMBER_IDS,
    S88_BUNDLE_MEMBER_IDS,
    WRITE_BOUNDARY_POLICY_MEMBERS,
    derive_write_boundary_route_surface_bindings,
    generation_tag,
    normalize_ruleset,
    validate_managed_live_member_aliases,
    write_boundary_policy_digest,
)


REQUIRED_CLASSES = [
    "boundary_gate", "resolver", "readiness_consumer", "live_emitter_binding",
    "master_runner_binding", "project_runner_binding", "scaffold_installer",
    "invocation_receipt", "close_readiness_gate",
    "remote_workflow", "remote_ruleset", "claim_policy", "profile_registry",
    "trusted_public_key",
]


def test_production_provisioner_has_distinct_equal_byte_authoring_subject():
    pair = (
        "production-request-provisioner",
        "scaffold-hybrid-core-provisioning-prp",
    )
    assert pair in EXACT_MEMBER_BYTE_ALIASES
    assert len(EXACT_MEMBER_BYTE_ALIASES) == 16
    assert EXPECTED_MEMBERS[pair[0]] == (
        "govML",
        "templates/build/enforcement/signed_authoring/production_request_provisioner.py",
    )
    assert EXPECTED_MEMBERS[pair[0]] != EXPECTED_MEMBERS[pair[1]]
    honest = {pair[0]: b"exact-prp", pair[1]: b"exact-prp"}
    build_module.validate_exact_member_byte_aliases(honest)
    planted = dict(honest)
    planted[pair[0]] = b"drifted-prp"
    with pytest.raises(ValueError, match="exact member byte alias divergence"):
        build_module.validate_exact_member_byte_aliases(planted)
    collapsed = dict(EXPECTED_MEMBERS)
    collapsed[pair[0]] = collapsed[pair[1]]
    with pytest.raises(ValueError, match="collapse onto one subject"):
        build_module.validate_exact_member_byte_aliases(honest, collapsed)


def managed_alias_fixture():
    contract = {
        member_id: EXPECTED_MEMBERS[member_id]
        for row in MANAGED_LIVE_MEMBER_ALIASES
        for member_id in row[:2]
    }
    contract["managed-enforcement-inventory"] = (
        "govML", "templates/build/enforcement/managed_enforcement_inventory.py"
    )
    contract["scaffold-hybrid-install-manifest"] = (
        "govML", "templates/build/enforcement/hybrid_install_manifest.json"
    )
    runner = next(
        row for row in MANAGED_LIVE_MEMBER_ALIASES
        if row[2] == "write_integrity/runners/runner_adapter.py"
    )
    core_rows = [
        {"path": target, "sha256": "0" * 64}
        for _authoring, _runtime, target, *_modes in MANAGED_LIVE_MEMBER_ALIASES
        if target != runner[2]
    ]
    inventory = b"""
COMMON = {}
BUILD_ONLY = {}
PROFILE_CONTRACT = {'research-build': {'research_type': 'build', 'surfaces': (), 'runner': 'project_run_gates.sh'}}
SIGNED_BASE = {'write_integrity/runners/runner_adapter.py': ('govML', 'templates/build/enforcement/runner_adapter_launcher.py')}
EMITTER_RUNTIME_SURFACE_CLOSURES = {}
"""
    hybrid = json.dumps({
        "core_members": core_rows,
        "report_members": [],
        "row_complete_members": [],
    }).encode()
    loaded = {
        member_id: f"equal:{target}".encode()
        for authoring, runtime, target, *_modes in MANAGED_LIVE_MEMBER_ALIASES
        for member_id in (authoring, runtime)
    }
    loaded["managed-enforcement-inventory"] = inventory
    loaded["scaffold-hybrid-install-manifest"] = hybrid
    modes = {
        member_id: mode
        for authoring, runtime, _target, authoring_mode, runtime_mode, _installed
        in MANAGED_LIVE_MEMBER_ALIASES
        for member_id, mode in (
            (authoring, authoring_mode), (runtime, runtime_mode)
        )
    }
    modes["managed-enforcement-inventory"] = "100644"
    modes["scaffold-hybrid-install-manifest"] = "100644"
    return loaded, modes, contract


def test_managed_live_alias_table_is_exact_closed_population():
    loaded, modes, contract = managed_alias_fixture()
    validate_managed_live_member_aliases(loaded, modes, contract)
    assert len(MANAGED_LIVE_MEMBER_ALIASES) == 15
    transforms = [
        row for row in MANAGED_LIVE_MEMBER_ALIASES
        if row[4] == "100644" and row[5] == 0o755
    ]
    assert transforms == [
        (
            "runner-adapter", "runner-adapter-launcher",
            "write_integrity/runners/runner_adapter.py",
            "100755", "100644", 0o755,
        )
    ]


@pytest.mark.parametrize(
    "plant,reason",
    (
        ("omission", "alias count"),
        ("extra", "runtime target mismatch"),
        ("divergence", "alias divergence"),
        ("authoring-mode", "authoring mode"),
        ("runtime-mode", "runtime mode"),
        ("installed-mode", "installed mode"),
        ("live-target", "runtime target mismatch"),
    ),
)
def test_managed_live_alias_population_plants_refuse(monkeypatch, plant, reason):
    loaded, modes, contract = managed_alias_fixture()
    table = list(MANAGED_LIVE_MEMBER_ALIASES)
    authoring, runtime, target, authoring_mode, runtime_mode, installed = table[0]
    if plant == "omission":
        table.pop(0)
    elif plant == "extra":
        table[0] = (authoring, runtime, "write_integrity/forged.py", authoring_mode, runtime_mode, installed)
    elif plant == "divergence":
        loaded[authoring] = b"planted divergence"
    elif plant == "authoring-mode":
        modes[authoring] = "100755"
    elif plant == "runtime-mode":
        modes[runtime] = "100755"
    elif plant == "installed-mode":
        table[0] = (authoring, runtime, target, authoring_mode, runtime_mode, 0o755)
    elif plant == "live-target":
        loaded["scaffold-hybrid-install-manifest"] = json.dumps({
            "core_members": [], "report_members": [], "row_complete_members": []
        }).encode()
    monkeypatch.setattr(contract_module, "MANAGED_LIVE_MEMBER_ALIASES", tuple(table))
    with pytest.raises(ValueError, match=reason):
        validate_managed_live_member_aliases(loaded, modes, contract)


def test_member_contract_imports_on_supported_controller_pythons(tmp_path):
    command = (
        "import member_contract as m; "
        "assert len(m.EXPECTED_MEMBERS) == 244; "
        "assert m.write_boundary_policy_digest"
    )
    for interpreter in (Path("/usr/bin/python3"), Path(sys.executable)):
        result = subprocess.run(
            [str(interpreter), "-B", "-c", command],
            cwd=HERE,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, (
            interpreter,
            result.stdout,
            result.stderr,
        )

    planted = tmp_path / "member_contract.py"
    source = (HERE / "member_contract.py").read_text(encoding="utf-8")
    planted.write_text(
        source.replace("from __future__ import annotations\n", "", 1),
        encoding="utf-8",
    )
    regression = subprocess.run(
        [
            "/usr/bin/python3",
            "-B",
            "-c",
            "import member_contract",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert regression.returncode != 0
    assert "type' object is not subscriptable" in regression.stderr
EXPECTED_ROW_COMPLETE_PACKAGE = {
    "row-complete-full-receipts": (
        "govML", "templates/build/enforcement/row_complete/full-receipts.json"
    ),
    "row-complete-ledger": (
        "govML", "templates/build/enforcement/row_complete/ledger.json"
    ),
    "row-complete-ancestry-attestation": (
        "govML", "templates/build/enforcement/row_complete/ancestry-attestation.json"
    ),
}


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


def test_row_complete_package_is_exact_closed_signed_scaffold_set():
    assert ROW_COMPLETE_PACKAGE_MEMBER_IDS == set(EXPECTED_ROW_COMPLETE_PACKAGE)
    assert {
        member_id: EXPECTED_MEMBERS[member_id]
        for member_id in ROW_COMPLETE_PACKAGE_MEMBER_IDS
    } == EXPECTED_ROW_COMPLETE_PACKAGE
    assert ROW_COMPLETE_PACKAGE_MEMBER_IDS < SIGNED_SCAFFOLD_MEMBER_IDS


@pytest.mark.parametrize("member_id", sorted(ROW_COMPLETE_PACKAGE_MEMBER_IDS))
def test_each_row_complete_member_omission_refuses_before_signing(
        tmp_path, member_id):
    manifest = complete_manifest()
    manifest["members"] = [
        row for row in manifest["members"] if row["member_id"] != member_id
    ]
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert member_id in captured.value.detail


@pytest.mark.parametrize("member_id", sorted(ROW_COMPLETE_PACKAGE_MEMBER_IDS))
def test_each_row_complete_member_wrong_provenance_refuses_before_signing(
        tmp_path, member_id):
    manifest = complete_manifest()
    row = next(
        item for item in manifest["members"] if item["member_id"] == member_id
    )
    row["repository"] = "research_enforcement_activation"
    row["path"] = "write_integrity/row_complete/forged.json"
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert member_id in captured.value.detail


def test_extra_row_complete_like_member_refuses_before_signing(tmp_path):
    manifest = complete_manifest()
    manifest["members"].append({
        "member_id": "row-complete-shadow-ledger",
        "repository": "govML",
        "path": "templates/build/enforcement/row_complete/shadow-ledger.json",
        "commit": "a" * 40,
        "sha256": "b" * 64,
        "byte_length": 1,
    })
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert "row-complete-shadow-ledger" in captured.value.detail


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


def test_research_scaffolder_registration_closure_is_signed():
    assert {
        member_id: EXPECTED_MEMBERS[member_id]
        for member_id in (
            "research-scaffolder",
            "research-type-registration-validator",
            "research-type-stage-owner-grid",
        )
    } == {
        "research-scaffolder": (
            "Moonshots_Career_Thesis_v2",
            "scripts/scaffold_research_project.py",
        ),
        "research-type-registration-validator": (
            "Moonshots_Career_Thesis_v2",
            "scripts/validate_research_type_registration.py",
        ),
        "research-type-stage-owner-grid": (
            "Moonshots_Career_Thesis_v2",
            ".claude/references/research_type_stage_artifact_owner_grid.json",
        ),
    }


def test_contract_covers_complete_s88_face_a_and_face_b_bundle_sets():
    assert len(EXPECTED_MEMBERS) == 244
    assert len(set(EXPECTED_MEMBERS.values())) == 244
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


def test_single_runner_replaces_legacy_copies_with_authority_closure():
    assert {
        member_id: EXPECTED_MEMBERS[member_id]
        for member_id in (
            "external-judge-authority-issuer",
            "external-judge-authority-verifier",
            "external-judge-authority-judge",
        )
    } == {
        "external-judge-authority-issuer": (
            "govML", "scripts/issue_external_judge_authority.py"
        ),
        "external-judge-authority-verifier": (
            "govML", "scripts/external_judge_authority.py"
        ),
        "external-judge-authority-judge": (
            "govML", "scripts/landscape_depth_judge.py"
        ),
    }
    assert not {
        "project-runner-f07", "project-runner-f08", "project-runner-f09"
    } & set(EXPECTED_MEMBERS)


def test_signed_bundle_closes_master_chain_direct_and_transitive_files():
    expected = {
        "master-pre-compute-check": (
            "govML", "scripts/pre_compute_check.sh"
        ),
        "signed-hypothesis-gate": (
            "Moonshots_Career_Thesis_v2", "scripts/hypothesis_gate.sh"
        ),
        "master-readability-checker": (
            "govML", "scripts/generators/gen_readability_check.py"
        ),
        "emitter-runtime-channel-voice-checker": (
            "govML", "scripts/generators/gen_channel_voice_check.py"
        ),
        "master-gate05": ("govML", "scripts/check_gate05.sh"),
        "master-gate05-scaffold": ("govML", "scripts/check_gate05_scaffold.sh"),
        "master-handoff-scrutiny": ("govML", "scripts/handoff_scrutiny_gate.sh"),
        "master-loop-exit": ("govML", "scripts/loop_exit_gate.sh"),
        "master-file-re-reading": ("govML", "scripts/file_re_reading_gate.sh"),
        "master-readme-checker": ("govML", "scripts/generators/gen_readme.py"),
        "master-generalizability": ("govML", "scripts/check_generalizability.sh"),
        "master-build-pipeline": ("govML", "scripts/build_pipeline_gate.sh"),
        "master-build-profile-gate-bundle": (
            "govML",
            "templates/build/enforcement/installed_build_profile_gate_bundle.py",
        ),
        "canonical-enforcement-block": (
            "govML",
            "templates/build/enforcement/run_gates_enforcement_block.sh",
        ),
        "canonical-agent-pre-check-runner": (
            "govML", "scripts/agent_pre_check_runner.sh"
        ),
        "canonical-research-integrity-checklist": (
            "govML", "checklists/research_integrity.checklist"
        ),
        "canonical-landscape-depth-f3": (
            "govML", "scripts/landscape_depth_gate_F3.sh"
        ),
        "canonical-landscape-depth-gate": (
            "govML", "scripts/landscape_depth_gate.sh"
        ),
    }
    assert SIGNED_COMPLETE_CHAIN_MEMBER_IDS == set(expected)
    assert {
        member_id: EXPECTED_MEMBERS[member_id]
        for member_id in SIGNED_COMPLETE_CHAIN_MEMBER_IDS
    } == expected
    assert COMPLETE_CHAIN_DEPENDENCIES == {
        "master-runner": {
            "master-pre-compute-check",
            "canonical-enforcement-block",
            "master-readability-checker",
            "emitter-runtime-channel-voice-checker",
            "master-gate05",
            "master-gate05-scaffold",
            "master-handoff-scrutiny",
            "master-loop-exit",
            "master-file-re-reading",
            "master-readme-checker",
            "master-generalizability",
            "master-build-pipeline",
            "master-build-profile-gate-bundle",
        },
        "master-pre-compute-check": {
            "signed-hypothesis-gate",
        },
        "canonical-enforcement-block": {
            "canonical-agent-pre-check-runner",
            "canonical-research-integrity-checklist",
            "canonical-landscape-depth-f3",
        },
        "canonical-landscape-depth-f3": {
            "canonical-landscape-depth-gate",
        },
    }
    assert set(COMPLETE_CHAIN_DEPENDENCIES) < set(EXPECTED_MEMBERS)
    assert set().union(*COMPLETE_CHAIN_DEPENDENCIES.values()) == set(expected)


@pytest.mark.parametrize("member_id", sorted(SIGNED_COMPLETE_CHAIN_MEMBER_IDS))
def test_each_complete_chain_dependency_omission_refuses_before_signing(
        tmp_path, member_id):
    manifest = complete_manifest()
    manifest["members"] = [
        row for row in manifest["members"] if row["member_id"] != member_id
    ]
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert member_id in captured.value.detail


@pytest.mark.parametrize("member_id", sorted(SIGNED_COMPLETE_CHAIN_MEMBER_IDS))
def test_each_complete_chain_dependency_retarget_refuses_before_signing(
        tmp_path, member_id):
    manifest = complete_manifest()
    row = next(
        item for item in manifest["members"] if item["member_id"] == member_id
    )
    row["path"] = "forged/complete-chain-substitute"
    with pytest.raises(IssuerRefusal) as captured:
        verify_members(manifest, tmp_path)
    assert captured.value.reason_code == "BUNDLE_MEMBER_SET_MISMATCH"
    assert member_id in captured.value.detail


def test_r4_authority_tools_remain_signed_runtime_members():
    expected = {
        "r4-plan-builder": "write_integrity/attestation/build_r4_plan.py",
        "r4-matrix-harness": "write_integrity/attestation/run_r4_matrix.py",
        "r4-harness-common": "write_integrity/attestation/harness_common.py",
        "r4-actor-probe": "write_integrity/attestation/r4_actor_probe.py",
        "r4-actor-inventory": "write_integrity/attestation/r4_actor_inventory.json",
    }
    assert {
        member_id: EXPECTED_MEMBERS[member_id][1] for member_id in expected
    } == expected
    assert all(EXPECTED_MEMBERS[member_id][0] == "research_enforcement_activation"
               for member_id in expected)
    assert "generation-2-owner-runbook" not in EXPECTED_MEMBERS
    assert "remote-freeze-sequence" not in EXPECTED_MEMBERS
    assert "generation-4-owner-runbook" not in EXPECTED_MEMBERS
    assert EXTERNAL_FREEZE_PROCEDURE_SUBJECT == (
        "rexcoleman.dev", ".github/write-enforcement/FREEZE_SEQUENCE.md"
    )
    assert EXTERNAL_GENERATION4_OWNER_RUNBOOK_SUBJECT == (
        "rexcoleman.dev",
        ".github/write-enforcement/GENERATION_4_OWNER_RUNBOOK.md",
    )
    assert len(EXPECTED_MEMBERS) == 244


def test_external_authoring_paths_are_exact_commit_inputs_not_installed_ids():
    assert len(EXTERNAL_EMITTER_AUTHORING_SUBJECTS) == 14
    assert not set(EXTERNAL_EMITTER_AUTHORING_SUBJECTS) & set(EXPECTED_MEMBERS)
    installed_subjects = {
        tuple(subjects["installed"])
        for subjects in EXPECTED_EMITTER_RUNTIME_INSTALLATIONS.values()
    }
    assert installed_subjects <= set(EXPECTED_MEMBERS.values())
    assert all(
        repository == "govML" and path.startswith("scripts/generators/")
        for repository, path in EXTERNAL_EMITTER_AUTHORING_SUBJECTS.values()
    )


def test_external_owner_documents_have_no_live_code_or_workflow_caller():
    repository = HERE.parents[1]
    forbidden = {"FREEZE_SEQUENCE.md", "GENERATION_4_OWNER_RUNBOOK.md"}
    live_files = [
        path
        for root in (repository / ".github/workflows", HERE)
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in {".py", ".sh", ".yml", ".yaml"}
        and path.name != "member_contract.py"
        and "tests" not in path.parts
    ]
    hits = {
        str(path.relative_to(repository)): sorted(
            name for name in forbidden
            if name in path.read_text(encoding="utf-8")
        )
        for path in live_files
    }
    assert not {path: names for path, names in hits.items() if names}


@pytest.mark.parametrize("member_id", sorted(SIGNED_COMPLETE_CHAIN_MEMBER_IDS))
def test_each_complete_chain_member_tampered_bytes_refuses(
        tmp_path, monkeypatch, member_id):
    workspace = tmp_path / "workspace"
    repository_name, relative = EXPECTED_MEMBERS[member_id]
    repository = workspace / repository_name
    subject = repository / relative
    subject.parent.mkdir(parents=True)
    subject.write_bytes(b"signed canonical block\n")
    subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email",
         "s134-builder@example.invalid"], check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name",
         "s134 Builder ARCH"], check=True,
    )
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    expected = {member_id: (repository_name, relative)}
    monkeypatch.setattr(issue_module, "EXPECTED_MEMBERS", expected)
    manifest = {
        "required_member_classes": REQUIRED_CLASSES,
        "members": [{
            "member_id": member_id,
            "repository": repository_name,
            "commit": commit,
            "path": relative,
            "sha256": "0" * 64,
            "byte_length": len(subject.read_bytes()),
        }],
    }
    with pytest.raises(ValueError, match=f"member mismatch: {member_id}"):
        verify_members(manifest, workspace)


def test_signed_scaffold_installer_closes_all_transitive_comparison_inputs():
    core = {
        "scaffold-hybrid-core-atomic-consumer": "write_integrity/consumer/atomic_consumer.py",
        "scaffold-hybrid-core-package-init": "write_integrity/hybrid/__init__.py",
            "scaffold-hybrid-core-durable-spend": "write_integrity/hybrid/durable_spend.py",
            "scaffold-hybrid-core-jsonschema-compat": "write_integrity/jsonschema_compat.py",
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
        **EXPECTED_ROW_COMPLETE_PACKAGE,
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
    assert len(SIGNED_SCAFFOLD_MEMBER_IDS) == 41
    assert len(EXPECTED_MEMBERS) - len(SIGNED_SCAFFOLD_MEMBER_IDS) == 203
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


def test_generation_4_member_contract_covers_runtime_lifetime_and_close_gate():
    runtime_required = {
        "wea-lifetime-library",
        "coverage-registry-library",
        "close-accounting-gate",
    }
    assert runtime_required <= set(EXPECTED_MEMBERS)
    expected_r4 = {
        "r4-plan-builder": (
            "research_enforcement_activation",
            "write_integrity/attestation/build_r4_plan.py",
        ),
        "r4-matrix-harness": (
            "research_enforcement_activation",
            "write_integrity/attestation/run_r4_matrix.py",
        ),
        "r4-harness-common": (
            "research_enforcement_activation",
            "write_integrity/attestation/harness_common.py",
        ),
        "r4-actor-probe": (
            "research_enforcement_activation",
            "write_integrity/attestation/r4_actor_probe.py",
        ),
        "r4-actor-inventory": (
            "research_enforcement_activation",
            "write_integrity/attestation/r4_actor_inventory.json",
        ),
    }
    assert {
        member_id: EXPECTED_MEMBERS[member_id] for member_id in expected_r4
    } == expected_r4


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
