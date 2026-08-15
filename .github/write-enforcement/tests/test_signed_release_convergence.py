from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import stat
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "signed_release_convergence.py"
ADAPTER = ROOT / "adapters/research_enforcement_activation.v1.json"
REGISTRATION_ADAPTER = ROOT / "adapters/research_enforcement_activation.registration-v1.json"
BAND_C_ADAPTER = ROOT / "adapters/research_enforcement_activation.band-c-m1-v1.json"
W2_ADAPTER = ROOT / "adapters/research_enforcement_activation.w2-project-bundle-v1.json"
NGA_ADAPTER = ROOT / "adapters/newsletter_generation_architecture.generation-5.json"
RER_ADAPTER = ROOT / "adapters/research_engine_release.generation-5.json"
INDEX = ROOT / "signed_release_convergence_index.json"
INVENTORY = ROOT / "signed_release_convergence_inventory.json"
DOC = ROOT / "SIGNED_RELEASE_CONVERGENCE.md"
INDEX_DOC = ROOT / "SIGNED_RELEASE_CONVERGENCE_INDEX.md"
FREEZE = ROOT / "FREEZE_SEQUENCE.md"
WORKFLOW = ROOT.parent / "workflows/signed-release-convergence.yml"
SPEC = importlib.util.spec_from_file_location("signed_release_convergence", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def roots(tmp_path):
    return {
        name: tmp_path / name
        for name in (
            "research_enforcement_activation",
            "govML",
            "Moonshots_Career_Thesis_v2",
            "newsletter",
            "rexcoleman.dev",
        )
    }


def contract_result():
    return {
        "deterministic": True,
        "noop_equal": False,
        "manifest_sha256": "a" * 64,
        "manifest_digest": "b" * 64,
        "member_count": 251,
        "remote_mutation": False,
        "owner_action": False,
        "anti_spin": "not-applicable-deterministic",
        "bcs_surface": "untouched",
    }


def build_result(raw_sha="a" * 64, member_count=251):
    return {
        "label": "manifest",
        "path": "/tmp/manifest.json",
        "sha256": raw_sha,
        "byte_length": 1,
        "manifest_digest": "b" * 64,
        "authority_generation": 5,
        "member_count": member_count,
        "stdout_sha256": "c" * 64,
        "stderr_sha256": "d" * 64,
    }


def test_adapter_is_closed_and_separates_other_infrastructure():
    value = tool.load_adapter(ADAPTER)
    assert value["schema_version"] == tool.ADAPTER_SCHEMA
    assert value["expected_member_count"] == 251
    assert value["boundaries"] == {
        "anti_spin": "not-applicable-deterministic",
        "bcs_partition": "forbidden",
        "owner_rail": "irreducible-human-only",
        "remote_mutation": "forbidden",
    }
    govml = next(
        row for row in value["hermetic_tests"]
        if row["name"] == "govml-clean-materialization"
    )
    assert "tests/test_s153_installer_ci_requirements.py" in govml["paths"]
    planted = dict(value)
    planted["owner_command"] = "forbidden"
    with pytest.raises(tool.Refusal, match="ADAPTER_FIELDS_REFUSED"):
        tool.closed_dict(planted, set(value), "ADAPTER")


def test_adapter_refuses_invalid_expected_member_count(tmp_path):
    value = json.loads(ADAPTER.read_text())
    for planted_value in (True, 0, "249"):
        value["expected_member_count"] = planted_value
        planted = tmp_path / ("adapter-%s.json" % str(planted_value).lower())
        planted.write_text(json.dumps(value))
        with pytest.raises(tool.Refusal, match="EXPECTED_MEMBER_COUNT_REFUSED"):
            tool.load_adapter(planted)


def test_registration_adapter_closes_over_s155_authority_population():
    value = tool.load_adapter(REGISTRATION_ADAPTER)
    assert value["adapter_id"] == (
        "research-enforcement-activation-generation-5-registration-v1"
    )
    assert value["authority_generation"] == 5
    assert value["expected_member_count"] == 255
    govml = next(
        row for row in value["hermetic_tests"]
        if row["name"] == "govml-registration-and-clean-materialization"
    )
    assert "tests/test_s155_research_type_registration.py" in govml["paths"]
    assert "tests/test_s150_signed_member_root.py" in govml["paths"]
    assert "tests/test_s154_production_artifact_adapter.py" in govml["paths"]
    assert "tests/test_s88_arm_remote_members.py" in govml["paths"]
    assert "tests/test_generate_s88_authority_fixture.py" in govml["paths"]
    sources = next(
        row for row in value["system_python_sources"]
        if row["repository"] == "govML"
    )
    assert "templates/build/enforcement/research_type_registration.py" in sources["paths"]
    assert "templates/build/enforcement/artifact_integrity_authority_resolver.py" in sources["paths"]
    assert "templates/build/enforcement/artifact_integrity_effect_gate.py" in sources["paths"]
    assert "templates/build/enforcement/record_write_side_validation.py" in sources["paths"]
    assert "templates/build/enforcement/write_side_arm.py" in sources["paths"]


def test_band_c_adapter_closes_over_m1_and_probe_resolver_population():
    value = tool.load_adapter(BAND_C_ADAPTER)
    assert value["adapter_id"] == (
        "research-enforcement-activation-generation-5-band-c-m1-v1"
    )
    assert value["authority_generation"] == 5
    assert value["expected_member_count"] == 257
    govml = next(
        row for row in value["hermetic_tests"]
        if row["name"] == "govml-registration-and-clean-materialization"
    )
    assert "tests/test_s157_profile_local_and_probe_resolver.py" in govml["paths"]
    sources = next(
        row for row in value["system_python_sources"]
        if row["repository"] == "govML"
    )
    assert "templates/build/enforcement/profile_local_artifact_producers.py" in sources["paths"]
    assert "templates/build/enforcement/probe_fixture_root.py" in sources["paths"]


def test_w2_adapter_closes_over_project_bundle_resolution_and_polarities():
    value = tool.load_adapter(W2_ADAPTER)
    assert value["adapter_id"] == (
        "research-enforcement-activation-generation-5-w2-project-bundle-v1"
    )
    assert value["authority_generation"] == 5
    assert value["expected_member_count"] == 257
    govml = next(
        row for row in value["hermetic_tests"]
        if row["name"] == "govml-write-side-project-bundle"
    )
    for path in (
        "tests/test_s157_write_side_project_bundle.py",
        "tests/test_s143_write_boundary_refuses_non_evaluation.py",
        "tests/test_s65_close_machinery.py",
        "tests/test_write_scaffold_install.py",
    ):
        assert path in govml["paths"]
    sources = next(
        row for row in value["system_python_sources"]
        if row["repository"] == "govML"
    )
    assert "templates/build/enforcement/write_side_arm.py" in sources["paths"]
    assert "templates/build/enforcement/write_boundary_verdict_event.py" in sources["paths"]


def test_dependent_adapters_bind_exact_target_identity_and_signed_authority():
    expected = {
        NGA_ADAPTER: {
            "adapter_id": "newsletter-generation-architecture-generation-5",
            "project_id": "newsletter_generation_architecture",
            "repository": "rexcoleman/newsletter_generation_architecture",
            "default_branch": "main",
            "named_refusal": "F09",
        },
        RER_ADAPTER: {
            "adapter_id": "research-engine-release-generation-5",
            "project_id": "research_engine_release",
            "repository": "rexcoleman/research_engine_release",
            "default_branch": "master",
            "named_refusal": "AUTHORITY_LAPSED",
        },
    }
    for path, identity in expected.items():
        value = tool.load_adapter(path)
        dependent = value["dependent_project"]
        assert value["schema_version"] == tool.DEPENDENT_ADAPTER_SCHEMA
        assert value["adapter_id"] == identity["adapter_id"]
        assert value["authority_generation"] == 5
        assert value["expected_member_count"] == 255
        for field in ("project_id", "repository", "default_branch", "named_refusal"):
            assert dependent[field] == identity[field]
        assert dependent["runner_path"] == "scripts/run_gates.sh"
        assert dependent["preflight_arguments"] == ["--engine-preflight"]
        assert dependent["required_source"] == "SIGNED_BUNDLE"
        assert {row["repository"] for row in value["hermetic_tests"]} == {
            "govML", "research_enforcement_activation", "rexcoleman.dev"
        }


@pytest.mark.parametrize(
    ("field", "planted", "reason"),
    [
        ("repository", "rexcoleman/newsletter", "DEPENDENT_PROJECT_REPOSITORY_REFUSED"),
        ("default_branch", "develop", "DEPENDENT_PROJECT_DEFAULT_BRANCH_REFUSED"),
        ("runner_path", "scripts/other.sh", "DEPENDENT_PROJECT_RUNNER_REFUSED"),
        ("preflight_arguments", ["--no-verify"], "DEPENDENT_PROJECT_PREFLIGHT_REFUSED"),
        ("required_source", "SHARED_CHECKOUT", "DEPENDENT_PROJECT_SOURCE_REFUSED"),
        ("named_refusal", "wea_expired", "DEPENDENT_PROJECT_REFUSAL_ID_REFUSED"),
    ],
)
def test_dependent_adapter_refuses_planted_route_drift(
    tmp_path, field, planted, reason
):
    value = copy.deepcopy(json.loads(NGA_ADAPTER.read_text()))
    value["dependent_project"][field] = planted
    target = tmp_path / "adapter.json"
    target.write_text(json.dumps(value))
    with pytest.raises(tool.Refusal, match=reason):
        tool.load_adapter(target)


def test_dependent_adapter_contract_evidence_binds_target_and_poststate(
    tmp_path, monkeypatch
):
    adapter = tool.load_adapter(RER_ADAPTER)
    evidence = tmp_path / "evidence"
    result = build_result(member_count=255)
    tool.receipt(evidence, "manifest-a", result)
    tool.receipt(evidence, "manifest-b", result)
    contract = tool.contract_snapshot(adapter, evidence, "plan", None)
    assert contract["dependent_project"] == adapter["dependent_project"]
    assert contract["remote_mutation"] is False
    assert contract["owner_action"] is False

    expected_roots = [{"logical_name": name} for name in sorted(roots(tmp_path))]
    tool.receipt(evidence, "roots", expected_roots)
    monkeypatch.setattr(tool, "root_snapshot", lambda *_args: expected_roots)
    poststate = tool.poststate_snapshot(adapter, roots(tmp_path), evidence, None)
    assert poststate == {
        "roots_unchanged": True,
        "remote_mutation": False,
        "root_count": 5,
    }


@pytest.mark.parametrize("adapter_path", [NGA_ADAPTER, RER_ADAPTER])
def test_dependent_adapter_resume_preserves_refusal_and_evidence(
    tmp_path, monkeypatch, adapter_path
):
    state = tmp_path / (adapter_path.stem + "-state.json")
    evidence = tmp_path / (adapter_path.stem + "-evidence")
    mapping = roots(tmp_path / adapter_path.stem)
    for path in mapping.values():
        path.mkdir(parents=True)
    monkeypatch.setattr(tool, "parse_roots", lambda _rows, _adapter: mapping)

    calls = []

    def first(phase, *_args):
        calls.append(phase)
        if phase == "impact":
            raise tool.Refusal("PLANTED_DEPENDENT_REFUSAL")
        return []

    monkeypatch.setattr(tool, "phase_result", first)
    with pytest.raises(tool.Refusal, match="PLANTED_DEPENDENT_REFUSAL"):
        tool.execute(adapter_path, state, evidence, [], "plan", False)
    assert calls == ["roots", "impact"]
    assert json.loads(state.read_text())["completed"] == ["roots"]

    dependent = tool.load_adapter(adapter_path)["dependent_project"]
    calls[:] = []

    def resumed(phase, *_args):
        calls.append(phase)
        if phase == "contract":
            value = contract_result()
            value["member_count"] = 255
            value["dependent_project"] = dependent
            return value
        return []

    monkeypatch.setattr(tool, "phase_result", resumed)
    monkeypatch.setattr(tool, "root_snapshot", lambda *_args: [])
    assert tool.execute(adapter_path, state, evidence, [], "plan", True) == 0
    assert calls == list(tool.PHASES[1:])
    summary = json.loads((evidence / "summary.json").read_text())
    assert summary["adapter_id"] == tool.load_adapter(adapter_path)["adapter_id"]
    assert summary["contract"]["dependent_project"] == dependent
    assert json.loads(state.read_text())["status"] == "complete"


def test_contract_snapshot_refuses_stale_adapter_member_count(tmp_path):
    evidence = tmp_path / "evidence"
    result = build_result()
    tool.receipt(evidence, "manifest-a", result)
    tool.receipt(evidence, "manifest-b", result)
    with pytest.raises(tool.Refusal, match="BUILT_MANIFEST_CONTRACT_REFUSED"):
        tool.contract_snapshot(
            {"authority_generation": 5, "expected_member_count": 248},
            evidence,
            "plan",
            None,
        )


def test_index_is_closed_and_resolves_every_registered_adapter():
    value = tool.load_index(INDEX)
    assert value["schema_version"] == tool.INDEX_SCHEMA
    assert value["engine"] == SOURCE.name
    assert value["documentation"] == DOC.name
    assert value["index_guide"] == INDEX_DOC.name
    assert value["cross_generation_inventory"] == INVENTORY.name
    identifiers = [row["adapter_id"] for row in value["adapters"]]
    assert identifiers == [
        "research-enforcement-activation-generation-5",
        "research-enforcement-activation-generation-5-registration-v1",
        "research-enforcement-activation-generation-5-band-c-m1-v1",
        "research-enforcement-activation-generation-5-w2-project-bundle-v1",
        "newsletter-generation-architecture-generation-5",
        "research-engine-release-generation-5",
    ]
    for adapter_id in identifiers:
        path = tool.resolve_adapter(INDEX, adapter_id)
        assert tool.load_adapter(path)["adapter_id"] == adapter_id


def test_index_refuses_duplicate_unknown_retired_and_traversing_rows(
    tmp_path,
):
    index_root = tmp_path / "write-enforcement"
    index_root.mkdir()
    (tmp_path / "workflows").mkdir()
    for source in (SOURCE, DOC, INDEX_DOC, INVENTORY):
        shutil.copyfile(source, index_root / source.name)
    tests = index_root / "tests"
    tests.mkdir()
    shutil.copyfile(Path(__file__), tests / Path(__file__).name)
    adapters = index_root / "adapters"
    adapters.mkdir()
    for adapter_path in (
        ADAPTER, REGISTRATION_ADAPTER, BAND_C_ADAPTER, W2_ADAPTER,
        NGA_ADAPTER, RER_ADAPTER
    ):
        shutil.copyfile(adapter_path, adapters / adapter_path.name)
    shutil.copyfile(WORKFLOW, tmp_path / "workflows" / WORKFLOW.name)

    value = json.loads(INDEX.read_text())
    duplicate = dict(value["adapters"][0])
    value["adapters"].append(duplicate)
    planted = index_root / "index.json"
    planted.write_text(json.dumps(value))
    with pytest.raises(tool.Refusal, match="INDEX_ADAPTER_ID_DUPLICATE"):
        tool.load_index(planted)
    with pytest.raises(tool.Refusal, match="INDEX_ADAPTER_UNKNOWN"):
        tool.resolve_adapter(INDEX, "unknown-adapter")

    retired = json.loads(INDEX.read_text())
    retired["adapters"][0]["status"] = "retired"
    planted_retired = index_root / "retired.json"
    planted_retired.write_text(json.dumps(retired))
    with pytest.raises(tool.Refusal, match="INDEX_ADAPTER_RETIRED"):
        tool.resolve_adapter(
            planted_retired, "research-enforcement-activation-generation-5"
        )

    traversing = json.loads(INDEX.read_text())
    traversing["adapters"][0]["path"] = "../escape.json"
    planted_traversing = index_root / "traversing.json"
    planted_traversing.write_text(json.dumps(traversing))
    with pytest.raises(tool.Refusal, match="RELATIVE_PATH_REFUSED"):
        tool.load_index(planted_traversing)

    shadowed = json.loads(INDEX.read_text())
    shadowed["engine"] = "tests/test_signed_release_convergence.py"
    planted_shadowed = index_root / "shadowed.json"
    planted_shadowed.write_text(json.dumps(shadowed))
    with pytest.raises(tool.Refusal, match="INDEX_PATH_IDENTITY_REFUSED:engine"):
        tool.load_index(planted_shadowed)

    misplaced = json.loads(INDEX.read_text())
    misplaced["adapters"][0]["path"] = "shadow.json"
    planted_misplaced = index_root / "misplaced.json"
    planted_misplaced.write_text(json.dumps(misplaced))
    with pytest.raises(tool.Refusal, match="INDEX_ADAPTER_PATH_REFUSED"):
        tool.load_index(planted_misplaced)


def test_cross_generation_inventory_is_closed_and_covers_six_properties():
    value = tool.load_cross_generation_inventory(INVENTORY)
    assert len(value["entries"]) == 21
    assert {row["repository"] for row in value["entries"]} == {
        "govML", "rexcoleman.dev",
    }
    assert len({row["session"] for row in value["entries"]}) >= 6
    assert value["properties"] == {
        "evidence": "tested", "hermetic": "tested", "identity": "tested",
        "poststate": "tested", "refusal": "tested", "resume": "tested",
    }
    assert value["untested_properties"] == []


def test_cross_generation_inventory_refuses_dropped_property(tmp_path):
    value = json.loads(INVENTORY.read_text())
    del value["properties"]["resume"]
    planted = tmp_path / "inventory.json"
    planted.write_text(json.dumps(value))
    with pytest.raises(tool.Refusal, match="INVENTORY_PROPERTY_SET_REFUSED"):
        tool.load_cross_generation_inventory(planted)


def test_adapter_rejects_arbitrary_test_program(tmp_path):
    value = json.loads(ADAPTER.read_text())
    value["hermetic_tests"][0]["paths"] = ["scripts/mutate.py"]
    planted = tmp_path / "adapter.json"
    planted.write_text(json.dumps(value))
    with pytest.raises(tool.Refusal, match="HERMETIC_TEST_PATH_REFUSED"):
        tool.load_adapter(planted)


def test_atomic_json_is_mode_0600_and_canonical(tmp_path):
    target = tmp_path / "state.json"
    tool.atomic_json(target, {"z": 1, "a": 2})
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_bytes() == b'{"a":2,"z":1}\n'


def test_secure_regular_bytes_closes_builder_output_mode(tmp_path):
    target = tmp_path / "manifest.json"
    target.write_bytes(b"{}\n")
    target.chmod(0o664)
    assert tool.secure_regular_bytes(target) == b"{}\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    link = tmp_path / "manifest-link.json"
    link.symlink_to(target)
    with pytest.raises(tool.Refusal, match="NONREGULAR_FILE"):
        tool.secure_regular_bytes(link)


def test_minimal_environment_excludes_host_and_credentials(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "secret")
    monkeypatch.setenv("REA_BUNDLE_READ_TOKEN", "secret")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/host/socket")
    value = tool.hermetic_environment()
    assert value["HOME"] == "/nonexistent/rea-release-preflight"
    assert value["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "GH_TOKEN" not in value
    assert "REA_BUNDLE_READ_TOKEN" not in value
    assert "SSH_AUTH_SOCK" not in value


def test_builder_token_is_transient_and_only_added_to_build_child(monkeypatch):
    class Completed:
        stdout = "transient-token\n"

    monkeypatch.setattr(tool, "run", lambda *_args, **_kwargs: Completed())
    value = tool.authenticated_builder_environment()
    assert value["GH_TOKEN"] == "transient-token"
    assert "REA_BUNDLE_READ_TOKEN" not in value
    assert "SSH_AUTH_SOCK" not in value
    source = SOURCE.read_text(encoding="utf-8")
    assert 'state["GH_TOKEN"]' not in source
    assert '"GH_TOKEN":' not in source


def test_pytest_interpreter_is_resolved_before_minimal_child_env(
    tmp_path, monkeypatch
):
    class Completed:
        stdout = ""
        stderr = ""

    calls = []
    candidate = tmp_path / "python3"
    candidate.write_text("#!/bin/sh\n")
    monkeypatch.setattr(tool.shutil, "which", lambda name: str(candidate))
    monkeypatch.setattr(
        tool,
        "run",
        lambda argv, **kwargs: calls.append((argv, kwargs)) or Completed(),
    )
    assert tool.pytest_interpreter() == str(candidate)
    assert calls[0][0][-1] == "import pytest"
    assert calls[0][1]["env"] == tool.hermetic_environment()


def test_pytest_interpreter_refuses_missing_pytest(monkeypatch):
    monkeypatch.setattr(tool.shutil, "which", lambda name: "/usr/bin/python3")
    monkeypatch.setattr(
        tool,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            tool.Refusal("COMMAND_REFUSED")
        ),
    )
    with pytest.raises(tool.Refusal, match="PYTEST_IMPORT_REFUSED"):
        tool.pytest_interpreter()


def test_hermetic_snapshot_compiles_registered_sources_with_system_python(
    tmp_path, monkeypatch
):
    mapping = roots(tmp_path)
    for path in mapping.values():
        path.mkdir()
    adapter = tool.load_adapter(ADAPTER)
    for row in adapter["system_python_sources"]:
        for item in row["paths"]:
            target = mapping[row["repository"]] / item
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("value = 1\n")
    adapter["hermetic_tests"] = []
    calls = []

    class Completed:
        stdout = ""
        stderr = ""

    def planted_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return Completed()

    monkeypatch.setattr(tool, "run", planted_run)
    monkeypatch.setattr(tool, "pytest_interpreter", lambda: "/usr/bin/python3")
    result = tool.hermetic_snapshot(adapter, mapping)
    assert len(result) == 5
    assert all(row["name"] == "system-python-compile" for row in result)
    assert all(row[0][0] == "/usr/bin/python3" for row in calls)
    assert all(row[1]["env"] == tool.hermetic_environment() for row in calls)


def test_impact_contract_uses_closed_successor_population():
    value = tool.member_contract(ROOT.parents[1])
    assert len(value) == 257
    assert value["research-type-registration-engine"] == (
        "govML",
        "templates/build/enforcement/research_type_registration.py",
    )
    assert value["research-type-registration-catalogs"] == (
        "govML",
        "templates/build/enforcement/research_type_registration_catalogs.json",
    )
    assert value["research-type-registration-registry"] == (
        "govML",
        "templates/build/enforcement/research_type_registration_registry.json",
    )
    assert value["research-type-registration-schema"] == (
        "govML",
        "templates/build/enforcement/research_type_registration_schema.json",
    )


def test_impact_contract_refuses_absent_or_nonmapping_successor_selector(tmp_path):
    member = tmp_path / ".github/write-enforcement/member_contract.py"
    member.parent.mkdir(parents=True)
    member.write_text("EXPECTED_MEMBERS = {}\n")
    with pytest.raises(
        tool.Refusal, match="SUCCESSOR_MEMBER_CONTRACT_SELECTOR_REFUSED"
    ):
        tool.member_contract(tmp_path)
    member.write_text(
        "EXPECTED_MEMBERS = {}\n"
        "def successor_members():\n"
        "    return []\n"
    )
    with pytest.raises(tool.Refusal, match="MEMBER_CONTRACT_REFUSED"):
        tool.member_contract(tmp_path)


def test_parse_roots_requires_exact_five(tmp_path):
    adapter = tool.load_adapter(ADAPTER)
    mapping = roots(tmp_path)
    for path in mapping.values():
        path.mkdir()
    rows = ["%s=%s" % row for row in mapping.items()]
    assert tool.parse_roots(rows, adapter) == {
        name: path.resolve() for name, path in mapping.items()
    }
    with pytest.raises(tool.Refusal, match="ROOT_SET_REFUSED"):
        tool.parse_roots(rows[:-1], adapter)


def test_contract_refuses_nondeterminism(tmp_path):
    evidence = tmp_path / "evidence"
    a = build_result()
    b = dict(a)
    b["sha256"] = "c" * 64
    tool.receipt(evidence, "manifest-a", a)
    tool.receipt(evidence, "manifest-b", b)
    with pytest.raises(tool.Refusal, match="DETERMINISTIC_REBUILD_REFUSED"):
        tool.contract_snapshot(tool.load_adapter(ADAPTER), evidence, "plan", None)


def test_noop_contract_requires_exact_baseline_bytes(tmp_path):
    evidence = tmp_path / "evidence"
    baseline = tmp_path / "manifest.json"
    baseline.write_bytes(b"baseline\n")
    result = build_result(tool.sha256(baseline.read_bytes()))
    tool.receipt(evidence, "manifest-a", result)
    tool.receipt(evidence, "manifest-b", result)
    observed = tool.contract_snapshot(
        tool.load_adapter(ADAPTER), evidence, "noop-rehearsal", baseline
    )
    assert observed["noop_equal"] is True
    baseline.write_bytes(b"drift\n")
    with pytest.raises(tool.Refusal, match="NOOP_BASELINE_DIVERGENCE"):
        tool.contract_snapshot(
            tool.load_adapter(ADAPTER), evidence, "noop-rehearsal", baseline
        )


def test_state_resume_verifies_receipts_and_does_not_repeat_prefix(
    tmp_path, monkeypatch
):
    state = tmp_path / "state.json"
    evidence = tmp_path / "evidence"
    mapping = roots(tmp_path)
    for path in mapping.values():
        path.mkdir()
    calls = []

    monkeypatch.setattr(tool, "parse_roots", lambda _rows, _adapter: mapping)

    def first(phase, _adapter, _roots, _evidence, _mode, _baseline):
        calls.append(phase)
        if phase == "impact":
            raise tool.Refusal("PLANTED_PHASE_REFUSAL")
        return []

    monkeypatch.setattr(tool, "phase_result", first)
    with pytest.raises(tool.Refusal, match="PLANTED_PHASE_REFUSAL"):
        tool.execute(ADAPTER, state, evidence, [], "plan", False)
    saved = json.loads(state.read_text())
    assert saved["status"] == "refused"
    assert saved["completed"] == ["roots"]
    assert calls == ["roots", "impact"]

    calls[:] = []

    def resumed(phase, _adapter, _roots, _evidence, _mode, _baseline):
        calls.append(phase)
        return contract_result() if phase == "contract" else []

    monkeypatch.setattr(tool, "phase_result", resumed)
    monkeypatch.setattr(tool, "root_snapshot", lambda *_args: [])
    assert tool.execute(ADAPTER, state, evidence, [], "plan", True) == 0
    assert calls == list(tool.PHASES[1:])
    assert json.loads(state.read_text())["status"] == "complete"
    assert json.loads((evidence / "summary.json").read_text())["status"] == "PASS"


def test_resume_refuses_tampered_phase_receipt(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    evidence = tmp_path / "evidence"
    mapping = roots(tmp_path)
    for path in mapping.values():
        path.mkdir()
    monkeypatch.setattr(tool, "parse_roots", lambda _rows, _adapter: mapping)
    monkeypatch.setattr(
        tool,
        "phase_result",
        lambda phase, *_args: contract_result() if phase == "contract" else [],
    )
    assert tool.execute(ADAPTER, state, evidence, [], "plan", False) == 0
    target = evidence / "receipts" / "roots.json"
    value = json.loads(target.read_text())
    value["result"] = ["tampered"]
    target.write_text(json.dumps(value))
    with pytest.raises(tool.Refusal, match="PHASE_RECEIPT_DRIFT"):
        tool.execute(ADAPTER, state, evidence, [], "plan", True)


def test_resume_revalidates_live_root_identity(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    evidence = tmp_path / "evidence"
    mapping = roots(tmp_path)
    for path in mapping.values():
        path.mkdir()
    monkeypatch.setattr(tool, "parse_roots", lambda _rows, _adapter: mapping)
    monkeypatch.setattr(
        tool,
        "phase_result",
        lambda phase, *_args: contract_result() if phase == "contract" else [],
    )
    assert tool.execute(ADAPTER, state, evidence, [], "plan", False) == 0
    monkeypatch.setattr(tool, "root_snapshot", lambda *_args: [{"drift": True}])
    with pytest.raises(tool.Refusal, match="RESUME_ROOT_DRIFT"):
        tool.execute(ADAPTER, state, evidence, [], "plan", True)


def test_state_binds_exact_tool_source(tmp_path, monkeypatch):
    state = tool.new_state(
        ADAPTER.read_bytes(),
        tool.load_adapter(ADAPTER),
        "plan",
        tmp_path / "evidence",
        None,
    )
    assert state["tool_sha256"] == tool.sha256(SOURCE.read_bytes())
    state["tool_sha256"] = "0" * 64
    target = tmp_path / "state.json"
    tool.atomic_json(target, state)
    with pytest.raises(tool.Refusal, match="STATE_IDENTITY_REFUSED"):
        tool.load_state(
            target,
            ADAPTER.read_bytes(),
            tool.load_adapter(ADAPTER),
            tmp_path / "evidence",
            None,
        )


def test_noop_requires_separate_baseline(tmp_path, monkeypatch):
    mapping = roots(tmp_path)
    for path in mapping.values():
        path.mkdir()
    monkeypatch.setattr(tool, "parse_roots", lambda _rows, _adapter: mapping)
    with pytest.raises(tool.Refusal, match="NOOP_BASELINE_REQUIRED"):
        tool.execute(
            ADAPTER,
            tmp_path / "state.json",
            tmp_path / "evidence",
            [],
            "noop-rehearsal",
            False,
        )


def test_driver_has_no_remote_mutation_or_owner_delivery_surface():
    source = SOURCE.read_text(encoding="utf-8")
    forbidden = (
        "gh pr merge",
        "gh workflow run",
        "pending_deployments",
        "git/refs",
        "owner_step_runner",
        "WA_KC_LIVE_DEPLOY",
    )
    for item in forbidden:
        assert item not in source
    assert '"remote_mutation": False' in source
    assert '"owner_action": False' in source


def test_navigation_docs_bind_registered_entry_and_boundaries():
    doc = DOC.read_text(encoding="utf-8")
    index_doc = INDEX_DOC.read_text(encoding="utf-8")
    freeze = FREEZE.read_text(encoding="utf-8")
    for required in (
        "signed_release_convergence.py",
        "research_enforcement_activation.v1.json",
        "not the BCS deployment accelerator",
        "Anti-spin applies to LLM-judged carries",
        "Owner rail is reserved",
        "signed_release_convergence_index.json",
        "--adapter-id",
    ):
        assert required in doc
    assert "signed-release" in freeze
    assert "convergence accelerator" in freeze
    assert "--noop-rehearsal" in freeze
    assert "canonical discovery surface" in index_doc
    assert "not release authority" in index_doc


def test_pr_workflow_is_read_only_and_runs_both_test_layers():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in raw
    assert "persist-credentials: false" in raw
    assert "--self-test" in raw
    assert "test_signed_release_convergence.py" in raw
    assert "signed_release_convergence_index.json" in raw
    assert "SIGNED_RELEASE_CONVERGENCE_INDEX.md" in raw
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in raw
    assert "pytest==8.4.1" in raw
    assert "FREEZE_SEQUENCE.md" not in raw
    for forbidden in ("pull-requests: write", "contents: write", "gh pr merge"):
        assert forbidden not in raw


def test_isolated_self_test(capsys):
    assert tool.self_test() == 0
    assert "SELF_TEST_PASS checks=9" in capsys.readouterr().out


def test_list_adapters_and_indexed_execution_selection(monkeypatch, capsys, tmp_path):
    assert tool.main(["--list-adapters"]) == 0
    listed = capsys.readouterr().out
    assert "research-enforcement-activation-generation-5\tactive\t" in listed
    assert (
        "research-enforcement-activation-generation-5-registration-v1\tactive\t"
        in listed
    )
    assert (
        "research-enforcement-activation-generation-5-band-c-m1-v1\tactive\t"
        in listed
    )
    assert (
        "research-enforcement-activation-generation-5-w2-project-bundle-v1"
        "\tactive\t" in listed
    )
    assert "newsletter-generation-architecture-generation-5\tactive\t" in listed
    assert "research-engine-release-generation-5\tactive\t" in listed

    captured = {}

    def fake_execute(adapter_path, *_args, **_kwargs):
        captured["adapter"] = adapter_path
        return 0

    monkeypatch.setattr(tool, "execute", fake_execute)
    assert tool.main([
        "--adapter-id", "research-enforcement-activation-generation-5",
        "--state", str(tmp_path / "state.json"),
        "--evidence-dir", str(tmp_path / "evidence"),
        "--plan",
    ]) == 0
    assert captured["adapter"] == ADAPTER


def test_cli_refuses_ambiguous_or_missing_adapter_selection(capsys, tmp_path):
    common = [
        "--state", str(tmp_path / "state.json"),
        "--evidence-dir", str(tmp_path / "evidence"),
        "--plan",
    ]
    assert tool.main(common) == 2
    assert "ADAPTER_SELECTION_REQUIRED" in capsys.readouterr().err
    assert tool.main([
        "--adapter", str(ADAPTER),
        "--adapter-id", "research-enforcement-activation-generation-5",
        *common,
    ]) == 2
    assert "ADAPTER_SELECTION_CONFLICT" in capsys.readouterr().err
