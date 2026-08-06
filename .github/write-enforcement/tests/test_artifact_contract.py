"""Tests for the generation-aware published-artifact contract.

The issuer deadlocked because it validated its predecessor's artifact against
the CURRENT member set.  Version N+1 demanded of a version-N predecessor a
member only a version-N+1 run emits, so no predecessor could ever satisfy it:
a precondition unreachable by any registered transition (P-6), asserted against
the wrong basis (P-4).

These tests require the resolver to accept an older predecessor carrying its
own generation's set, and equally to refuse every failure it claims to catch,
so a resolver that always accepts and one that always refuses both fail.
"""

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT.parents[0] / "workflows" / "issue-write-enforcement-attestation.yml"

SPEC = importlib.util.spec_from_file_location("artifact_contract", ROOT / "artifact_contract.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TABLE = MODULE.load_table(ROOT / "artifact_contract_versions.json")

GEN1 = "43063308680d8beafcde00336d3a8166df087d0b21d9612d90f32ce0e7d3edea"
GEN2 = "e168564a7ba5af6f3b346cdf0bf57fa8a614d9ed0e63fcac3e9ac86223f79661"


def packet(tmp_path, names, marker):
    root = tmp_path / "predecessor"
    root.mkdir()
    for name in names:
        (root / name).write_bytes(f"fixture:{name}\n".encode())
    receipt = {"workflow_run_id": 41}
    if marker is not None:
        receipt["workflow_blob_sha256"] = marker
    (root / "issuance_receipt.json").write_bytes(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    return root


def members(version):
    return list(TABLE["versions"][version - 1]["members"])


def test_table_is_monotonic_dense_and_closed():
    digests = set()
    previous = set()
    for index, entry in enumerate(TABLE["versions"]):
        assert entry["version"] == index + 1
        current = set(entry["members"])
        if previous:
            assert previous < current, "a generation may only GAIN members"
        previous = current
        for digest in entry["workflow_blob_sha256"]:
            assert digest not in digests
            digests.add(digest)


def test_current_generation_is_bound_to_the_live_issuer_workflow():
    """The table cannot describe a workflow other than the one that runs."""
    assert MODULE.verify_current_binding(TABLE, WORKFLOW)


def test_workflow_output_literal_matches_the_current_generation():
    """The output bar at every publish step is still the full current set.

    There are two issuance paths -- the owner-approved capability-change job and
    the unattended renewal job -- and each proves public-only custody against
    its own hardcoded literal.  Every literal must be the SAME set and must be
    the current generation: a renewal path publishing a different set would be
    a capability change smuggled past the classifier.
    """
    literals = re.findall(r"expected=\$'([^']*)'", WORKFLOW.read_text())
    assert len(literals) == 2, "one output bar per issuance path"
    assert len(set(literals)) == 1, "the issuance paths declare divergent sets"
    for literal in literals:
        observed = tuple(sorted(literal.split("\\n")))
        assert observed == MODULE.current_members(TABLE)
        assert "predecessor_write_enforcement_attestation.json" in observed


@pytest.mark.parametrize("version,marker", [(1, GEN1), (2, GEN2)])
def test_older_predecessor_carrying_its_own_set_is_accepted(tmp_path, version, marker):
    root = packet(tmp_path, members(version), marker)
    entry = MODULE.validate_predecessor_set(
        MODULE.observe_packet(root), MODULE.read_receipt(root), TABLE)
    assert entry["version"] == version


def test_current_predecessor_is_accepted_so_the_chain_sustains(tmp_path):
    entry = MODULE.current_entry(TABLE)
    root = packet(tmp_path, entry["members"], entry["workflow_blob_sha256"][0])
    assert MODULE.validate_predecessor_set(
        MODULE.observe_packet(root), MODULE.read_receipt(root), TABLE) == entry


def test_predecessor_missing_a_member_its_generation_required_refuses(tmp_path):
    names = members(2)
    target = "hybrid_capability_authority.json"
    assert target in names, "PRE-PLANT: target not a member, plant would be a no-op"
    names.remove(target)
    root = packet(tmp_path, names, GEN2)
    assert not (root / target).exists(), "PLANT MISSED"
    with pytest.raises(MODULE.ContractRefusal,
                       match=f"PREDECESSOR_MEMBER_MISSING:{re.escape(target)}"):
        MODULE.validate_predecessor_set(
            MODULE.observe_packet(root), MODULE.read_receipt(root), TABLE)


def test_relabelling_a_newer_packet_as_older_refuses(tmp_path):
    root = packet(tmp_path, members(2), GEN1)
    with pytest.raises(MODULE.ContractRefusal, match="PREDECESSOR_MEMBER_UNEXPECTED:"):
        MODULE.validate_predecessor_set(
            MODULE.observe_packet(root), MODULE.read_receipt(root), TABLE)


def test_unknown_generation_never_falls_back_to_a_permissive_set(tmp_path):
    root = packet(tmp_path, members(1), "de" * 32)
    with pytest.raises(MODULE.ContractRefusal, match="PREDECESSOR_UNKNOWN_GENERATION:"):
        MODULE.validate_predecessor_set(
            MODULE.observe_packet(root), MODULE.read_receipt(root), TABLE)


def test_absent_and_malformed_markers_refuse(tmp_path):
    (tmp_path / "a").mkdir()
    absent = packet(tmp_path / "a", members(2), None)
    with pytest.raises(MODULE.ContractRefusal, match="PREDECESSOR_GENERATION_MARKER_ABSENT"):
        MODULE.validate_predecessor_set(
            MODULE.observe_packet(absent), MODULE.read_receipt(absent), TABLE)
    (tmp_path / "b").mkdir()
    bad = packet(tmp_path / "b", members(2), "nope")
    with pytest.raises(MODULE.ContractRefusal, match="PREDECESSOR_GENERATION_MARKER_MALFORMED"):
        MODULE.validate_predecessor_set(
            MODULE.observe_packet(bad), MODULE.read_receipt(bad), TABLE)


def test_unparseable_receipt_refuses(tmp_path):
    root = packet(tmp_path, members(2), GEN2)
    (root / "issuance_receipt.json").write_bytes(b"{{{")
    with pytest.raises(MODULE.ContractRefusal, match="PREDECESSOR_RECEIPT_UNPARSEABLE"):
        MODULE.read_receipt(root)


def test_unknown_member_name_refuses(tmp_path):
    root = packet(tmp_path, members(2), GEN2)
    (root / "rogue.json").write_bytes(b"x\n")
    with pytest.raises(MODULE.ContractRefusal,
                       match="PREDECESSOR_UNKNOWN_MEMBER_NAME:rogue.json"):
        MODULE.validate_predecessor_set(
            MODULE.observe_packet(root), MODULE.read_receipt(root), TABLE)


def test_a_table_edited_to_shrink_the_current_set_refuses(tmp_path):
    table = json.loads(json.dumps(TABLE))
    table["versions"][-1]["members"].remove(
        "predecessor_write_enforcement_attestation.json")
    path = tmp_path / "versions.json"
    path.write_text(json.dumps(table))
    with pytest.raises(MODULE.ContractRefusal, match="CONTRACT_TABLE_NOT_MONOTONIC"):
        MODULE.load_table(path)


def test_a_table_pointing_at_the_wrong_workflow_refuses(tmp_path):
    other = tmp_path / "other.yml"
    other.write_text("not the issuer workflow\n")
    with pytest.raises(MODULE.ContractRefusal, match="CURRENT_GENERATION_BINDING_REFUSED"):
        MODULE.verify_current_binding(TABLE, other)
