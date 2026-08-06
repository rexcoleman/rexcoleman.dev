"""Both polarities of the renewal contract, on realistic attestation bytes.

Every fixture here is shaped exactly like a production attestation: the field
set is cross-checked against the payload ``issue_wea.py`` actually constructs,
so a new field added to the issuer without being classified breaks these tests
rather than silently widening what an unattended renewal may move.
"""

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SPEC = importlib.util.spec_from_file_location(
    "renewal_contract", ROOT / "renewal_contract.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)

ISSUE_SPEC = importlib.util.spec_from_file_location("issue_wea", ROOT / "issue_wea.py")
ISSUE = importlib.util.module_from_spec(ISSUE_SPEC)
assert ISSUE_SPEC.loader
ISSUE_SPEC.loader.exec_module(ISSUE)

ISSUER = (
    "https://github.com/rexcoleman/rexcoleman.dev/actions/workflows/"
    "issue-write-enforcement-attestation.yml"
)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sign(payload):
    """Attach a structurally valid signature envelope.

    ``signed_digest`` is a plain SHA-256 over the canonical unsigned payload, so
    it is reproducible without key material.  Verifying the signature VALUE
    against the trust root is verify_hosted_wea.py's job and is not restated
    here; these tests exercise classification, not cryptography.
    """
    signed = dict(payload)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signed_digest": hashlib.sha256(canonical(payload)).hexdigest(),
        "value": "AA" * 43 + "==",
    }
    return signed


def basis(**overrides):
    value = {
        "schema_version": "rea.write.wea.live.v2",
        "purpose": "LIVE_ENFORCEMENT",
        "state": "ENFORCING",
        "issuer": ISSUER,
        "issuer_source_digest": "1a" * 32,
        "renewal_policy_digest": "2b" * 32,
        "coverage_registry_digest": "3c" * 32,
        "coverage_registry_generation": 4,
        "publishing_capability_scope": ["blog-track", "full", "research"],
        "required_surfaces": ["report", "blog", "publication", "distribution"],
        "enforcement_bundle_manifest_digest": "4d" * 32,
        "claim_policy_digest": "5e" * 32,
        "trusted_key_id": "rea-wea-ed25519-69654455a16e7627",
    }
    value.update(overrides)
    return value


def predecessor_bytes(**overrides):
    payload = basis(**overrides.pop("basis", {}))
    payload.update({
        "authority_epoch": 5,
        "predecessor_wea_digest": "9f" * 32,
        "issuance_receipt_digest": "6f" * 32,
        "issued_at": "2026-08-06T11:24:18Z",
        "not_before": "2026-08-06T11:24:18Z",
        "expires_at": "2026-08-07T11:24:18Z",
    })
    payload.update(overrides)
    return canonical(sign(payload)) + b"\n"


def candidate_bytes(predecessor_raw, **overrides):
    payload = basis(**overrides.pop("basis", {}))
    payload.update({
        "authority_epoch": 6,
        "predecessor_wea_digest": hashlib.sha256(predecessor_raw).hexdigest(),
        "issuance_receipt_digest": "7a" * 32,
        "issued_at": "2026-08-07T05:17:04Z",
        "not_before": "2026-08-07T05:17:04Z",
        "expires_at": "2026-08-08T05:17:04Z",
    })
    payload.update(overrides)
    return canonical(sign(payload)) + b"\n"


# --------------------------------------------------------------------------
# The partition is not allowed to drift from what the issuer actually emits.
# --------------------------------------------------------------------------


def issuer_payload_fields():
    """Every key ``issue_wea.py`` writes into the attestation payload.

    Read from source rather than executed, because constructing the payload
    for real needs a protected key, a frozen workspace and a live ruleset.
    """
    tree = ast.parse((ROOT / "issue_wea.py").read_text())
    fields = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "payload"
            and isinstance(node.value, ast.Dict)
        ):
            fields.update(
                key.value for key in node.value.keys if isinstance(key, ast.Constant)
            )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "update"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "payload"
            and node.args
            and isinstance(node.args[0], ast.Dict)
        ):
            fields.update(
                key.value for key in node.args[0].keys if isinstance(key, ast.Constant)
            )
    assert fields, "payload construction not found in issue_wea.py"
    return fields | {"signature"}


def test_classified_universe_is_exactly_the_issued_field_set():
    assert MODULE.CLASSIFIED_FIELDS == issuer_payload_fields()


def test_partition_is_disjoint_and_total():
    assert not MODULE.CAPABILITY_FIELDS & MODULE.CHAIN_FIELDS
    assert (
        MODULE.CAPABILITY_FIELDS | MODULE.CHAIN_FIELDS
    ) == MODULE.CLASSIFIED_FIELDS
    assert len(MODULE.CLASSIFIED_FIELDS) == 20


def test_lifetime_constant_matches_the_issuer():
    now = datetime(2026, 8, 6, tzinfo=timezone.utc)
    issued, expires = ISSUE.issuance_times(now)
    assert expires - issued == MODULE.AUTHORITY_LIFETIME == timedelta(hours=24)


# --------------------------------------------------------------------------
# Positive polarity.
# --------------------------------------------------------------------------


def test_identical_capability_basis_is_a_renewal():
    predecessor = predecessor_bytes()
    candidate = candidate_bytes(predecessor)
    report = MODULE.classify(predecessor, candidate)
    assert report["verdict"] == "RENEWAL"
    assert report["predecessor_epoch"] == 5
    assert report["authority_epoch"] == 6
    assert report["predecessor_wea_sha256"] == hashlib.sha256(predecessor).hexdigest()


def test_renewal_verdict_is_not_reachable_from_a_trivially_equal_pair():
    """A renewal of an attestation by itself is refused, not accepted."""
    predecessor = predecessor_bytes()
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.classify(predecessor, predecessor)
    assert caught.value.reason_code == "RENEWAL_EPOCH_NOT_SUCCESSOR"


# --------------------------------------------------------------------------
# Negative polarity: every capability-bearing field.
# --------------------------------------------------------------------------


CAPABILITY_MUTATIONS = {
    "schema_version": "rea.write.wea.live.v3",
    "purpose": "STAGED_NONPRODUCTION_CONVERGENCE_PROOF",
    "state": "ADVISORY",
    "issuer": "https://github.com/attacker/x/actions/workflows/y.yml",
    "issuer_source_digest": "ff" * 32,
    "renewal_policy_digest": "ee" * 32,
    "coverage_registry_digest": "dd" * 32,
    "coverage_registry_generation": 5,
    "publishing_capability_scope": ["blog-track", "full", "research", "write-publish"],
    "required_surfaces": ["report", "blog", "publication", "distribution", "email"],
    "enforcement_bundle_manifest_digest": "cc" * 32,
    "claim_policy_digest": "bb" * 32,
    "trusted_key_id": "rea-wea-ed25519-0000000000000000",
}


def test_every_capability_field_has_a_mutation_case():
    assert set(CAPABILITY_MUTATIONS) == MODULE.CAPABILITY_FIELDS


@pytest.mark.parametrize("field", sorted(CAPABILITY_MUTATIONS))
def test_capability_change_is_refused_and_names_the_approved_path(field):
    predecessor = predecessor_bytes()
    candidate = candidate_bytes(predecessor, basis={field: CAPABILITY_MUTATIONS[field]})
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.classify(predecessor, candidate)
    assert caught.value.reason_code == "RENEWAL_CAPABILITY_CHANGE_REFUSED"
    assert f"field={field}" in caught.value.detail
    assert "rea-write-enforcement-issuer" in caught.value.detail
    assert "required_reviewers" in caught.value.detail


def test_unclassified_field_refuses_rather_than_passing_silently():
    predecessor = predecessor_bytes()
    payload = json.loads(candidate_bytes(predecessor))
    payload["publishing_capability_scope_v2"] = ["everything"]
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.classify(predecessor, canonical(payload))
    assert caught.value.reason_code == "RENEWAL_FIELD_UNCLASSIFIED"
    assert "publishing_capability_scope_v2" in caught.value.detail


def test_absent_field_refuses():
    predecessor = predecessor_bytes()
    payload = json.loads(candidate_bytes(predecessor))
    payload.pop("required_surfaces")
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.classify(predecessor, canonical(payload))
    assert caught.value.reason_code == "RENEWAL_FIELD_ABSENT"


# --------------------------------------------------------------------------
# Negative polarity: chain and lifetime.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"authority_epoch": 7}, "RENEWAL_EPOCH_NOT_SUCCESSOR"),
        ({"authority_epoch": 5}, "RENEWAL_EPOCH_NOT_SUCCESSOR"),
        ({"authority_epoch": 4}, "RENEWAL_EPOCH_NOT_SUCCESSOR"),
        ({"authority_epoch": 0}, "RENEWAL_EPOCH_MALFORMED"),
        ({"authority_epoch": True}, "RENEWAL_EPOCH_MALFORMED"),
        ({"predecessor_wea_digest": "0a" * 32}, "RENEWAL_PREDECESSOR_LINK_REFUSED"),
        ({"issuance_receipt_digest": "6f" * 32}, "RENEWAL_RECEIPT_NOT_FRESH"),
        ({"issuance_receipt_digest": "short"}, "RENEWAL_RECEIPT_DIGEST_MALFORMED"),
        (
            {"expires_at": "2026-08-14T05:17:04Z"},
            "RENEWAL_LIFETIME_REFUSED",
        ),
        (
            {"not_before": "2026-08-07T05:17:05Z"},
            "RENEWAL_LIFETIME_REFUSED",
        ),
        (
            {
                "issued_at": "2026-08-05T05:17:04Z",
                "not_before": "2026-08-05T05:17:04Z",
                "expires_at": "2026-08-06T05:17:04Z",
            },
            "RENEWAL_NOT_MONOTONIC",
        ),
        ({"issued_at": "not-a-time"}, "RENEWAL_TIMESTAMP_MALFORMED"),
    ],
)
def test_chain_violations_are_refused(overrides, reason):
    predecessor = predecessor_bytes()
    candidate = candidate_bytes(predecessor, **overrides)
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.classify(predecessor, candidate)
    assert caught.value.reason_code == reason


def test_signature_envelope_that_does_not_cover_the_payload_is_refused():
    predecessor = predecessor_bytes()
    payload = json.loads(candidate_bytes(predecessor))
    payload["signature"]["signed_digest"] = "1f" * 32
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.classify(predecessor, canonical(payload))
    assert caught.value.reason_code == "RENEWAL_SIGNED_DIGEST_MISMATCH"


def test_missing_signature_envelope_is_refused():
    predecessor = predecessor_bytes()
    payload = json.loads(candidate_bytes(predecessor))
    payload["signature"] = "not-an-envelope"
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.classify(predecessor, canonical(payload))
    assert caught.value.reason_code == "RENEWAL_SIGNATURE_SHAPE_REFUSED"


@pytest.mark.parametrize("raw", [b"", b"[]", b"not json"])
def test_unparseable_input_refuses(raw):
    predecessor = predecessor_bytes()
    with pytest.raises(MODULE.RenewalRefusal):
        MODULE.classify(predecessor, raw)


# --------------------------------------------------------------------------
# Precheck: refuse before the protected key is ever materialised.
# --------------------------------------------------------------------------


def manifest_bytes(manifest_digest):
    return json.dumps({"manifest_digest": manifest_digest}).encode()


def test_precheck_passes_on_an_unmoved_bundle():
    predecessor = predecessor_bytes()
    report = MODULE.precheck(predecessor, manifest_bytes("4d" * 32))
    assert report["verdict"] == "RENEWAL_PRECHECK_PASS"


def test_precheck_refuses_a_moved_bundle_before_signing():
    predecessor = predecessor_bytes()
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.precheck(predecessor, manifest_bytes("aa" * 32))
    assert caught.value.reason_code == "RENEWAL_CAPABILITY_CHANGE_REFUSED"
    assert "enforcement_bundle_manifest_digest" in caught.value.detail
    assert "rea-write-enforcement-issuer" in caught.value.detail


def test_precheck_refuses_a_malformed_manifest():
    predecessor = predecessor_bytes()
    with pytest.raises(MODULE.RenewalRefusal) as caught:
        MODULE.precheck(predecessor, b'{"manifest_digest": 7}')
    assert caught.value.reason_code == "RENEWAL_MANIFEST_SHAPE_REFUSED"


# --------------------------------------------------------------------------
# CLI exit codes: the workflow reads these, not the exceptions.
# --------------------------------------------------------------------------


def run_cli(tmp_path, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "renewal_contract.py"), *args],
        capture_output=True,
        cwd=tmp_path,
    )


def test_cli_exits_zero_on_renewal(tmp_path):
    predecessor = predecessor_bytes()
    (tmp_path / "pred.json").write_bytes(predecessor)
    (tmp_path / "cand.json").write_bytes(candidate_bytes(predecessor))
    result = run_cli(
        tmp_path, "classify", "--predecessor", "pred.json", "--candidate", "cand.json"
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["verdict"] == "RENEWAL"


def test_cli_exits_three_on_capability_change(tmp_path):
    predecessor = predecessor_bytes()
    (tmp_path / "pred.json").write_bytes(predecessor)
    (tmp_path / "cand.json").write_bytes(
        candidate_bytes(predecessor, basis={"publishing_capability_scope": ["full"]})
    )
    result = run_cli(
        tmp_path, "classify", "--predecessor", "pred.json", "--candidate", "cand.json"
    )
    assert result.returncode == 3
    assert b"RENEWAL_CAPABILITY_CHANGE_REFUSED" in result.stderr
    assert b"field=publishing_capability_scope" in result.stderr


def test_cli_exits_three_on_unreadable_input(tmp_path):
    result = run_cli(
        tmp_path, "classify", "--predecessor", "absent.json", "--candidate", "absent.json"
    )
    assert result.returncode == 3
    assert b"RENEWAL_PREDECESSOR_UNREADABLE" in result.stderr
