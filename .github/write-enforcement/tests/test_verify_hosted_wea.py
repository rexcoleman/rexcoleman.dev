import argparse
import importlib.util
import json
from pathlib import Path

import pytest


TARGET = Path(__file__).resolve().parents[1] / "verify_hosted_wea.py"
SPEC = importlib.util.spec_from_file_location("verify_hosted_wea", TARGET)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def args(tmp_path):
    issuance = tmp_path / "issuance"
    issuance.mkdir()
    return argparse.Namespace(
        issuance=issuance, workspace=tmp_path / "workspace",
        consumer_id="newsletter-remote-check", surface="publication",
    )


def test_public_artifact_inventory_remains_exact_ten():
    assert len(MODULE.PUBLIC_ARTIFACTS) == 10
    assert MODULE.PUBLIC_ARTIFACTS == {
        "SHA256SUMS", "claim_policy.json", "claim_registry.json",
        "enforcement_bundle_manifest.json", "hybrid_capability_authority.json",
        "hybrid_capability_provider", "issuance_receipt.json", "runtime_mount.py",
        "trusted_wea_public.pem", "write_enforcement_attestation.json",
    }


@pytest.mark.parametrize("mode,reason,readable", [
    ("deleted", "WEA_MISSING", False),
    ("expired", "WEA_EXPIRED", True),
    ("corrupt", "WEA_CORRUPT", True),
    ("bundle-byte-changed", "WEA_WRONG_BUNDLE", True),
])
def test_r4_modes_emit_typed_refusal_with_digest_context(tmp_path, monkeypatch, capsys, mode, reason, readable):
    parsed = args(tmp_path)
    if readable:
        (parsed.issuance / "write_enforcement_attestation.json").write_bytes(
            b'{"state":"ENFORCING"}' if mode != "corrupt" else b'{"corrupt":'
        )

    def refuse(_args):
        if mode == "deleted":
            raise FileNotFoundError(
                2, "missing", str(parsed.issuance / "write_enforcement_attestation.json")
            )
        raise MODULE.HostedWEARefusal(reason, mode)

    monkeypatch.setattr(MODULE, "verify", refuse)
    raw_exit, report = MODULE.run(parsed)
    assert raw_exit == report["raw_exit"] == 3
    assert report["verdict"] == "REFUSE"
    assert report["reason_code"] == reason
    assert report["mutation_observed"] is False
    assert (report["state_digest"] is not None) is readable
    assert "PASS" not in json.dumps(report)
    assert "SKIP" not in json.dumps(report)
    assert "INERT" not in json.dumps(report)


def successor_loaded_fixture():
    actors = [
        "RPT-01", "BLG-01", "BLG-02", "BLG-03", "BLG-04", "BLG-05",
        "BLG-06", "BLG-07", "BLG-08", "BLG-09", "BLG-10", "PUB-01A",
        "PUB-01B", "PUB-01C", "PUB-02", "PUB-03", "PUB-04", "DST-01",
        "DST-02", "DST-03", "DST-04", "DST-05A", "DST-05B", "DST-06",
        "DST-07", "DST-08", "DST-09", "DST-10", "DST-11",
    ]
    rows = []
    seams = []
    actor_index = 0
    for number in range(22, 66):
        path_id = f"F{number}"
        if number < 32:
            surface, row_actors = "report", []
            seams.append({
                "path_id": path_id, "seam_id": f"seam-{path_id}",
                "design_section": path_id, "description": path_id,
            })
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
            "operation": path_id, "actor_ids": row_actors,
            "coverage": "registered",
        })
    row_raw = json.dumps({
        "schema_version": "rea.write-boundary.row-registry.v1",
        "population": {
            "first_path_id": "F22", "last_path_id": "F65", "expected_count": 44,
        },
        "canonical_actor_ids": actors, "aliases": {"RPT-01A": "RPT-01"},
        "rows": rows,
    }).encode()
    seam_raw = json.dumps({
        "schema_version": "rea.write-boundary.seam-registry.v1", "seams": seams,
    }).encode()
    loaded = {
        member_id: f"verified:{member_id}".encode()
        for member_id, _relative in MODULE.EXPECTED_MEMBERS.items()
    }
    loaded["write-boundary-row-registry"] = row_raw
    loaded["write-boundary-seam-registry"] = seam_raw
    return loaded


def successor_payload(loaded, manifest, wea_raw):
    return {
        "schema_version": "rea.write.hybrid-capability-authority.v1",
        "purpose": "VERIFY_ONLY_CURRENT_REGISTRY",
        "issuer": MODULE.ISSUER,
        "authority_epoch": MODULE.AUTHORITY_GENERATION,
        "wea_sha256": MODULE.digest(wea_raw),
        "enforcement_bundle_manifest_digest": manifest["manifest_digest"],
        "claim_registry_sha256": MODULE.digest(loaded["claim-registry"]),
        "claim_policy_sha256": MODULE.digest(loaded["claim-policy"]),
        "provider_sha256": MODULE.digest(loaded["hybrid-capability-provider"]),
        "runtime_mount_sha256": MODULE.digest(loaded["route-runtime-mount"]),
        "write_boundary_policy_sha256": MODULE.write_boundary_policy_digest(loaded),
        "route_surface_bindings": MODULE.derive_write_boundary_route_surface_bindings(
            loaded["write-boundary-row-registry"],
            loaded["write-boundary-seam-registry"],
        ),
        "issued_at": "2026-07-31T00:00:00Z",
        "expires_at": "2026-08-01T00:00:00Z",
    }


def test_hosted_verifier_recomputes_policy_and_routes_from_verified_loaded_bytes():
    loaded = successor_loaded_fixture()
    manifest = {"manifest_digest": "a" * 64}
    wea_raw = b"signed-wea\n"
    payload = successor_payload(loaded, manifest, wea_raw)
    policy_digest, bindings = MODULE.verify_successor_authority_bindings(
        payload, loaded, manifest, wea_raw
    )
    assert policy_digest == payload["write_boundary_policy_sha256"]
    assert len(bindings) == 39
    assert "RPT-01A" not in bindings
    assert bindings["PUB-04"] == ["publication", "report"]
    assert bindings["DST-02"] == "blog"


@pytest.mark.parametrize("field", [
    "write_boundary_policy_sha256", "route_surface_bindings",
])
def test_hosted_verifier_refuses_signed_successor_binding_drift(field):
    loaded = successor_loaded_fixture()
    manifest = {"manifest_digest": "a" * 64}
    wea_raw = b"signed-wea\n"
    payload = successor_payload(loaded, manifest, wea_raw)
    payload[field] = "0" * 64 if field.endswith("sha256") else {"RPT-01A": "report"}
    with pytest.raises(MODULE.HostedWEARefusal) as captured:
        MODULE.verify_successor_authority_bindings(
            payload, loaded, manifest, wea_raw
        )
    assert captured.value.reason_code == "WEA_WRONG_BUNDLE"
