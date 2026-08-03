import argparse
import base64
import importlib.util
import json
import subprocess
from datetime import datetime, timedelta, timezone
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


def test_public_artifact_inventory_remains_exact_eleven():
    assert len(MODULE.PUBLIC_ARTIFACTS) == 11
    assert MODULE.PUBLIC_ARTIFACTS == {
        "SHA256SUMS", "claim_policy.json", "claim_registry.json",
        "enforcement_bundle_manifest.json", "hybrid_capability_authority.json",
        "hybrid_capability_provider", "issuance_receipt.json", "runtime_mount.py",
        "trusted_wea_public.pem", "write_enforcement_attestation.json",
        "predecessor_write_enforcement_attestation.json",
    }


def public_packet_fixture(tmp_path):
    issuance = tmp_path / "packet"
    issuance.mkdir()
    names = sorted(MODULE.PUBLIC_ARTIFACTS - {"SHA256SUMS"})
    for name in names:
        (issuance / name).write_bytes(f"artifact:{name}\n".encode())
    (issuance / "SHA256SUMS").write_text("".join(
        f"{MODULE.digest((issuance / name).read_bytes())}  {name}\n"
        for name in names
    ), encoding="ascii")
    return issuance


def _git(root, *args):
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def artifact_relative_packet(tmp_path, monkeypatch, changed_member_id):
    workspace = tmp_path / "workspace"
    member_bytes = {
        member_id: f"signed:{member_id}\n".encode()
        for member_id in MODULE.EXPECTED_MEMBERS
    }
    public = b"fixture-public-key-bytes\n"
    member_bytes["trusted-public-key"] = public
    member_bytes["newsletter-trusted-public-key"] = public
    member_bytes["profile-registry"] = MODULE.canonical({
        "schema_version": "rea.write.publishing_profiles.v1",
        "profiles": [
            {"profile_id": "research", "publishes": True},
            {"profile_id": "nonpublishing", "publishes": False},
        ],
    })
    member_bytes["claim-policy"] = b'{"policy":"signed-object"}\n'

    roots = {}
    for repository in sorted({pair[0] for pair in MODULE.EXPECTED_MEMBERS.values()}):
        root = workspace / repository
        root.mkdir(parents=True)
        _git(root, "init", "-q")
        _git(root, "config", "user.name", "hosted verifier fixture")
        _git(root, "config", "user.email", "fixture@example.invalid")
        roots[repository] = root
    for member_id, (repository, relative) in MODULE.EXPECTED_MEMBERS.items():
        target = roots[repository] / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(member_bytes[member_id])
    commits = {}
    for repository, root in roots.items():
        _git(root, "add", ".")
        _git(root, "commit", "-q", "-m", "signed fixture")
        commits[repository] = _git(root, "rev-parse", "HEAD")

    members = []
    for member_id, (repository, relative) in MODULE.EXPECTED_MEMBERS.items():
        raw = member_bytes[member_id]
        members.append({
            "member_id": member_id,
            "repository": repository,
            "commit": commits[repository],
            "path": relative,
            "sha256": MODULE.digest(raw),
            "byte_length": len(raw),
        })
    manifest = {
        "schema_version": "rea.write.enforcement-bundle-manifest.v1",
        "authority_generation": MODULE.AUTHORITY_GENERATION,
        "members": members,
    }
    manifest["manifest_digest"] = MODULE.digest(MODULE.canonical(manifest))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    expires = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    predecessor = {
        "schema_version": "rea.write.wea.live.v2",
        "purpose": "LIVE_ENFORCEMENT", "state": "ENFORCING",
        "issuer": MODULE.ISSUER,
        "authority_epoch": MODULE.AUTHORITY_GENERATION - 1,
    }
    predecessor_digest = MODULE.digest(MODULE.canonical(predecessor))
    predecessor["signature"] = {
        "algorithm": "ed25519", "signed_digest": predecessor_digest,
        "value": base64.b64encode(b"0" * 64).decode(),
    }
    predecessor_raw = MODULE.canonical(predecessor) + b"\n"
    wea = {
        "schema_version": "rea.write.wea.live.v2",
        "purpose": "LIVE_ENFORCEMENT",
        "state": "ENFORCING",
        "authority_epoch": MODULE.AUTHORITY_GENERATION,
        "predecessor_wea_digest": MODULE.digest(predecessor_raw),
        "issuer": MODULE.ISSUER,
        "issued_at": issued,
        "expires_at": expires,
        "publishing_capability_scope": ["research"],
        "required_surfaces": sorted(MODULE.SURFACES),
        "enforcement_bundle_manifest_digest": manifest["manifest_digest"],
        "claim_policy_digest": MODULE.digest(member_bytes["claim-policy"]),
        "coverage_registry_digest": MODULE.digest(
            member_bytes["managed-gate-coverage-registry"]
        ),
        "coverage_registry_generation": MODULE.AUTHORITY_GENERATION,
        "trusted_key_id": f"rea-wea-ed25519-{MODULE.digest(public)[:16]}",
    }
    signed_digest = MODULE.digest(MODULE.canonical(wea))
    wea["signature"] = {
        "algorithm": "ed25519",
        "signed_digest": signed_digest,
        "value": base64.b64encode(b"0" * 64).decode(),
    }
    issuance = tmp_path / "issuance"
    issuance.mkdir()
    payloads = {
        "write_enforcement_attestation.json": MODULE.canonical(wea) + b"\n",
        "enforcement_bundle_manifest.json": MODULE.canonical(manifest) + b"\n",
        "trusted_wea_public.pem": public,
        "claim_policy.json": member_bytes["claim-policy"],
        "claim_registry.json": member_bytes["claim-registry"],
        "hybrid_capability_provider": member_bytes["hybrid-capability-provider"],
        "runtime_mount.py": member_bytes["route-runtime-mount"],
        "hybrid_capability_authority.json": b"{}\n",
        "predecessor_write_enforcement_attestation.json": predecessor_raw,
    }
    workflow = next(row for row in members if row["member_id"] == "remote-issuer-workflow")
    receipt = {
        "schema_version": "rea.write.remote-issuance-receipt.v1",
        "issuer": MODULE.ISSUER,
        "workflow_repository": "rexcoleman/rexcoleman.dev",
        "event": "workflow_dispatch",
        "workflow_ref": "refs/tags/rea-wea-generation-4-fixture",
        "workflow_sha": "2" * 40,
        "workflow_run_id": 123,
        "wea_sha256": MODULE.digest(payloads["write_enforcement_attestation.json"]),
        "manifest_sha256": manifest["manifest_digest"],
        "workflow_blob_sha256": workflow["sha256"],
    }
    payloads["issuance_receipt.json"] = MODULE.canonical(receipt) + b"\n"
    for name, raw in payloads.items():
        (issuance / name).write_bytes(raw)
    (issuance / "SHA256SUMS").write_text("".join(
        f"{MODULE.digest((issuance / name).read_bytes())}  {name}\n"
        for name in sorted(payloads)
    ), encoding="ascii")

    changed_repository, changed_relative = MODULE.EXPECTED_MEMBERS[changed_member_id]
    (roots[changed_repository] / changed_relative).write_bytes(b"mutable-checkout-drift\n")
    monkeypatch.setattr(MODULE, "verify_signature", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        MODULE,
        "verify_envelope",
        lambda *_args, **_kwargs: {"issued_at": issued, "expires_at": expires},
    )
    monkeypatch.setattr(
        MODULE,
        "verify_successor_authority_bindings",
        lambda *_args, **_kwargs: ("a" * 64, {"PUB-01A": "publication"}),
    )
    return argparse.Namespace(
        issuance=issuance,
        workspace=workspace,
        consumer_id="artifact-relative-regression",
        surface="publication",
    )


@pytest.mark.parametrize("changed_member_id", [
    "claim-policy",
    "profile-registry",
    "trusted-public-key",
    "route-report",
])
def test_hosted_verifier_uses_exact_commit_objects_despite_checkout_drift(
        tmp_path, monkeypatch, changed_member_id):
    parsed = artifact_relative_packet(tmp_path, monkeypatch, changed_member_id)
    report = MODULE.verify(parsed)
    assert report["verdict"] == "PASS"
    assert report["public_checksums_verified"] is True


def test_hosted_verifier_refuses_crossed_signed_coverage_registry_digest(
        tmp_path, monkeypatch):
    parsed = artifact_relative_packet(
        tmp_path, monkeypatch, "managed-gate-coverage-registry"
    )
    issuance = parsed.issuance
    wea_path = issuance / "write_enforcement_attestation.json"
    wea = json.loads(wea_path.read_bytes())
    wea["coverage_registry_digest"] = "0" * 64
    unsigned = dict(wea)
    unsigned.pop("signature")
    signed_digest = MODULE.digest(MODULE.canonical(unsigned))
    wea["signature"] = {
        "algorithm": "ed25519", "signed_digest": signed_digest,
        "value": base64.b64encode(b"0" * 64).decode(),
    }
    wea_path.write_bytes(MODULE.canonical(wea) + b"\n")
    receipt_path = issuance / "issuance_receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["wea_sha256"] = MODULE.digest(wea_path.read_bytes())
    receipt_path.write_bytes(MODULE.canonical(receipt) + b"\n")
    payloads = sorted(MODULE.PUBLIC_ARTIFACTS - {"SHA256SUMS"})
    (issuance / "SHA256SUMS").write_text("".join(
        f"{MODULE.digest((issuance / name).read_bytes())}  {name}\n"
        for name in payloads
    ), encoding="ascii")

    with pytest.raises(MODULE.HostedWEARefusal) as captured:
        MODULE.verify(parsed)
    assert captured.value.reason_code == "WEA_WRONG_BUNDLE"
    assert captured.value.detail == "coverage_registry_digest"


def test_public_checksum_closure_verifies_all_nine_payload_files(tmp_path):
    issuance = public_packet_fixture(tmp_path)
    observed = MODULE.verify_public_checksums(issuance)
    assert set(observed) == MODULE.PUBLIC_ARTIFACTS - {"SHA256SUMS"}


@pytest.mark.parametrize("name", sorted(MODULE.PUBLIC_ARTIFACTS - {"SHA256SUMS"}))
def test_public_checksum_closure_refuses_each_changed_artifact(tmp_path, name):
    issuance = public_packet_fixture(tmp_path)
    (issuance / name).write_bytes(b"changed-after-checksum\n")
    with pytest.raises(MODULE.HostedWEARefusal) as captured:
        MODULE.verify_public_checksums(issuance)
    assert captured.value.reason_code == "WEA_WRONG_BUNDLE"
    assert captured.value.detail == f"sha256sums:{name}"


@pytest.mark.parametrize("artifact_name,member_id", [
    ("claim_registry.json", "claim-registry"),
    ("claim_policy.json", "claim-policy"),
    ("hybrid_capability_provider", "hybrid-capability-provider"),
    ("runtime_mount.py", "route-runtime-mount"),
])
def test_hosted_verifier_refuses_carried_member_copy_drift(
        tmp_path, artifact_name, member_id):
    issuance = public_packet_fixture(tmp_path)
    loaded = {
        "claim-registry": (issuance / "claim_registry.json").read_bytes(),
        "claim-policy": (issuance / "claim_policy.json").read_bytes(),
        "hybrid-capability-provider": (
            issuance / "hybrid_capability_provider"
        ).read_bytes(),
        "route-runtime-mount": (issuance / "runtime_mount.py").read_bytes(),
    }
    MODULE.verify_carried_member_copies(issuance, loaded)
    loaded[member_id] = b"different-signed-member-bytes\n"
    with pytest.raises(MODULE.HostedWEARefusal) as captured:
        MODULE.verify_carried_member_copies(issuance, loaded)
    assert captured.value.reason_code == "WEA_WRONG_BUNDLE"
    assert captured.value.detail == f"carried_member:{artifact_name}"


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
