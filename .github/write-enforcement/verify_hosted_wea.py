#!/usr/bin/env python3
"""Verify a remote-issued WEA in protected hosted workflows."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from member_contract import (
    AUTHORITY_GENERATION,
    EXPECTED_MEMBERS,
    derive_write_boundary_route_surface_bindings,
    write_boundary_policy_digest,
)

ISSUER = "https://github.com/rexcoleman/rexcoleman.dev/actions/workflows/issue-write-enforcement-attestation.yml"
REF_PREFIX = f"refs/tags/rea-wea-generation-{AUTHORITY_GENERATION}-"
SURFACES = {"report", "blog", "publication", "distribution"}
PUBLIC_ARTIFACTS = {
    "SHA256SUMS", "claim_policy.json", "claim_registry.json",
    "enforcement_bundle_manifest.json", "hybrid_capability_authority.json",
    "hybrid_capability_provider", "issuance_receipt.json", "runtime_mount.py",
    "trusted_wea_public.pem", "write_enforcement_attestation.json",
}


class HostedWEARefusal(Exception):
    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}:{detail}")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(char in "0123456789abcdef" for char in value)


def load(path: Path) -> tuple[bytes, dict]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"not object: {path}")
    return raw, value


def verify_signature(public: Path, signed_digest: str, signature_b64: str) -> None:
    signature = base64.b64decode(signature_b64, validate=True)
    if len(signature) != 64:
        raise ValueError("signature length")
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        (root / "digest").write_bytes(bytes.fromhex(signed_digest))
        (root / "signature").write_bytes(signature)
        subprocess.run([
            "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public),
            "-rawin", "-in", str(root / "digest"), "-sigfile", str(root / "signature"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def verify_envelope(public: Path, envelope: dict, label: str) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise HostedWEARefusal("WEA_CORRUPT", f"{label}_envelope")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise HostedWEARefusal("WEA_CORRUPT", f"{label}_shape")
    signed_digest = digest(canonical(payload))
    if (
        set(signature) != {"algorithm", "signed_digest", "value"}
        or signature.get("algorithm") != "ed25519"
        or signature.get("signed_digest") != signed_digest
    ):
        raise HostedWEARefusal("WEA_CORRUPT", f"{label}_signature_shape")
    try:
        verify_signature(public, signed_digest, signature.get("value", ""))
    except (ValueError, subprocess.CalledProcessError):
        raise HostedWEARefusal("WEA_CORRUPT", f"{label}_signature") from None
    return payload


def verify_successor_authority_bindings(
    hybrid_payload: dict,
    loaded: dict[str, bytes],
    manifest: dict,
    wea_raw: bytes,
) -> tuple[str, dict[str, str | list[str]]]:
    """Recompute successor policy and route closure from verified member bytes."""
    required_hybrid_fields = {
        "schema_version", "purpose", "issuer", "authority_epoch", "wea_sha256",
        "enforcement_bundle_manifest_digest", "claim_registry_sha256",
        "claim_policy_sha256", "provider_sha256", "runtime_mount_sha256",
        "write_boundary_policy_sha256", "route_surface_bindings", "issued_at",
        "expires_at",
    }
    try:
        expected_route_bindings = derive_write_boundary_route_surface_bindings(
            loaded["write-boundary-row-registry"],
            loaded["write-boundary-seam-registry"],
        )
        expected_policy_digest = write_boundary_policy_digest(loaded)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise HostedWEARefusal("WEA_WRONG_BUNDLE", "write_boundary_policy") from None
    if (
        set(hybrid_payload) != required_hybrid_fields
        or hybrid_payload.get("schema_version")
        != "rea.write.hybrid-capability-authority.v1"
        or hybrid_payload.get("purpose") != "VERIFY_ONLY_CURRENT_REGISTRY"
        or hybrid_payload.get("issuer") != ISSUER
        or hybrid_payload.get("authority_epoch") != AUTHORITY_GENERATION
        or hybrid_payload.get("wea_sha256") != digest(wea_raw)
        or hybrid_payload.get("enforcement_bundle_manifest_digest")
        != manifest["manifest_digest"]
        or hybrid_payload.get("claim_registry_sha256")
        != digest(loaded["claim-registry"])
        or hybrid_payload.get("claim_policy_sha256") != digest(loaded["claim-policy"])
        or hybrid_payload.get("provider_sha256")
        != digest(loaded["hybrid-capability-provider"])
        or hybrid_payload.get("runtime_mount_sha256")
        != digest(loaded["route-runtime-mount"])
        or hybrid_payload.get("write_boundary_policy_sha256")
        != expected_policy_digest
        or hybrid_payload.get("route_surface_bindings") != expected_route_bindings
    ):
        raise HostedWEARefusal("WEA_WRONG_BUNDLE", "hybrid_authority_binding")
    return expected_policy_digest, expected_route_bindings


def verify(args: argparse.Namespace) -> dict:
    roots = {
        "research_enforcement_activation": args.workspace / "research_enforcement_activation",
        "govML": args.workspace / "govML",
        "Moonshots_Career_Thesis_v2": args.workspace / "Moonshots_Career_Thesis_v2",
        "newsletter": args.workspace / "newsletter",
        "rexcoleman.dev": args.workspace / "rexcoleman.dev",
    }
    if {path.name for path in args.issuance.iterdir() if path.is_file()} != PUBLIC_ARTIFACTS:
        raise HostedWEARefusal("WEA_CORRUPT", "public_artifact_set")
    wea_raw, wea = load(args.issuance / "write_enforcement_attestation.json")
    manifest_raw, manifest = load(args.issuance / "enforcement_bundle_manifest.json")
    _, receipt = load(args.issuance / "issuance_receipt.json")
    public = args.issuance / "trusted_wea_public.pem"
    public_raw = public.read_bytes()
    pinned = [
        roots["govML"] / "templates/build/enforcement/trusted_wea_public.pem",
        roots["newsletter"] / ".github/integrity/wea/trusted_wea_public.pem",
    ]
    if any(path.read_bytes() != public_raw for path in pinned):
        raise HostedWEARefusal("WEA_CORRUPT", "trusted_public_key_mismatch")
    unsigned_manifest = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest.get("schema_version") != "rea.write.enforcement-bundle-manifest.v1" or digest(canonical(unsigned_manifest)) != manifest.get("manifest_digest"):
        raise HostedWEARefusal("WEA_CORRUPT", "manifest_digest")
    if manifest.get("authority_generation") != AUTHORITY_GENERATION:
        raise HostedWEARefusal("WEA_WRONG_BUNDLE", "authority_generation")
    members = manifest.get("members")
    if not isinstance(members, list) or not members:
        raise HostedWEARefusal("WEA_CORRUPT", "manifest_members")
    seen = set()
    loaded: dict[str, bytes] = {}
    for row in members:
        member_id, repository, relative = row["member_id"], row["repository"], row["path"]
        if member_id in seen or repository not in roots or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise HostedWEARefusal("WEA_CORRUPT", "manifest_member_shape")
        seen.add(member_id)
        payload = (roots[repository] / relative).read_bytes()
        if digest(payload) != row["sha256"] or len(payload) != row["byte_length"]:
            raise HostedWEARefusal("WEA_WRONG_BUNDLE", member_id)
        loaded[member_id] = payload
    observed_members = {
        row["member_id"]: (row["repository"], row["path"])
        for row in members
    }
    if observed_members != EXPECTED_MEMBERS or len(loaded) != len(EXPECTED_MEMBERS):
        raise HostedWEARefusal("WEA_WRONG_BUNDLE", "member_set")

    _, hybrid_authority = load(args.issuance / "hybrid_capability_authority.json")
    hybrid_payload = verify_envelope(public, hybrid_authority, "hybrid_authority")
    expected_policy_digest, expected_route_bindings = (
        verify_successor_authority_bindings(
            hybrid_payload, loaded, manifest, wea_raw
        )
    )
    registry = json.loads((roots["research_enforcement_activation"] / "write_integrity/foundation/publishing_capability_profiles.json").read_bytes())
    scope = [row["profile_id"] for row in registry["profiles"] if row.get("publishes") is True]
    policy = (roots["research_enforcement_activation"] / "write_integrity/authority/claim_policy.json").read_bytes()
    if wea.get("schema_version") == "rea.write.wea.r4-fixture.v1" or wea.get("purpose") == "R4_NEGATIVE_FIXTURE":
        raise HostedWEARefusal("WEA_WRONG_PURPOSE", "R4_NEGATIVE_FIXTURE")
    if wea.get("schema_version") == "rea.write.wea.live.v2":
        generation = wea.get("authority_epoch")
        if (
            wea.get("issuer") != ISSUER
            or wea.get("purpose") != "LIVE_ENFORCEMENT"
            or wea.get("state") != "ENFORCING"
            or generation != AUTHORITY_GENERATION
            or not lower_hex(wea.get("predecessor_wea_digest"), 64)
        ):
            raise HostedWEARefusal("WEA_CORRUPT", "remote_state")
    elif (wea.get("issuer") != ISSUER or wea.get("state") != "ENFORCING"
            or wea.get("authority_generation") != AUTHORITY_GENERATION):
        raise HostedWEARefusal("WEA_CORRUPT", "remote_state")
    else:
        generation = wea["authority_generation"]
    if wea.get("publishing_capability_scope") != scope or set(wea.get("required_surfaces", [])) != SURFACES:
        raise HostedWEARefusal("WEA_CORRUPT", "scope")
    if wea.get("enforcement_bundle_manifest_digest") != manifest["manifest_digest"] or wea.get("claim_policy_digest") != digest(policy):
        raise HostedWEARefusal("WEA_WRONG_BUNDLE", "bundle_or_policy")
    if wea.get("trusted_key_id") != f"rea-wea-ed25519-{digest(public_raw)[:16]}":
        raise HostedWEARefusal("WEA_CORRUPT", "key_id")
    signature = wea.get("signature")
    unsigned_wea = {key: value for key, value in wea.items() if key != "signature"}
    signed_digest = digest(canonical(unsigned_wea))
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519" or signature.get("signed_digest") != signed_digest:
        raise HostedWEARefusal("WEA_CORRUPT", "signature_shape")
    try:
        verify_signature(public, signed_digest, signature.get("value", ""))
    except (ValueError, subprocess.CalledProcessError) as exc:
        raise HostedWEARefusal("WEA_CORRUPT", f"signature:{type(exc).__name__}") from None
    now = datetime.now(timezone.utc)
    issued = datetime.fromisoformat(wea["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(wea["expires_at"].replace("Z", "+00:00"))
    if issued > now or expires <= issued or expires <= now:
        reason = "WEA_EXPIRED" if expires <= now else "WEA_CORRUPT"
        raise HostedWEARefusal(reason, "time")
    if (
        hybrid_payload["issued_at"] != wea["issued_at"]
        or hybrid_payload["expires_at"] != wea["expires_at"]
    ):
        raise HostedWEARefusal("WEA_WRONG_BUNDLE", "hybrid_authority_time")
    workflow_ref = receipt.get("workflow_ref")
    workflow_sha = receipt.get("workflow_sha")
    workflow_rows = [row for row in members if row["member_id"] == "remote-issuer-workflow"]
    if (
        receipt.get("issuer") != ISSUER
        or receipt.get("workflow_repository") != "rexcoleman/rexcoleman.dev"
        or receipt.get("event") != "workflow_dispatch"
        or not isinstance(workflow_ref, str) or not workflow_ref.startswith(REF_PREFIX) or workflow_ref == REF_PREFIX
        or not lower_hex(workflow_sha, 40)
        or receipt.get("wea_sha256") != digest(wea_raw)
        or receipt.get("manifest_sha256") != manifest["manifest_digest"]
        or len(workflow_rows) != 1
        or receipt.get("workflow_blob_sha256") != workflow_rows[0]["sha256"]
    ):
        raise HostedWEARefusal("WEA_CORRUPT", "remote_provenance")
    tuple_value = {
        "state": "ENFORCING", "state_digest": digest(wea_raw),
        "authority_generation": generation,
        "enforcement_bundle_manifest_digest": manifest["manifest_digest"],
        "required_surfaces": wea["required_surfaces"],
    }
    report = {
        "schema_version": "rea.write.wea-consumer-report.v1",
        "consumer_id": args.consumer_id, "surface": args.surface,
        "verdict": "PASS", "raw_exit": 0, "remote_issued": True,
        "wea_status_tuple": tuple_value,
        "wea_status_tuple_digest": digest(canonical(tuple_value)),
        "workflow_run_id": receipt["workflow_run_id"],
        "write_boundary_policy_sha256": expected_policy_digest,
        "write_boundary_route_count": len(expected_route_bindings),
    }
    return report


def refusal_report(args: argparse.Namespace, reason: str, detail: str = "") -> dict:
    path = args.issuance / "write_enforcement_attestation.json"
    try:
        state_digest = digest(path.read_bytes())
    except OSError:
        state_digest = None
    return {
        "schema_version": "rea.write.wea-consumer-report.v1",
        "consumer_id": args.consumer_id,
        "surface": args.surface,
        "verdict": "REFUSE",
        "reason_code": reason,
        "detail": detail,
        "raw_exit": 3,
        "remote_issued": False,
        "state_digest": state_digest,
        "mutation_observed": False,
    }


def run(args: argparse.Namespace) -> tuple[int, dict]:
    try:
        return 0, verify(args)
    except HostedWEARefusal as exc:
        return 3, refusal_report(args, exc.reason_code, exc.detail)
    except FileNotFoundError as exc:
        reason = "WEA_MISSING" if exc.filename == str(args.issuance / "write_enforcement_attestation.json") else "WEA_CORRUPT"
        return 3, refusal_report(args, reason, Path(exc.filename or "unknown").name)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return 3, refusal_report(args, "WEA_CORRUPT", type(exc).__name__)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuance", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--consumer-id", required=True)
    parser.add_argument("--surface", choices=sorted(SURFACES))
    args = parser.parse_args()
    raw_exit, report = run(args)
    print(json.dumps(report, sort_keys=True))
    return raw_exit


if __name__ == "__main__":
    raise SystemExit(main())
