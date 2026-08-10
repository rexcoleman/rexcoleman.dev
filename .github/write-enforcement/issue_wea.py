#!/usr/bin/env python3
"""Protected-runner WEA issuer; never installed in an emitting project."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import member_contract
from member_contract import (
    AUTHORITY_GENERATION,
    EXPECTED_MEMBERS,
    REQUIRED_MEMBER_CLASSES,
    RULESET_ID,
    STAGED_NONPRODUCTION_MANIFEST_SCHEMA,
    STAGED_NONPRODUCTION_HYBRID_PURPOSE,
    STAGED_NONPRODUCTION_HYBRID_SCHEMA,
    STAGED_NONPRODUCTION_PURPOSE,
    STAGED_NONPRODUCTION_RECEIPT_SCHEMA,
    STAGED_NONPRODUCTION_WEA_SCHEMA,
    derive_write_boundary_route_surface_bindings,
    normalize_ruleset,
    staged_nonproduction_members,
    write_boundary_policy_digest,
)

ISSUER = "https://github.com/rexcoleman/rexcoleman.dev/actions/workflows/issue-write-enforcement-attestation.yml"
REPOSITORIES = {
    "research_enforcement_activation": "research_enforcement_activation",
    "govML": "govML",
    "Moonshots_Career_Thesis_v2": "Moonshots_Career_Thesis_v2",
    "newsletter": "newsletter",
    "rexcoleman.dev": "rexcoleman.dev",
}


class IssuerRefusal(RuntimeError):
    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def committed_bytes(root: Path, commit: str, path: str) -> bytes:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("member commit")
    if Path(path).is_absolute() or ".." in Path(path).parts:
        raise ValueError("member path")
    result = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{path}"],
                            check=False, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError(f"member unavailable: {root.name}:{path}")
    return result.stdout


def load_manifest(path: Path, *, staged_nonproduction: bool = False) -> dict:
    value = json.loads(path.read_bytes())
    unsigned = {key: item for key, item in value.items() if key != "manifest_digest"}
    expected_schema = (
        STAGED_NONPRODUCTION_MANIFEST_SCHEMA
        if staged_nonproduction
        else "rea.write.enforcement-bundle-manifest.v1"
    )
    if (value.get("schema_version") != expected_schema
            or value.get("manifest_digest") != digest(canonical(unsigned))
            or value.get("authority_generation") != AUTHORITY_GENERATION
            or value.get("ruleset_id") != RULESET_ID
            or not isinstance(value.get("members"), list) or not value["members"]):
        raise ValueError("manifest contract")
    return value


def verify_members(
    manifest: dict,
    workspace: Path,
    *,
    staged_nonproduction: bool = False,
) -> dict[str, bytes]:
    classes = manifest.get("required_member_classes")
    if (
        not isinstance(classes, list)
        or len(classes) != len(REQUIRED_MEMBER_CLASSES)
        or set(classes) != set(REQUIRED_MEMBER_CLASSES)
    ):
        raise IssuerRefusal("BUNDLE_MEMBER_SET_MISMATCH", "member_classes")
    expected_members = (
        staged_nonproduction_members()
        if staged_nonproduction
        else EXPECTED_MEMBERS
    )
    observed = {}
    for row in manifest["members"]:
        if isinstance(row, dict) and isinstance(row.get("member_id"), str):
            observed[row["member_id"]] = (row.get("repository"), row.get("path"))
    if observed != expected_members or len(observed) != len(manifest["members"]):
        missing = sorted(set(expected_members) - set(observed))
        extra = sorted(set(observed) - set(expected_members))
        changed = sorted(key for key in set(observed) & set(expected_members)
                         if observed[key] != expected_members[key])
        raise IssuerRefusal("BUNDLE_MEMBER_SET_MISMATCH",
                            f"missing={missing};extra={extra};changed={changed}")
    loaded: dict[str, bytes] = {}
    for row in manifest["members"]:
        if not isinstance(row, dict) or set(row) != {
            "member_id", "repository", "commit", "path", "sha256", "byte_length"
        } or row["repository"] not in REPOSITORIES or row["member_id"] in loaded:
            raise ValueError("member shape")
        raw = committed_bytes(workspace / REPOSITORIES[row["repository"]], row["commit"], row["path"])
        if len(raw) != row["byte_length"] or digest(raw) != row["sha256"]:
            raise ValueError(f"member mismatch: {row['member_id']}")
        loaded[row["member_id"]] = raw
    return loaded


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(
            path.read_bytes(), password=None, backend=default_backend()
        )
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key algorithm")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(
            path.read_bytes(), backend=default_backend()
        )
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key algorithm")
    return key


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_trust_roots(
    loaded: dict[str, bytes], public: bytes, *, staged_nonproduction: bool = False
) -> None:
    if staged_nonproduction:
        staged = loaded.get("staged-nonproduction-trusted-public-key")
        production = (
            loaded.get("trusted-public-key"),
            loaded.get("newsletter-trusted-public-key"),
        )
        valid = staged == public and all(root != public for root in production)
    else:
        valid = (
            loaded.get("trusted-public-key") == public
            and loaded.get("newsletter-trusted-public-key") == public
        )
    if not valid:
        raise IssuerRefusal("TRUST_ROOT_COPY_MISMATCH", "govml_or_newsletter")


def issuance_times(now: datetime) -> tuple[datetime, datetime]:
    """Production issuer exposes one coherent active-successor mode."""
    return now, now + timedelta(hours=24)


def sign_payload(payload: dict, private_key: Path) -> dict:
    signed_digest = digest(canonical(payload))
    signature = load_private_key(private_key).sign(
        bytes.fromhex(signed_digest)
    )
    signed = dict(payload)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signed_digest": signed_digest,
        "value": base64.b64encode(signature).decode(),
    }
    return signed


def sign_envelope(payload: dict, private_key: Path) -> dict:
    signed = sign_payload(payload, private_key)
    return {
        "payload": {key: value for key, value in signed.items() if key != "signature"},
        "signature": signed["signature"],
    }


def authenticated_predecessor(
    path: Path, public_key: Path, *, staged_nonproduction: bool = False
) -> tuple[bytes, dict]:
    """Authenticate the exact artifact being replaced and derive its epoch."""
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise IssuerRefusal("PREDECESSOR_WEA_INVALID", "not_object")
    signature = value.get("signature")
    payload = {key: item for key, item in value.items() if key != "signature"}
    signed_digest = digest(canonical(payload))
    if (
        not isinstance(signature, dict)
        or signature.get("algorithm") != "ed25519"
        or signature.get("signed_digest") != signed_digest
        or payload.get("schema_version") != (
            STAGED_NONPRODUCTION_WEA_SCHEMA
            if staged_nonproduction else "rea.write.wea.live.v2"
        )
        or payload.get("purpose") != (
            STAGED_NONPRODUCTION_PURPOSE
            if staged_nonproduction else "LIVE_ENFORCEMENT"
        )
        or payload.get("state") != "ENFORCING"
        or payload.get("issuer") != ISSUER
        or isinstance(payload.get("authority_epoch"), bool)
        or not isinstance(payload.get("authority_epoch"), int)
        or payload["authority_epoch"] < 1
    ):
        raise IssuerRefusal("PREDECESSOR_WEA_INVALID", "shape")
    try:
        signature_raw = base64.b64decode(signature.get("value", ""), validate=True)
        if len(signature_raw) != 64:
            raise ValueError("signature_length")
        load_public_key(public_key).verify(
            signature_raw, bytes.fromhex(signed_digest)
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise IssuerRefusal("PREDECESSOR_WEA_INVALID", "signature") from None
    return raw, payload


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("manifest", "workspace", "ruleset-json", "private-key", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--predecessor-wea", type=Path)
    parser.add_argument("--predecessor-wea-sha256", required=True)
    parser.add_argument("--staged-nonproduction", action="store_true")
    args = parser.parse_args()
    if args.staged_nonproduction:
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
            raise IssuerRefusal(
                "STAGED_NONPRODUCTION_HOSTED_REFUSED", "GITHUB_ACTIONS"
            )
        try:
            args.output.resolve().relative_to(Path("/tmp"))
            args.private_key.resolve().relative_to(Path("/tmp"))
            args.workspace.resolve().relative_to(Path("/tmp"))
        except ValueError:
            raise IssuerRefusal(
                "STAGED_NONPRODUCTION_TMP_REQUIRED", "output_private_workspace"
            ) from None
    if args.staged_nonproduction:
        manifest = load_manifest(args.manifest, staged_nonproduction=True)
        loaded = verify_members(
            manifest, args.workspace, staged_nonproduction=True
        )
    else:
        manifest = load_manifest(args.manifest)
        loaded = verify_members(manifest, args.workspace)
    ruleset = json.loads(args.ruleset_json.read_bytes())
    if (ruleset.get("id") != RULESET_ID
            or digest(canonical(normalize_ruleset(ruleset))) != manifest.get("normalized_ruleset_sha256")):
        raise ValueError("live ruleset drift")
    live_workflow = committed_bytes(
        args.workspace / "rexcoleman.dev", os.environ["GITHUB_SHA"],
        ".github/workflows/issue-write-enforcement-attestation.yml",
    )
    if live_workflow != loaded["remote-issuer-workflow"]:
        raise ValueError("workflow byte drift")
    if Path(__file__).read_bytes() != loaded["remote-issuer"]:
        raise IssuerRefusal("BUNDLE_MEMBER_BYTES_MISMATCH", "remote-issuer")
    if Path(member_contract.__file__).read_bytes() != loaded["remote-member-contract"]:
        raise IssuerRefusal("BUNDLE_MEMBER_BYTES_MISMATCH", "remote-member-contract")

    registry = json.loads(loaded["profile-registry"])
    scope = [row["profile_id"] for row in registry["profiles"] if row.get("publishes") is True]
    args.output.mkdir(parents=True, exist_ok=True)
    public_path = args.output / "trusted_wea_public.pem"
    private_key = load_private_key(args.private_key)
    public = public_bytes(private_key)
    public_path.write_bytes(public)
    verify_trust_roots(
        loaded, public, staged_nonproduction=args.staged_nonproduction
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at, expires_at = issuance_times(now)
    if args.predecessor_wea is None:
        raise IssuerRefusal("PREDECESSOR_WEA_REQUIRED", "active issuance")
    predecessor_raw, predecessor_payload = authenticated_predecessor(
        args.predecessor_wea,
        public_path,
        staged_nonproduction=args.staged_nonproduction,
    )
    predecessor = digest(predecessor_raw)
    if predecessor != args.predecessor_wea_sha256:
        raise IssuerRefusal("PREDECESSOR_WEA_INVALID", "dispatch_digest_mismatch")
    issuance_epoch = predecessor_payload["authority_epoch"] + 1
    payload = {
            "schema_version": (
                STAGED_NONPRODUCTION_WEA_SCHEMA
                if args.staged_nonproduction else "rea.write.wea.live.v2"
            ),
            "purpose": (
                STAGED_NONPRODUCTION_PURPOSE
                if args.staged_nonproduction else "LIVE_ENFORCEMENT"
            ),
            "state": "ENFORCING",
            "authority_epoch": issuance_epoch,
            "predecessor_wea_digest": predecessor,
            "issuer": ISSUER,
            "issuer_source_digest": digest(loaded["remote-issuer"] + loaded["remote-member-contract"]),
            "renewal_policy_digest": digest(b"successor-required:no-human-cadence:v1"),
            "issuance_receipt_digest": digest(f"pending:{os.environ['GITHUB_RUN_ID']}:{now.isoformat()}".encode()),
            "coverage_registry_digest": digest(
                loaded["managed-gate-coverage-registry"]
            ),
            "coverage_registry_generation": manifest["authority_generation"],
            "publishing_capability_scope": scope,
            "required_surfaces": ["report", "blog", "publication", "distribution"],
        }
    payload.update({
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "not_before": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "enforcement_bundle_manifest_digest": manifest["manifest_digest"],
        "claim_policy_digest": digest(loaded["claim-policy"]),
        "trusted_key_id": f"rea-wea-ed25519-{digest(public)[:16]}",
    })
    wea = sign_payload(payload, args.private_key)
    wea_path = args.output / "write_enforcement_attestation.json"
    manifest_path = args.output / "enforcement_bundle_manifest.json"
    wea_path.write_bytes(canonical(wea) + b"\n")
    manifest_path.write_bytes(canonical(manifest) + b"\n")
    receipt = {
        "schema_version": (
            STAGED_NONPRODUCTION_RECEIPT_SCHEMA
            if args.staged_nonproduction
            else "rea.write.remote-issuance-receipt.v1"
        ), "issuer": ISSUER,
        "workflow_repository": os.environ["GITHUB_REPOSITORY"], "workflow_ref": os.environ["GITHUB_REF"],
        "workflow_sha": os.environ["GITHUB_SHA"], "workflow_blob_sha256": digest(live_workflow),
        "workflow_run_id": int(os.environ["GITHUB_RUN_ID"]),
        "workflow_run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "event": os.environ["GITHUB_EVENT_NAME"],
        "wea_sha256": digest(wea_path.read_bytes()), "manifest_sha256": manifest["manifest_digest"],
        "issued_at": wea["issued_at"],
    }
    (args.output / "issuance_receipt.json").write_bytes(canonical(receipt) + b"\n")
    registry_path = args.output / "claim_registry.json"
    policy_path = args.output / "claim_policy.json"
    provider_path = args.output / "hybrid_capability_provider"
    runtime_path = args.output / "runtime_mount.py"
    registry_path.write_bytes(loaded["claim-registry"])
    policy_path.write_bytes(loaded["claim-policy"])
    provider_path.write_bytes(loaded["hybrid-capability-provider"])
    runtime_path.write_bytes(loaded["route-runtime-mount"])
    provider_path.chmod(0o755)
    runtime_path.chmod(0o755)
    try:
        route_surface_bindings = derive_write_boundary_route_surface_bindings(
            loaded["write-boundary-row-registry"],
            loaded["write-boundary-seam-registry"],
        )
        boundary_policy_sha256 = write_boundary_policy_digest(loaded)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IssuerRefusal(
            "WRITE_BOUNDARY_POLICY_INVALID", type(exc).__name__
        ) from None
    hybrid_payload = {
        "schema_version": (
            STAGED_NONPRODUCTION_HYBRID_SCHEMA
            if args.staged_nonproduction
            else "rea.write.hybrid-capability-authority.v1"
        ),
        "purpose": (
            STAGED_NONPRODUCTION_HYBRID_PURPOSE
            if args.staged_nonproduction
            else "VERIFY_ONLY_CURRENT_REGISTRY"
        ),
        "issuer": ISSUER,
        "authority_epoch": payload["authority_epoch"],
        "wea_sha256": digest(wea_path.read_bytes()),
        "enforcement_bundle_manifest_digest": manifest["manifest_digest"],
        "claim_registry_sha256": digest(registry_path.read_bytes()),
        "claim_policy_sha256": digest(policy_path.read_bytes()),
        "provider_sha256": digest(provider_path.read_bytes()),
        "runtime_mount_sha256": digest(runtime_path.read_bytes()),
        "write_boundary_policy_sha256": boundary_policy_sha256,
        "route_surface_bindings": route_surface_bindings,
        "issued_at": wea["issued_at"],
        "expires_at": wea["expires_at"],
    }
    authority_path = args.output / "hybrid_capability_authority.json"
    authority_path.write_bytes(canonical(sign_envelope(hybrid_payload, args.private_key)) + b"\n")
    (args.output / "predecessor_write_enforcement_attestation.json").write_bytes(
        predecessor_raw
    )
    names = (
        "write_enforcement_attestation.json",
        "enforcement_bundle_manifest.json",
        "issuance_receipt.json",
        "trusted_wea_public.pem",
        "claim_registry.json",
        "claim_policy.json",
        "hybrid_capability_provider",
        "runtime_mount.py",
        "hybrid_capability_authority.json",
    )
    names = names + ("predecessor_write_enforcement_attestation.json",)
    (args.output / "SHA256SUMS").write_text("".join(
        f"{digest((args.output / name).read_bytes())}  {name}\n" for name in names), encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
