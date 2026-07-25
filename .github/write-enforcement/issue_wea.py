#!/usr/bin/env python3
"""Protected-runner WEA issuer; never installed in an emitting project."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import member_contract
from member_contract import (
    AUTHORITY_GENERATION,
    EXPECTED_MEMBERS,
    RULESET_ID,
    normalize_ruleset,
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


def load_manifest(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    unsigned = {key: item for key, item in value.items() if key != "manifest_digest"}
    if (value.get("schema_version") != "rea.write.enforcement-bundle-manifest.v1"
            or value.get("manifest_digest") != digest(canonical(unsigned))
            or value.get("authority_generation") != AUTHORITY_GENERATION
            or value.get("ruleset_id") != RULESET_ID
            or not isinstance(value.get("members"), list) or not value["members"]):
        raise ValueError("manifest contract")
    return value


def verify_members(manifest: dict, workspace: Path) -> dict[str, bytes]:
    required_classes = {
        "boundary_gate", "resolver", "readiness_consumer", "live_emitter_binding",
        "master_runner_binding", "project_runner_binding", "scaffold_installer",
        "remote_workflow", "remote_ruleset", "claim_policy", "profile_registry",
        "trusted_public_key",
    }
    if set(manifest.get("required_member_classes", [])) != required_classes:
        raise IssuerRefusal("BUNDLE_MEMBER_SET_MISMATCH", "member_classes")
    observed = {}
    for row in manifest["members"]:
        if isinstance(row, dict) and isinstance(row.get("member_id"), str):
            observed[row["member_id"]] = (row.get("repository"), row.get("path"))
    if observed != EXPECTED_MEMBERS or len(observed) != len(manifest["members"]):
        missing = sorted(set(EXPECTED_MEMBERS) - set(observed))
        extra = sorted(set(observed) - set(EXPECTED_MEMBERS))
        changed = sorted(key for key in set(observed) & set(EXPECTED_MEMBERS)
                         if observed[key] != EXPECTED_MEMBERS[key])
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


def openssl(args: list[str]) -> None:
    result = subprocess.run(["openssl", *args], check=False, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError("openssl operation")


def verify_trust_roots(loaded: dict[str, bytes], public: bytes) -> None:
    if (loaded.get("trusted-public-key") != public
            or loaded.get("newsletter-trusted-public-key") != public):
        raise IssuerRefusal("TRUST_ROOT_COPY_MISMATCH", "govml_or_newsletter")


def issuance_times(now: datetime, mode: str) -> tuple[datetime, datetime]:
    if mode == "active":
        return now, now + timedelta(hours=24)
    if mode == "expired_fixture":
        return now - timedelta(hours=48), now - timedelta(hours=24)
    raise ValueError("issuance time mode")


def sign_payload(payload: dict, private_key: Path) -> dict:
    signed_digest = digest(canonical(payload))
    digest_path, signature_path = private_key.parent / "unsigned.digest", private_key.parent / "wea.sig"
    digest_path.write_bytes(bytes.fromhex(signed_digest))
    openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
             "-in", str(digest_path), "-out", str(signature_path)])
    signed = dict(payload)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signed_digest": signed_digest,
        "value": base64.b64encode(signature_path.read_bytes()).decode(),
    }
    digest_path.unlink(); signature_path.unlink()
    return signed


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("manifest", "workspace", "ruleset-json", "private-key", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--time-mode", choices=("active", "expired_fixture"), default="active")
    parser.add_argument("--predecessor-wea-digest", default="")
    args = parser.parse_args()
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
    openssl(["pkey", "-in", str(args.private_key), "-pubout", "-out", str(public_path)])
    public = public_path.read_bytes()
    verify_trust_roots(loaded, public)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at, expires_at = issuance_times(now, args.time_mode)
    predecessor = args.predecessor_wea_digest.strip() or None
    if args.time_mode == "active":
        if AUTHORITY_GENERATION > 1 and not re.fullmatch(r"[0-9a-f]{64}", predecessor or ""):
            raise IssuerRefusal("PREDECESSOR_WEA_DIGEST_REQUIRED", "active generation-4 issuance")
        payload = {
            "schema_version": "rea.write.wea.live.v2",
            "purpose": "LIVE_ENFORCEMENT",
            "state": "ENFORCING",
            "authority_epoch": manifest["authority_generation"],
            "predecessor_wea_digest": predecessor,
            "issuer": ISSUER,
            "issuer_source_digest": digest(loaded["remote-issuer"] + loaded["remote-member-contract"]),
            "renewal_policy_digest": digest(b"successor-required:no-human-cadence:v1"),
            "issuance_receipt_digest": digest(f"pending:{os.environ['GITHUB_RUN_ID']}:{now.isoformat()}".encode()),
            "coverage_registry_digest": digest(loaded["profile-registry"]),
            "coverage_registry_generation": manifest["authority_generation"],
            "publishing_capability_scope": scope,
            "required_surfaces": ["report", "blog", "publication", "distribution"],
        }
    else:
        payload = {
            "schema_version": "rea.write.wea.r4-fixture.v1",
            "purpose": "R4_NEGATIVE_FIXTURE",
            "state": "FIXTURE",
            "authority_epoch": manifest["authority_generation"],
            "predecessor_wea_digest": None,
            "issuer": ISSUER,
            "issuer_source_digest": digest(loaded["remote-issuer"] + loaded["remote-member-contract"]),
            "renewal_policy_digest": digest(b"fixture:no-production-use:v1"),
            "issuance_receipt_digest": digest(f"fixture:{os.environ['GITHUB_RUN_ID']}:{now.isoformat()}".encode()),
            "coverage_registry_digest": digest(loaded["profile-registry"]),
            "coverage_registry_generation": manifest["authority_generation"],
            "fixture_id": f"r4-fixture-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}",
            "production_eligible": False,
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
        "schema_version": "rea.write.remote-issuance-receipt.v1", "issuer": ISSUER,
        "workflow_repository": os.environ["GITHUB_REPOSITORY"], "workflow_ref": os.environ["GITHUB_REF"],
        "workflow_sha": os.environ["GITHUB_SHA"], "workflow_blob_sha256": digest(live_workflow),
        "workflow_run_id": int(os.environ["GITHUB_RUN_ID"]),
        "workflow_run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "event": os.environ["GITHUB_EVENT_NAME"],
        "wea_sha256": digest(wea_path.read_bytes()), "manifest_sha256": manifest["manifest_digest"],
        "issued_at": wea["issued_at"],
    }
    (args.output / "issuance_receipt.json").write_bytes(canonical(receipt) + b"\n")
    names = ("write_enforcement_attestation.json", "enforcement_bundle_manifest.json",
             "issuance_receipt.json", "trusted_wea_public.pem")
    (args.output / "SHA256SUMS").write_text("".join(
        f"{digest((args.output / name).read_bytes())}  {name}\n" for name in names), encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
