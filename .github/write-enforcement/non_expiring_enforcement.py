#!/usr/bin/env python3
"""Non-expiring project-carried enforcement packet verifier and reconciler."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


PACKET_SCHEMA = "rea.write.non-expiring-enforcement.packet.v1"
REVOCATION_SCHEMA = "rea.write.non-expiring-enforcement.revocations.v1"
VERIFY_REPORT_SCHEMA = "rea.write.non-expiring-enforcement.verify-report.v1"
RECONCILE_REPORT_SCHEMA = "rea.write.non-expiring-enforcement.reconcile-report.v1"
PURPOSE = "NON_EXPIRING_LIVE_ENFORCEMENT"
ISSUER_MODE = "protected-default-automated"
PACKET_NAME = "enforcement_packet.json"
REVOCATION_NAME = "revocations.json"
PUBLIC_KEY_NAME = "trusted_wea_public.pem"
CHECKSUM_NAME = "SHA256SUMS"
PACKET_FILES = frozenset({
    PACKET_NAME,
    REVOCATION_NAME,
    PUBLIC_KEY_NAME,
    CHECKSUM_NAME,
})
SURFACES = frozenset({"report", "blog", "publication", "distribution"})


class EnforcementRefusal(RuntimeError):
    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _hex40(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(char in "0123456789abcdef" for char in value)
    )


def _instant(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EnforcementRefusal("PACKET_CORRUPT", f"{field}:not_utc")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(
            timezone.utc
        )
    except ValueError:
        raise EnforcementRefusal("PACKET_CORRUPT", f"{field}:invalid") from None


def _object(raw: bytes, reason_code: str, detail: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise EnforcementRefusal(reason_code, detail) from None
    if not isinstance(value, dict):
        raise EnforcementRefusal(reason_code, detail)
    return value


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(raw, backend=default_backend())
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise EnforcementRefusal("TRUST_ROOT_INVALID", type(exc).__name__) from None
    if not isinstance(key, Ed25519PublicKey):
        raise EnforcementRefusal("TRUST_ROOT_INVALID", "not_ed25519")
    return key


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(
            path.read_bytes(), password=None, backend=default_backend()
        )
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm):
        raise EnforcementRefusal("PRIVATE_KEY_INVALID", str(path)) from None
    if not isinstance(key, Ed25519PrivateKey):
        raise EnforcementRefusal("PRIVATE_KEY_INVALID", "not_ed25519")
    return key


def verify_signature(public: Ed25519PublicKey, payload: dict[str, Any],
                     signature: object) -> None:
    signed_digest = digest(canonical(payload))
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "signed_digest", "value"}
        or signature.get("algorithm") != "ed25519"
        or signature.get("signed_digest") != signed_digest
    ):
        raise EnforcementRefusal("SIGNATURE_INVALID", "shape_or_digest")
    try:
        signature_raw = base64.b64decode(signature.get("value", ""), validate=True)
        if len(signature_raw) != 64:
            raise ValueError("length")
        public.verify(signature_raw, bytes.fromhex(signed_digest))
    except (InvalidSignature, ValueError, binascii.Error):
        raise EnforcementRefusal("SIGNATURE_INVALID", "ed25519") from None


def sign_payload(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> dict:
    signed_digest = digest(canonical(payload))
    signature = private_key.sign(bytes.fromhex(signed_digest))
    signed = dict(payload)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signed_digest": signed_digest,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def verify_checksums(packet_root: Path) -> dict[str, str]:
    names = {path.name for path in packet_root.iterdir() if path.is_file()}
    if names != PACKET_FILES:
        raise EnforcementRefusal("PACKET_CORRUPT", "artifact_set")
    rows: dict[str, str] = {}
    for line in (packet_root / CHECKSUM_NAME).read_text(encoding="ascii").splitlines():
        parts = line.split("  ")
        if len(parts) != 2 or not _sha(parts[0]) or parts[1] in rows:
            raise EnforcementRefusal("PACKET_CORRUPT", "sha256sums_shape")
        rows[parts[1]] = parts[0]
    if set(rows) != PACKET_FILES - {CHECKSUM_NAME}:
        raise EnforcementRefusal("PACKET_CORRUPT", "sha256sums_set")
    for name, expected in rows.items():
        if digest((packet_root / name).read_bytes()) != expected:
            raise EnforcementRefusal("PACKET_WRONG_BUNDLE", f"sha256sums:{name}")
    return rows


def load_signed_object(raw: bytes, public: Ed25519PublicKey, label: str) -> tuple[dict, str]:
    value = _object(raw, "PACKET_CORRUPT", label)
    signature = value.get("signature")
    payload = {key: item for key, item in value.items() if key != "signature"}
    verify_signature(public, payload, signature)
    return payload, digest(raw)


def verify_packet(packet_root: Path, *, now: datetime | None = None) -> dict[str, Any]:
    checksums = verify_checksums(packet_root)
    public_raw = (packet_root / PUBLIC_KEY_NAME).read_bytes()
    public = load_public_key(public_raw)
    revocations_raw = (packet_root / REVOCATION_NAME).read_bytes()
    revocations, revocations_digest = load_signed_object(
        revocations_raw, public, "revocations"
    )
    packet_raw = (packet_root / PACKET_NAME).read_bytes()
    packet, packet_digest = load_signed_object(packet_raw, public, "packet")

    required_packet_fields = {
        "schema_version", "purpose", "state", "authority_generation",
        "packet_version", "issuer", "issuer_mode", "protected_default_repository",
        "protected_default_ref", "protected_default_commit", "source_manifest_digest",
        "subject_digest", "issued_at", "not_before", "publishing_capability_scope",
        "required_surfaces", "revocation_list_digest", "trusted_key_id",
    }
    if set(packet) != required_packet_fields:
        raise EnforcementRefusal("PACKET_CORRUPT", "packet_fields")
    if (
        packet.get("schema_version") != PACKET_SCHEMA
        or packet.get("purpose") != PURPOSE
        or packet.get("state") != "ENFORCING"
        or packet.get("issuer_mode") != ISSUER_MODE
        or packet.get("protected_default_ref") not in {"refs/heads/main", "refs/heads/master"}
        or not _hex40(packet.get("protected_default_commit"))
        or not _sha(packet.get("source_manifest_digest"))
        or not _sha(packet.get("subject_digest"))
        or packet.get("revocation_list_digest") != revocations_digest
        or packet.get("trusted_key_id") != f"rea-nonexpiring-ed25519-{digest(public_raw)[:16]}"
    ):
        raise EnforcementRefusal("PACKET_CORRUPT", "packet_binding")
    if isinstance(packet.get("authority_generation"), bool) or not isinstance(
        packet.get("authority_generation"), int
    ) or packet["authority_generation"] < 1:
        raise EnforcementRefusal("PACKET_CORRUPT", "authority_generation")
    if not isinstance(packet.get("packet_version"), str) or not packet["packet_version"]:
        raise EnforcementRefusal("PACKET_CORRUPT", "packet_version")
    if not isinstance(packet.get("publishing_capability_scope"), list) or not all(
        isinstance(item, str) and item for item in packet["publishing_capability_scope"]
    ):
        raise EnforcementRefusal("PACKET_CORRUPT", "publishing_capability_scope")
    surfaces = packet.get("required_surfaces")
    if not isinstance(surfaces, list) or set(surfaces) != SURFACES:
        raise EnforcementRefusal("PACKET_CORRUPT", "required_surfaces")
    issued = _instant(packet.get("issued_at"), "issued_at")
    not_before = _instant(packet.get("not_before"), "not_before")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if issued > current or not_before > current:
        raise EnforcementRefusal("PACKET_NOT_YET_VALID", packet["not_before"])

    required_revocation_fields = {
        "schema_version", "issuer", "issued_at", "protected_default_commit",
        "revoked_packet_digests", "revoked_packet_versions",
    }
    if (
        set(revocations) != required_revocation_fields
        or revocations.get("schema_version") != REVOCATION_SCHEMA
        or not _hex40(revocations.get("protected_default_commit"))
        or not isinstance(revocations.get("revoked_packet_digests"), list)
        or not isinstance(revocations.get("revoked_packet_versions"), list)
        or not all(_sha(item) for item in revocations["revoked_packet_digests"])
        or not all(isinstance(item, str) and item for item in revocations["revoked_packet_versions"])
    ):
        raise EnforcementRefusal("REVOCATION_LIST_CORRUPT", "shape")
    _instant(revocations.get("issued_at"), "revocations.issued_at")
    if (
        packet_digest in revocations["revoked_packet_digests"]
        or packet["packet_version"] in revocations["revoked_packet_versions"]
    ):
        raise EnforcementRefusal("PACKET_REVOKED", packet["packet_version"])

    return {
        "schema_version": VERIFY_REPORT_SCHEMA,
        "verdict": "PASS",
        "state": "ENFORCING",
        "manual_activation_required": False,
        "expires_at": None,
        "packet_digest": packet_digest,
        "packet_version": packet["packet_version"],
        "revocation_list_digest": revocations_digest,
        "protected_default_commit": packet["protected_default_commit"],
        "issuer_mode": packet["issuer_mode"],
        "checksums": checksums,
    }


def atomic_copy_packet(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    backup = destination.parent / f".{destination.name}.previous"
    try:
        for name in PACKET_FILES:
            shutil.copy2(source / name, temporary / name)
        if backup.exists():
            shutil.rmtree(backup)
        if destination.exists():
            os.replace(destination, backup)
        os.replace(temporary, destination)
        if backup.exists():
            shutil.rmtree(backup)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        if backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise


def reconcile(source: Path, state_root: Path, *, now: datetime | None = None) -> dict[str, Any]:
    current = state_root / "current"
    alerts = state_root / "alerts"
    alerts.mkdir(parents=True, exist_ok=True)
    try:
        candidate = verify_packet(source, now=now)
    except EnforcementRefusal as exc:
        if current.is_dir():
            last = verify_packet(current, now=now)
            alert = {
                "schema_version": "rea.write.non-expiring-enforcement.alert.v1",
                "reason_code": exc.reason_code,
                "detail": exc.detail,
                "kept_packet_digest": last["packet_digest"],
            }
            (alerts / "last_failure.json").write_bytes(canonical(alert) + b"\n")
            return {
                "schema_version": RECONCILE_REPORT_SCHEMA,
                "verdict": "KEPT_LAST_VERIFIED",
                "installed": False,
                "reason_code": exc.reason_code,
                "current_packet_digest": last["packet_digest"],
            }
        raise
    atomic_copy_packet(source, current)
    return {
        "schema_version": RECONCILE_REPORT_SCHEMA,
        "verdict": "INSTALLED",
        "installed": True,
        "current_packet_digest": candidate["packet_digest"],
        "packet_version": candidate["packet_version"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--packet-root", required=True, type=Path)
    reconcile_parser = sub.add_parser("reconcile")
    reconcile_parser.add_argument("--source", required=True, type=Path)
    reconcile_parser.add_argument("--state-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            report = verify_packet(args.packet_root)
        else:
            report = reconcile(args.source, args.state_root)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except EnforcementRefusal as exc:
        report = {
            "schema_version": VERIFY_REPORT_SCHEMA,
            "verdict": "REFUSE",
            "reason_code": exc.reason_code,
            "detail": exc.detail,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
