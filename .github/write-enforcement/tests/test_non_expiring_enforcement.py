import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


TARGET = Path(__file__).resolve().parents[1] / "non_expiring_enforcement.py"
SPEC = importlib.util.spec_from_file_location("non_expiring_enforcement", TARGET)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


NOW = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)


def _public(private):
    return private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _write_packet(root, private, *, version="v1", revoked_digests=None,
                  revoked_versions=None, subject_digest=None):
    public = _public(private)
    revocation_payload = {
        "schema_version": MODULE.REVOCATION_SCHEMA,
        "issuer": "rexcoleman.dev protected default",
        "issued_at": "2026-09-30T11:59:00Z",
        "protected_default_commit": "a" * 40,
        "revoked_packet_digests": revoked_digests or [],
        "revoked_packet_versions": revoked_versions or [],
    }
    revocations = MODULE.sign_payload(revocation_payload, private)
    revocation_raw = MODULE.canonical(revocations) + b"\n"
    packet_payload = {
        "schema_version": MODULE.PACKET_SCHEMA,
        "purpose": MODULE.PURPOSE,
        "state": "ENFORCING",
        "authority_generation": 5,
        "packet_version": version,
        "issuer": "rexcoleman.dev protected default",
        "issuer_mode": MODULE.ISSUER_MODE,
        "protected_default_repository": "rexcoleman/research_enforcement_activation",
        "protected_default_ref": "refs/heads/master",
        "protected_default_commit": "b" * 40,
        "source_manifest_digest": "c" * 64,
        "subject_digest": subject_digest or "d" * 64,
        "issued_at": "2026-09-30T11:58:00Z",
        "not_before": "2026-09-30T11:58:00Z",
        "publishing_capability_scope": ["research"],
        "required_surfaces": ["blog", "distribution", "publication", "report"],
        "revocation_list_digest": MODULE.digest(revocation_raw),
        "trusted_key_id": f"rea-nonexpiring-ed25519-{MODULE.digest(public)[:16]}",
    }
    packet = MODULE.sign_payload(packet_payload, private)
    packet_raw = MODULE.canonical(packet) + b"\n"
    root.mkdir(parents=True, exist_ok=True)
    payloads = {
        MODULE.PACKET_NAME: packet_raw,
        MODULE.REVOCATION_NAME: revocation_raw,
        MODULE.PUBLIC_KEY_NAME: public,
    }
    for name, raw in payloads.items():
        (root / name).write_bytes(raw)
    (root / MODULE.CHECKSUM_NAME).write_text(
        "".join(
            f"{MODULE.digest((root / name).read_bytes())}  {name}\n"
            for name in sorted(payloads)
        ),
        encoding="ascii",
    )
    return MODULE.digest(packet_raw)


def _anchor(root, private):
    path = root / "trusted.pem"
    path.write_bytes(_public(private))
    return path


def test_non_expiring_packet_verifies_offline_and_has_no_expiry(tmp_path):
    private = Ed25519PrivateKey.generate()
    trusted = _anchor(tmp_path, private)
    _write_packet(tmp_path / "packet", private)
    report = MODULE.verify_packet(
        tmp_path / "packet", trusted_public_key=trusted, now=NOW
    )
    assert report["verdict"] == "PASS"
    assert report["expires_at"] is None
    assert report["manual_activation_required"] is False
    assert report["issuer_mode"] == MODULE.ISSUER_MODE


def test_tampered_packet_bytes_refuse_before_admission(tmp_path):
    private = Ed25519PrivateKey.generate()
    trusted = _anchor(tmp_path, private)
    packet = tmp_path / "packet"
    _write_packet(packet, private)
    path = packet / MODULE.PACKET_NAME
    path.write_bytes(path.read_bytes().replace(b'"state":"ENFORCING"', b'"state":"DISABLED"'))
    with pytest.raises(MODULE.EnforcementRefusal) as captured:
        MODULE.verify_packet(packet, trusted_public_key=trusted, now=NOW)
    assert captured.value.reason_code == "PACKET_WRONG_BUNDLE"


def test_foreign_resigned_packet_refuses_against_birth_pinned_anchor(tmp_path):
    trusted_private = Ed25519PrivateKey.generate()
    foreign_private = Ed25519PrivateKey.generate()
    trusted = _anchor(tmp_path, trusted_private)
    _write_packet(tmp_path / "packet", foreign_private)
    with pytest.raises(MODULE.EnforcementRefusal) as captured:
        MODULE.verify_packet(
            tmp_path / "packet", trusted_public_key=trusted, now=NOW
        )
    assert captured.value.reason_code == "TRUST_ROOT_MISMATCH"


def test_signed_revocation_list_refuses_named_version(tmp_path):
    private = Ed25519PrivateKey.generate()
    trusted = _anchor(tmp_path, private)
    revoked_by_version = tmp_path / "revoked-by-version"
    _write_packet(revoked_by_version, private, version="v9", revoked_versions=["v9"])
    with pytest.raises(MODULE.EnforcementRefusal) as captured:
        MODULE.verify_packet(revoked_by_version, trusted_public_key=trusted, now=NOW)
    assert captured.value.reason_code == "PACKET_REVOKED"


def test_reconciler_installs_new_version_and_keeps_last_verified_on_bad_candidate(tmp_path):
    private = Ed25519PrivateKey.generate()
    trusted = _anchor(tmp_path, private)
    source_v1 = tmp_path / "source-v1"
    source_v2 = tmp_path / "source-v2"
    bad = tmp_path / "bad"
    state = tmp_path / "state"
    _write_packet(source_v1, private, version="v1", subject_digest="1" * 64)
    _write_packet(source_v2, private, version="v2", subject_digest="2" * 64)
    _write_packet(bad, private, version="v3", subject_digest="3" * 64)
    (bad / MODULE.PACKET_NAME).write_bytes(b'{"tampered":true}\n')

    first = MODULE.reconcile(source_v1, state, trusted_public_key=trusted, now=NOW)
    second = MODULE.reconcile(source_v2, state, trusted_public_key=trusted, now=NOW)
    kept = MODULE.reconcile(bad, state, trusted_public_key=trusted, now=NOW)

    assert first["verdict"] == "INSTALLED"
    assert second["verdict"] == "INSTALLED"
    assert second["packet_version"] == "v2"
    assert kept["verdict"] == "KEPT_LAST_VERIFIED"
    assert kept["current_packet_digest"] == second["current_packet_digest"]
    assert (state / "alerts" / "last_failure.json").is_file()


def test_issue_command_writes_verifiable_non_expiring_packet(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tracked.txt").write_text("protected bytes\n", encoding="utf-8")
    import subprocess
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True)

    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    trusted = _anchor(tmp_path, private)
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"member":"bytes"}\n', encoding="utf-8")
    output = tmp_path / "packet"

    report = MODULE.issue_packet(
        repo_root=repo,
        source_manifest=manifest,
        private_key=private_path,
        trusted_public_key=trusted,
        output=output,
        repository="rexcoleman/rexcoleman.dev",
        ref="refs/heads/main",
        packet_version="test-version",
        scope=["research"],
        now=NOW,
    )

    assert report["verdict"] == "ISSUED"
    verified = MODULE.verify_packet(output, trusted_public_key=trusted, now=NOW)
    assert verified["packet_version"] == "test-version"
    assert verified["expires_at"] is None
