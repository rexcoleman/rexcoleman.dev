#!/usr/bin/env python3
"""Seal the protected bundle token for a bound downstream GitHub key.

The ``seal`` command runs only inside the protected issuer environment.  It
validates exact Git reads at all five frozen commits, encrypts the existing
bundle token with libsodium ``crypto_box_seal``, and emits a strict packet that
contains ciphertext and binding metadata only.  It never writes a repository
secret and never needs a secrets-write credential.

The ``verify`` command authenticates a packet against exact workflow, manifest,
key, and ciphertext identities.  It is used both before local submission and
again by the issuing workflow.  Every refusal is typed and exits 3.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict


REFUSAL_EXIT = 3
SOURCE_TOKEN_ABSENT = "SOURCE_TOKEN_ABSENT"
MANIFEST_REFUSED = "MANIFEST_REFUSED"
GIT_READ_REFUSED = "GIT_READ_REFUSED"
KEY_BINDING_REFUSED = "KEY_BINDING_REFUSED"
SODIUM_REFUSED = "SODIUM_REFUSED"
PACKET_REFUSED = "PACKET_REFUSED"

SOURCE_ENV = "REA_BUNDLE_READ_TOKEN"
TARGET_REPOSITORY = "rexcoleman/research_enforcement_activation"
SECRET_NAME = "REA_BUNDLE_READ_TOKEN"
PACKET_SCHEMA = "rea.write.sealed-bundle-secret.v1"
SEALED_OVERHEAD = 48
LOGICAL_REPOSITORIES = {
    "research_enforcement_activation": "rexcoleman/research_enforcement_activation",
    "govML": "rexcoleman/govML",
    "Moonshots_Career_Thesis_v2": "rexcoleman/Moonshots_Career_Thesis",
    "newsletter": "rexcoleman/newsletter",
    "rexcoleman.dev": "rexcoleman/rexcoleman.dev",
}
PACKET_KEYS = {
    "schema_version", "target_repository", "secret_name", "key_id",
    "public_key_sha256", "ciphertext_b64", "ciphertext_sha256",
    "manifest_digest", "manifest_file_sha256", "workflow_run_id",
    "workflow_ref", "workflow_sha", "source_commits",
}


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def lower_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(char in "0123456789abcdef" for char in value))


def api(token: str, path: str):
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "rea-protected-sealed-bundle-transfer",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        status = getattr(exc, "code", type(exc).__name__)
        raise Refusal(GIT_READ_REFUSED, "status=%s path=%s" % (status, path)) from None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal(GIT_READ_REFUSED, "malformed_json path=%s" % path) from None


def load_manifest(path: Path):
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise Refusal(MANIFEST_REFUSED, type(exc).__name__) from None
    rows = value.get("members") if isinstance(value, dict) else None
    digest = value.get("manifest_digest") if isinstance(value, dict) else None
    unsigned = dict(value) if isinstance(value, dict) else {}
    unsigned.pop("manifest_digest", None)
    calculated = hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    if not isinstance(rows, list) or not rows or digest != calculated:
        raise Refusal(MANIFEST_REFUSED, "shape_or_digest")
    commits: Dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise Refusal(MANIFEST_REFUSED, "member_shape")
        logical, commit = row.get("repository"), row.get("commit")
        if logical not in LOGICAL_REPOSITORIES or not lower_hex(commit, 40):
            raise Refusal(MANIFEST_REFUSED, "member_identity")
        if logical in commits and commits[logical] != commit:
            raise Refusal(MANIFEST_REFUSED, "commit_ambiguous repository=%s" % logical)
        commits[logical] = commit
    if set(commits) != set(LOGICAL_REPOSITORIES):
        raise Refusal(MANIFEST_REFUSED, "repository_set")
    return raw, digest, commits


def validate_source_reads(token: str, commits: Dict[str, str]) -> None:
    for logical, repository in LOGICAL_REPOSITORIES.items():
        commit = commits[logical]
        try:
            value = api(token, "/repos/%s/git/commits/%s" % (repository, commit))
        except Refusal as exc:
            raise Refusal(GIT_READ_REFUSED, "repository=%s %s" % (
                repository, exc.detail,
            )) from None
        if (not isinstance(value, dict) or value.get("sha") != commit
                or not lower_hex(value.get("tree", {}).get("sha"), 40)):
            raise Refusal(GIT_READ_REFUSED, "repository=%s identity" % repository)


def decode_key(value: str, expected_sha256: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        raise Refusal(KEY_BINDING_REFUSED, "public_key_base64") from None
    if len(raw) != 32 or not lower_hex(expected_sha256, 64):
        raise Refusal(KEY_BINDING_REFUSED, "public_key_shape")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise Refusal(KEY_BINDING_REFUSED, "public_key_digest")
    return raw


def sodium_library():
    name = ctypes.util.find_library("sodium")
    if not name:
        raise Refusal(SODIUM_REFUSED, "library_absent")
    try:
        library = ctypes.cdll.LoadLibrary(name)
        if library.sodium_init() < 0:
            raise Refusal(SODIUM_REFUSED, "initialization")
        library.crypto_box_seal.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
        ]
        library.crypto_box_seal.restype = ctypes.c_int
        return library
    except (AttributeError, OSError):
        raise Refusal(SODIUM_REFUSED, "interface") from None


def seal_bytes(message: bytes, public_key: bytes) -> bytes:
    if not message:
        raise Refusal(SOURCE_TOKEN_ABSENT, SOURCE_ENV)
    output = ctypes.create_string_buffer(len(message) + SEALED_OVERHEAD)
    source = ctypes.create_string_buffer(message, len(message))
    key = ctypes.create_string_buffer(public_key, len(public_key))
    if sodium_library().crypto_box_seal(output, source, len(message), key) != 0:
        raise Refusal(SODIUM_REFUSED, "seal")
    return output.raw


def workflow_identity(environ):
    run_id = environ.get("GITHUB_RUN_ID", "")
    ref = environ.get("GITHUB_REF", "")
    sha = environ.get("GITHUB_SHA", "")
    if (not re.fullmatch(r"[1-9][0-9]*", run_id)
            or not ref.startswith("refs/tags/rea-wea-generation-5-")
            or not lower_hex(sha, 40)):
        raise Refusal(PACKET_REFUSED, "workflow_identity")
    return int(run_id), ref, sha


def canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8") + b"\n"


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.tmp.%s" % (path.name, os.getpid()))
    try:
        with temporary.open("xb") as handle:
            os.chmod(temporary, 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def seal(args, environ) -> int:
    token = environ.get(SOURCE_ENV, "") or ""
    if not token.strip():
        raise Refusal(SOURCE_TOKEN_ABSENT, SOURCE_ENV)
    if not isinstance(args.key_id, str) or not re.fullmatch(r"[0-9]+", args.key_id):
        raise Refusal(KEY_BINDING_REFUSED, "key_id")
    manifest_raw, manifest_digest, commits = load_manifest(args.manifest)
    public_key = decode_key(args.public_key_b64, args.public_key_sha256)
    validate_source_reads(token, commits)
    run_id, workflow_ref, workflow_sha = workflow_identity(environ)
    ciphertext = seal_bytes(token.encode("utf-8"), public_key)
    packet = {
        "schema_version": PACKET_SCHEMA,
        "target_repository": TARGET_REPOSITORY,
        "secret_name": SECRET_NAME,
        "key_id": args.key_id,
        "public_key_sha256": args.public_key_sha256,
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "manifest_digest": manifest_digest,
        "manifest_file_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "workflow_run_id": run_id,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
        "source_commits": commits,
    }
    atomic_write(args.output, canonical(packet))
    print("SEALED_BUNDLE_TRANSFER_PASS repositories=5 run_id=%s key_id=%s "
          "ciphertext_sha256=%s secret_bytes_printed=false" % (
              run_id, args.key_id, packet["ciphertext_sha256"],
          ))
    return 0


def load_packet(path: Path):
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise Refusal(PACKET_REFUSED, type(exc).__name__) from None
    if not isinstance(value, dict) or set(value) != PACKET_KEYS:
        raise Refusal(PACKET_REFUSED, "shape")
    try:
        ciphertext = base64.b64decode(value["ciphertext_b64"], validate=True)
    except (TypeError, ValueError):
        raise Refusal(PACKET_REFUSED, "ciphertext_base64") from None
    if (len(ciphertext) <= SEALED_OVERHEAD
            or hashlib.sha256(ciphertext).hexdigest() != value["ciphertext_sha256"]):
        raise Refusal(PACKET_REFUSED, "ciphertext_digest")
    return value


def verify(args) -> int:
    value = load_packet(args.packet)
    _raw, manifest_digest, commits = load_manifest(args.manifest)
    checks = {
        "schema_version": PACKET_SCHEMA,
        "target_repository": TARGET_REPOSITORY,
        "secret_name": SECRET_NAME,
        "key_id": args.key_id,
        "public_key_sha256": args.public_key_sha256,
        "ciphertext_sha256": args.ciphertext_sha256,
        "manifest_digest": manifest_digest,
        "manifest_file_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "workflow_run_id": args.run_id,
        "workflow_ref": args.workflow_ref,
        "workflow_sha": args.workflow_sha,
        "source_commits": commits,
    }
    if any(value.get(key) != expected for key, expected in checks.items()):
        raise Refusal(PACKET_REFUSED, "identity")
    print("SEALED_BUNDLE_PACKET_VERIFIED run_id=%s key_id=%s "
          "ciphertext_sha256=%s secret_bytes_printed=false" % (
              args.run_id, args.key_id, args.ciphertext_sha256,
          ))
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    seal_parser = commands.add_parser("seal")
    seal_parser.add_argument("--manifest", type=Path, required=True)
    seal_parser.add_argument("--key-id", required=True)
    seal_parser.add_argument("--public-key-b64", required=True)
    seal_parser.add_argument("--public-key-sha256", required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--packet", type=Path, required=True)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--key-id", required=True)
    verify_parser.add_argument("--public-key-sha256", required=True)
    verify_parser.add_argument("--ciphertext-sha256", required=True)
    verify_parser.add_argument("--run-id", type=int, required=True)
    verify_parser.add_argument("--workflow-ref", required=True)
    verify_parser.add_argument("--workflow-sha", required=True)
    return value


def main(argv=None, environ=None) -> int:
    args = parser().parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        return seal(args, environ) \
            if args.command == "seal" else verify(args)
    except Refusal as exc:
        detail = exc.detail
        secret = environ.get(SOURCE_ENV, "") or ""
        if secret:
            detail = detail.replace(secret, "***")
        print("REFUSED %s: %s" % (exc.code, detail), file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT
    except Exception as exc:
        print("REFUSED UNEXPECTED_%s" % type(exc).__name__, file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
