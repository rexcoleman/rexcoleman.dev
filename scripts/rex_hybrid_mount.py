#!/usr/bin/env python3
"""Fixed C1 hybrid effects for rexcoleman.dev.

The public entry points accept final bytes plus closed JSON effect plans.
They never accept callbacks, commands, authority paths, destinations, or
caller-selected sinks.  Production authority is obtained from the fixed C1
provider only after the route lock and exact prestate have been established.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


INSTALLED_VERIFY_ONLY_PROVIDER = (
    Path.home()
    / ".local/libexec/rea_enforcement/hybrid_capability_provider"
)
CANONICAL_REPO = Path("/home/azureuser/rexcoleman.dev")
CANONICAL_STATE = Path("/home/azureuser/.local/state/rea_enforcement")
REPOSITORY = "rexcoleman/rexcoleman.dev"
ORIGIN = "https://github.com/rexcoleman/rexcoleman.dev.git"
REFUSAL_EXIT = 3
PLAN_SCHEMA = "rea.c3.rex.closed-effect-plan.v1"
BUNDLE_SCHEMA = "rea.c3.rex.exact-byte-bundle.v1"
LOCAL_EFFECT_SCHEMA = "rea.c3.rex.local-effect-evidence.v1"
MANIFEST_SCHEMA = "rea.c3.rex.hybrid-subject-manifest.v1"
RELEASE_SCHEMA = "rea.c3.rex.release-subject.v1"
EFFECT_SCHEMA = "rea.c3.rex.route-effect.v1"
DEPLOY_RECEIPT_SCHEMA = "rea.c3.rex.deploy-receipt.v1"
TRANSPORT_SCHEMA = "rea.c3.rex.authorization-transport.v1"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_BRANCH = re.compile(r"^(?:codex|feature|fix)/[A-Za-z0-9._/-]+$")


class RexHybridRefusal(RuntimeError):
    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        self.raw_exit = REFUSAL_EXIT
        super().__init__(f"REFUSE({reason_code}): {detail}")


@dataclass(frozen=True)
class RexHybridContext:
    repo_root: Path
    state_root: Path
    base_context: Any
    production: bool = True
    fixture_root: Path | None = None

    @classmethod
    def canonical(cls) -> "RexHybridContext":
        return cls(
            repo_root=CANONICAL_REPO,
            state_root=CANONICAL_STATE / "rex-c3",
            base_context=None,
            production=True,
            fixture_root=None,
        )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise RexHybridRefusal("EFFECT_PLAN_INVALID", "not_json") from None


def _closed_plan(
    route_id: str, operation: str, parameters: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": PLAN_SCHEMA,
        "route_id": route_id,
        "operation": operation,
        "parameters": parameters,
    }


def build_bundle(route_id: str, slug: str, members: list[tuple[str, bytes]]) -> bytes:
    """Construct canonical data-only final bytes for a route-owned caller."""
    if route_id not in {"BLG-08", "DST-02"} or not _SLUG.fullmatch(slug):
        raise RexHybridRefusal("EFFECT_PLAN_INVALID", f"{route_id}:slug")
    encoded = []
    for relative_path, raw in members:
        if not isinstance(raw, bytes):
            raise RexHybridRefusal("FINAL_BYTES_UNAVAILABLE", relative_path)
        relative_path = _safe_relative(relative_path)
        if relative_path.startswith(".rea/"):
            raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", relative_path)
        encoded.append(
            {
                "path": relative_path,
                "byte_length": len(raw),
                "sha256": _sha256(raw),
                "content_b64": base64.b64encode(raw).decode("ascii"),
            }
        )
    encoded.sort(key=lambda row: row["path"])
    if len({row["path"] for row in encoded}) != len(encoded):
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "duplicate_member")
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "route_id": route_id,
        "repository": REPOSITORY,
        "slug": slug,
        "members": [
            {
                "path": row["path"],
                "byte_length": row["byte_length"],
                "sha256": row["sha256"],
            }
            for row in encoded
        ],
    }
    manifest_raw = _canonical(manifest) + b"\n"
    manifest_id = _sha256(manifest_raw)
    encoded.append(
        {
            "path": (
                f".rea/c3/hybrid-subject-manifests/"
                f"{route_id.lower()}-{manifest_id}.json"
            ),
            "byte_length": len(manifest_raw),
            "sha256": manifest_id,
            "content_b64": base64.b64encode(manifest_raw).decode("ascii"),
        }
    )
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "route_id": route_id,
        "slug": slug,
        "members": sorted(encoded, key=lambda row: row["path"]),
    }
    raw = _canonical(value)
    _decode_bundle(route_id, raw)
    return raw


def _safe_relative(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise RexHybridRefusal("EFFECT_PLAN_INVALID", "member_path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise RexHybridRefusal("EFFECT_PLAN_INVALID", "member_path")
    normalized = path.as_posix()
    if normalized != value:
        raise RexHybridRefusal("EFFECT_PLAN_INVALID", "member_path")
    return normalized


def _allowed_member(route_id: str, slug: str, relative: str) -> bool:
    if relative.startswith(f".rea/c3/hybrid-subject-manifests/{route_id.lower()}-"):
        return relative.endswith(".json")
    if route_id == "BLG-08":
        return relative == f"content/posts/{slug}.md" or (
            relative.startswith(f"static/images/{slug}/")
            and len(PurePosixPath(relative).parts) >= 4
        )
    suffixes = {
        f"cross-posts/{slug}_devto.md",
        f"cross-posts/{slug}_linkedin.txt",
        f"cross-posts/{slug}_reddit.md",
    }
    return relative in suffixes


def _decode_bundle(route_id: str, candidate: bytes) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(candidate, bytes) or not candidate:
        raise RexHybridRefusal("FINAL_BYTES_UNAVAILABLE", route_id)
    try:
        value = json.loads(candidate)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "bundle_json") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "route_id", "slug", "members"}
        or value.get("schema_version") != BUNDLE_SCHEMA
        or value.get("route_id") != route_id
        or not isinstance(value.get("slug"), str)
        or not _SLUG.fullmatch(value["slug"])
        or not isinstance(value.get("members"), list)
        or _canonical(value) != candidate
    ):
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "bundle_shape")
    slug = value["slug"]
    members: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in value["members"]:
        if not isinstance(row, dict) or set(row) != {
            "path", "byte_length", "sha256", "content_b64"
        }:
            raise RexHybridRefusal("FINAL_BYTES_INVALID", "member_shape")
        relative = _safe_relative(row["path"])
        if relative in seen or not _allowed_member(route_id, slug, relative):
            raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", relative)
        try:
            raw = base64.b64decode(row["content_b64"], validate=True)
        except (ValueError, TypeError):
            raise RexHybridRefusal("FINAL_BYTES_INVALID", f"{relative}:base64") from None
        if (
            not isinstance(row["byte_length"], int)
            or isinstance(row["byte_length"], bool)
            or row["byte_length"] != len(raw)
            or row["sha256"] != _sha256(raw)
        ):
            raise RexHybridRefusal("FINAL_BYTES_INVALID", f"{relative}:digest")
        seen.add(relative)
        members.append({"path": relative, "raw": raw, "sha256": row["sha256"]})
    manifests = [
        row for row in members
        if row["path"].startswith(".rea/c3/hybrid-subject-manifests/")
    ]
    artifacts = [row for row in members if row not in manifests]
    expected_count = 3 if route_id == "DST-02" else None
    if (
        len(manifests) != 1
        or not artifacts
        or (expected_count is not None and len(artifacts) != expected_count)
    ):
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "member_count")
    if route_id == "BLG-08" and f"content/posts/{slug}.md" not in {
        row["path"] for row in artifacts
    }:
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "post_missing")
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "route_id": route_id,
        "repository": REPOSITORY,
        "slug": slug,
        "members": [
            {
                "path": row["path"],
                "byte_length": len(row["raw"]),
                "sha256": row["sha256"],
            }
            for row in sorted(artifacts, key=lambda item: item["path"])
        ],
    }
    manifest_raw = _canonical(manifest) + b"\n"
    expected_manifest_path = (
        f".rea/c3/hybrid-subject-manifests/"
        f"{route_id.lower()}-{_sha256(manifest_raw)}.json"
    )
    if (
        manifests[0]["path"] != expected_manifest_path
        or manifests[0]["raw"] != manifest_raw
    ):
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "admission_manifest")
    return slug, members


def _target(route_id: str, slug: str, members: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "repository": REPOSITORY,
        "route_id": route_id,
        "slug": slug,
        "members": [
            {"path": row["path"], "sha256": row["sha256"], "byte_length": len(row["raw"])}
            for row in members
        ],
    }


def bundle_target(route_id: str, candidate: bytes) -> dict[str, Any]:
    slug, members = _decode_bundle(route_id, candidate)
    return _target(route_id, slug, members)


def bundle_plan(route_id: str, candidate: bytes) -> dict[str, Any]:
    slug, _members = _decode_bundle(route_id, candidate)
    return _closed_plan(route_id, "atomic_write_bundle", {"slug": slug})


def _validate_plan(
    route_id: str, effect_plan: dict[str, Any], slug: str
) -> str:
    if (
        not isinstance(effect_plan, dict)
        or set(effect_plan) != {"schema_version", "route_id", "operation", "parameters"}
        or effect_plan.get("schema_version") != PLAN_SCHEMA
        or effect_plan.get("route_id") != route_id
        or not isinstance(effect_plan.get("parameters"), dict)
    ):
        raise RexHybridRefusal("EFFECT_PLAN_INVALID", route_id)
    expected_operation = {
        "BLG-08": "atomic_write_bundle",
        "DST-02": "atomic_write_bundle",
        "BLG-09": "push_pr_branch",
        "BLG-10": "dispatch_deploy",
    }.get(route_id)
    if effect_plan.get("operation") != expected_operation:
        raise RexHybridRefusal("EFFECT_PLAN_INVALID", f"{route_id}:operation")
    if route_id in {"BLG-08", "DST-02"}:
        if effect_plan["parameters"] != {"slug": slug}:
            raise RexHybridRefusal("EFFECT_PLAN_INVALID", f"{route_id}:parameters")
    return _sha256(_canonical(effect_plan))


def _require_context(context: RexHybridContext) -> None:
    root = context.repo_root.absolute()
    if context.production:
        if root != CANONICAL_REPO:
            raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(root))
    else:
        if context.fixture_root is None:
            raise RexHybridRefusal("FIXTURE_ROOT_REQUIRED", str(root))
        fixture = context.fixture_root.absolute()
        if root != fixture and fixture not in root.parents:
            raise RexHybridRefusal("FIXTURE_SEPARATION_REFUSED", str(root))
        if root == CANONICAL_REPO or CANONICAL_REPO in root.parents:
            raise RexHybridRefusal("FIXTURE_SEPARATION_REFUSED", str(root))


def _regular_or_absent(path: Path) -> bytes | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(path))
    return path.read_bytes()


def _safe_parent(repo_root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(repo_root)
    except ValueError:
        raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(path)) from None
    current = repo_root
    if current.is_symlink() or not current.is_dir():
        raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(current))
    for part in relative.parts[:-1]:
        current = current / part
        if current.exists():
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(current))


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".rea-c3-rex-", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _preimage_digest(preimages: dict[str, bytes | None]) -> str:
    return _sha256(
        _canonical(
            [
                {
                    "path": path,
                    "state": "ABSENT" if raw is None else "PRESENT",
                    "sha256": None if raw is None else _sha256(raw),
                    "byte_length": None if raw is None else len(raw),
                }
                for path, raw in sorted(preimages.items())
            ]
        )
    )


class _RegistrySpendStore:
    """Durably spend one installed-provider decision before its effect."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise RexHybridRefusal("SPEND_STORE_INVALID", "symlink")
        self.path = path
        try:
            with sqlite3.connect(path, timeout=30) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS registry_verification_spends (
                        attempt_nonce TEXT PRIMARY KEY,
                        verification_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        postimage_sha256 TEXT,
                        effect_receipt_json TEXT,
                        failure_code TEXT
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                    registry_verification_spends_verification_id_unique
                    ON registry_verification_spends (verification_id)
                    """
                )
        except sqlite3.IntegrityError:
            raise RexHybridRefusal(
                "SPEND_STORE_MIGRATION_REFUSED", "duplicate_verification_id"
            ) from None
        except sqlite3.Error as exc:
            raise RexHybridRefusal(
                "SPEND_STORE_UNAVAILABLE", type(exc).__name__
            ) from None

    def reserve(self, decision: dict[str, Any]) -> dict[str, Any]:
        verification = decision.get("verification_id")
        if (
            not isinstance(verification, str)
            or not verification.startswith("registry-verification-")
        ):
            raise RexHybridRefusal(
                "CAPABILITY_RESPONSE_INVALID", "verification_id"
            )
        attempt = os.urandom(16).hex()
        try:
            with sqlite3.connect(self.path, timeout=30) as connection:
                connection.execute(
                    """
                    INSERT INTO registry_verification_spends
                    (attempt_nonce, verification_id, status)
                    VALUES (?, ?, 'RESERVED')
                    """,
                    (attempt, verification),
                )
        except sqlite3.IntegrityError:
            raise RexHybridRefusal(
                "CAPABILITY_ALREADY_SPENT", verification
            ) from None
        except sqlite3.Error as exc:
            raise RexHybridRefusal(
                "SPEND_STORE_UNAVAILABLE", type(exc).__name__
            ) from None
        return {
            **decision,
            "attempt_nonce": attempt,
            "capability_id": verification,
        }

    def record_outcome(
        self,
        attempt_nonce: str,
        *,
        status: str,
        postimage_sha256: str | None,
        effect_receipt: dict[str, Any] | None,
        failure_code: str | None = None,
    ) -> None:
        stored_status = (
            "EFFECT_COMMITTED"
            if status == "EFFECT_COMMITTED"
            else "EFFECT_FAILED"
        )
        stored_failure = (
            failure_code
            if stored_status == "EFFECT_COMMITTED"
            else f"{status}:{failure_code or 'unspecified'}"
        )
        receipt = (
            json.dumps(effect_receipt, sort_keys=True, separators=(",", ":"))
            if effect_receipt is not None
            else None
        )
        try:
            with sqlite3.connect(self.path, timeout=30) as connection:
                changed = connection.execute(
                    """
                    UPDATE registry_verification_spends
                    SET status=?, postimage_sha256=?, effect_receipt_json=?,
                        failure_code=?
                    WHERE attempt_nonce=? AND status='RESERVED'
                    """,
                    (
                        stored_status,
                        postimage_sha256,
                        receipt,
                        stored_failure,
                        attempt_nonce,
                    ),
                ).rowcount
                if changed != 1:
                    raise sqlite3.IntegrityError("outcome_transition")
        except sqlite3.Error as exc:
            raise RexHybridRefusal(
                "SPEND_STORE_UNAVAILABLE", type(exc).__name__
            ) from None


def _authority(
    *,
    context: RexHybridContext,
    route_id: str,
    candidate: bytes,
    destination: str,
    requested_effect: str,
    target: dict[str, Any],
    plan_sha256: str,
    preimage_sha256: str | None,
) -> tuple[Any, Any, Any, Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    if (
        not INSTALLED_VERIFY_ONLY_PROVIDER.is_absolute()
        or not INSTALLED_VERIFY_ONLY_PROVIDER.is_file()
        or not os.access(INSTALLED_VERIFY_ONLY_PROVIDER, os.X_OK)
    ):
        raise RexHybridRefusal(
            "TRUSTED_CAPABILITY_ISSUER_UNAVAILABLE",
            "installed_verify_only_provider",
        )
    wea = {"provider_verified": True}
    request = {
        "schema_version": "rea.c3.hybrid.capability-request.v2",
        "route_id": route_id,
        "surface": "blog" if route_id.startswith("BLG-") else "distribution",
        "destination": destination,
        "requested_effect": requested_effect,
        "candidate_sha256": _sha256(candidate),
        "candidate_byte_length": len(candidate),
        "candidate_b64": base64.b64encode(candidate).decode("ascii"),
        "target_sha256": _sha256(_canonical(target)),
        "plan_sha256": plan_sha256,
        "preimage_sha256": preimage_sha256,
        "wea": wea,
    }
    try:
        completed = subprocess.run(
            [str(INSTALLED_VERIFY_ONLY_PROVIDER)],
            input=_canonical(request),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RexHybridRefusal(
            "TRUSTED_CAPABILITY_ISSUER_UNAVAILABLE", type(exc).__name__
        ) from None
    if completed.returncode != 0:
        try:
            refusal = json.loads(completed.stderr)
        except (UnicodeDecodeError, json.JSONDecodeError):
            refusal = {}
        raise RexHybridRefusal(
            refusal.get(
                "reason_code", "TRUSTED_CAPABILITY_ISSUER_UNAVAILABLE"
            ),
            refusal.get("detail", f"raw_exit={completed.returncode}"),
        )
    try:
        response = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RexHybridRefusal(
            "CAPABILITY_RESPONSE_INVALID", "not_json"
        ) from None
    binding_keys = {
        "route_id",
        "surface",
        "destination",
        "requested_effect",
        "candidate_sha256",
        "candidate_byte_length",
        "target_sha256",
        "plan_sha256",
        "preimage_sha256",
        "wea",
    }
    decision = response.get("decision") if isinstance(response, dict) else None
    binding = decision.get("request_binding") if isinstance(decision, dict) else None
    if (
        not isinstance(response, dict)
        or set(response) != {"schema_version", "authorization", "decision"}
        or response.get("schema_version")
        != "rea.write.registry-verification-response.v1"
        or not isinstance(response.get("authorization"), dict)
        or not isinstance(decision, dict)
        or decision.get("verdict") != "ADMIT"
        or not isinstance(binding, dict)
        or set(binding) != binding_keys
        or any(binding.get(key) != request.get(key) for key in binding_keys)
    ):
        raise RexHybridRefusal(
            "CAPABILITY_RESPONSE_INVALID", "request_binding"
        )
    store = _RegistrySpendStore(context.state_root / "registry-spends.sqlite3")
    payload = store.reserve(decision)
    return (
        None,
        None,
        store,
        payload,
        response["authorization"],
        decision,
        request,
    )


def _restore_bundle(
    preimages: dict[Path, bytes | None],
    committed: dict[Path, bytes],
    expected_absent: set[Path],
    created_directories: set[Path],
) -> bool:
    for path, candidate in committed.items():
        try:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != candidate:
                return False
        except OSError:
            return False
    for path in expected_absent:
        if path.exists() or path.is_symlink():
            return False
    try:
        for path, before in preimages.items():
            if before is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, before)
        for directory in sorted(
            created_directories, key=lambda item: len(item.parts), reverse=True
        ):
            try:
                directory.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                return False
        for path, before in preimages.items():
            if before is None:
                if path.exists() or path.is_symlink():
                    return False
            elif (
                path.is_symlink()
                or not path.is_file()
                or path.read_bytes() != before
            ):
                return False
        return all(not directory.exists() for directory in created_directories)
    except OSError:
        return False


def _admission_path(
    context: RexHybridContext, route_id: str, candidate_sha256: str
) -> Path:
    return (
        context.state_root
        / "local-effect-evidence"
        / f"{route_id.lower()}-{candidate_sha256}.json"
    )


def _existing_image_paths(repo_root: Path, slug: str) -> set[Path]:
    root = repo_root / "static/images" / slug
    if not root.exists():
        return set()
    if root.is_symlink() or not root.is_dir():
        raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(root))
    result: set[Path] = set()
    for path in root.rglob("*"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(path))
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(path))
        result.add(path)
    return result


def _created_parents(repo_root: Path, paths: set[Path]) -> set[Path]:
    result: set[Path] = set()
    for path in paths:
        current = path.parent
        while current != repo_root:
            if not current.exists():
                result.add(current)
            current = current.parent
    return result


def _consume_bundle(
    *,
    route_id: str,
    candidate: bytes,
    effect_plan: dict[str, Any],
    target: dict[str, Any],
    context: RexHybridContext,
) -> dict[str, Any]:
    _require_context(context)
    slug, members = _decode_bundle(route_id, candidate)
    projected = _target(route_id, slug, members)
    if not isinstance(target, dict) or target != projected:
        raise RexHybridRefusal("PLAN_TARGET_MISMATCH", route_id)
    plan_sha256 = _validate_plan(route_id, effect_plan, slug)
    candidate_sha256 = _sha256(candidate)
    destination = (
        f"bundle://{REPOSITORY}/{route_id}/{slug}"
        f"#plan-sha256={plan_sha256}"
    )
    context.state_root.mkdir(parents=True, exist_ok=True)
    lock_path = context.state_root / "route-locks/rex-bundle.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        target_paths = {context.repo_root / row["path"] for row in members}
        stale_paths: set[Path] = set()
        if route_id == "BLG-08":
            expected_images = {
                path for path in target_paths
                if path.is_relative_to(context.repo_root / "static/images" / slug)
            }
            stale_paths = _existing_image_paths(context.repo_root, slug) - expected_images
        preimages: dict[Path, bytes | None] = {}
        committed: dict[Path, bytes] = {}
        expected_absent: set[Path] = set()
        created_directories = _created_parents(
            context.repo_root, target_paths
        )
        for row in members:
            path = context.repo_root / row["path"]
            _safe_parent(context.repo_root, path)
            preimages[path] = _regular_or_absent(path)
        for path in stale_paths:
            preimages[path] = _regular_or_absent(path)
        admission_path = _admission_path(context, route_id, candidate_sha256)
        admission_preimage = _regular_or_absent(admission_path)
        preimage_sha256 = _preimage_digest(
            {
                path.relative_to(context.repo_root).as_posix(): raw
                for path, raw in preimages.items()
            }
        )
        created_directories.update(
            _created_parents(context.state_root, {admission_path})
        )
        preimages[admission_path] = admission_preimage
        (
            _protocol,
            _spend_module,
            store,
            payload,
            capability,
            lineage,
            request,
        ) = _authority(
            context=context,
            route_id=route_id,
            candidate=candidate,
            destination=destination,
            requested_effect="atomic_write",
            target=projected,
            plan_sha256=plan_sha256,
            preimage_sha256=preimage_sha256,
        )
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        effect_result = {
            "outcome": "EXACT_BUNDLE_WRITTEN",
            "repository": REPOSITORY,
            "slug": slug,
            "members": projected["members"],
            "candidate_sha256": candidate_sha256,
            "candidate_byte_length": len(candidate),
            "preimage_sha256": preimage_sha256,
            "committed_at": now,
        }
        portable = {
            "schema_version": LOCAL_EFFECT_SCHEMA,
            "route_id": route_id,
            "repository": REPOSITORY,
            "candidate_sha256": candidate_sha256,
            "candidate_byte_length": len(candidate),
            "target": projected,
            "destination": destination,
            "requested_effect": "atomic_write",
            "plan_sha256": plan_sha256,
            "preimage_sha256": preimage_sha256,
            "wea": request["wea"],
            "attempt_nonce": payload["attempt_nonce"],
            "capability_id": payload["capability_id"],
            "capability": capability,
            "lineage": lineage,
            "effect_result": effect_result,
            "server_effect_established": False,
            "durable_spend_proof_included": False,
            "server_acceptance": "NOT_ESTABLISHED",
        }
        portable_raw = _canonical(portable) + b"\n"
        receipt = {
            "schema_version": EFFECT_SCHEMA,
            "verdict": "EFFECT_COMMITTED",
            **portable,
            "local_effect_evidence_path": str(admission_path),
            "local_effect_evidence_sha256": _sha256(portable_raw),
        }
        try:
            for path in stale_paths:
                path.unlink()
                expected_absent.add(path)
            for row in members:
                path = context.repo_root / row["path"]
                _atomic_write(path, row["raw"])
                committed[path] = row["raw"]
            _atomic_write(admission_path, portable_raw)
            committed[admission_path] = portable_raw
            for path, expected in committed.items():
                if path.is_symlink() or path.read_bytes() != expected:
                    raise RexHybridRefusal("PARTIAL_OR_EXTRA_EFFECT", str(path))
            if route_id == "BLG-08":
                observed_images = _existing_image_paths(context.repo_root, slug)
                expected_images = {
                    path for path in target_paths
                    if path.is_relative_to(context.repo_root / "static/images" / slug)
                }
                if observed_images != expected_images:
                    raise RexHybridRefusal(
                        "PARTIAL_OR_EXTRA_EFFECT", "image_member_set"
                    )
        except BaseException as exc:
            rollback = _restore_bundle(
                preimages, committed, expected_absent, created_directories
            )
            try:
                store.record_outcome(
                    payload["attempt_nonce"],
                    status="ROLLBACK_COMPLETE" if rollback else "ROLLBACK_INCOMPLETE",
                    postimage_sha256=None,
                    effect_receipt=None,
                    failure_code=getattr(exc, "reason_code", type(exc).__name__),
                )
            except BaseException:
                raise RexHybridRefusal(
                    "RECEIPT_PERSISTENCE_INCOMPLETE",
                    "ROLLBACK_COMPLETE" if rollback else "ROLLBACK_INCOMPLETE",
                ) from exc
            raise
        try:
            store.record_outcome(
                payload["attempt_nonce"],
                status="EFFECT_COMMITTED",
                postimage_sha256=candidate_sha256,
                effect_receipt=receipt,
            )
        except BaseException as exc:
            rollback = _restore_bundle(
                preimages, committed, expected_absent, created_directories
            )
            raise RexHybridRefusal(
                "RECEIPT_PERSISTENCE_INCOMPLETE",
                "ROLLBACK_COMPLETE" if rollback else "ROLLBACK_INCOMPLETE",
            ) from exc
        return receipt


def consume_exact_bundle(
    *,
    route_id: str,
    candidate: bytes,
    effect_plan: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    """Canonical production entry point for BLG-08 and DST-02."""
    if route_id not in {"BLG-08", "DST-02"}:
        raise RexHybridRefusal("UNMANAGED_PRODUCTION_ROUTE", route_id)
    return _consume_bundle(
        route_id=route_id,
        candidate=candidate,
        effect_plan=effect_plan,
        target=target,
        context=RexHybridContext.canonical(),
    )


def _git(repo: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise RexHybridRefusal("GIT_EFFECT_REFUSED", type(exc).__name__) from None


def _git_bytes(repo: Path, *arguments: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise RexHybridRefusal("GIT_EFFECT_REFUSED", type(exc).__name__) from None


def build_branch_push_subject(repo_root: Path) -> bytes:
    branch = _git(repo_root, "branch", "--show-current")
    commit_sha = _git(repo_root, "rev-parse", "HEAD")
    tree_sha = _git(repo_root, "rev-parse", "HEAD^{tree}")
    manifest_paths = [
        repo_root / relative
        for relative in _git(
            repo_root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "HEAD^",
            "HEAD",
            "--",
            ".rea/c3/hybrid-subject-manifests",
        ).splitlines()
        if relative
    ]
    admissions = sorted(_sha256(path.read_bytes()) for path in manifest_paths)
    if not admissions:
        raise RexHybridRefusal(
            "PRE_MAIN_BOUNDARY_INVALID", "subject_manifest_missing"
        )
    portable = _portable_admissions(
        CANONICAL_STATE / "rex-c3", set(admissions)
    )
    return _canonical(
        {
            "schema_version": RELEASE_SCHEMA,
            "route_id": "BLG-09",
            "repository": REPOSITORY,
            "branch": branch,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "subject_manifest_sha256s": admissions,
            "local_effect_evidence_sha256s": [
                _sha256(raw) for raw in portable
            ],
        }
    )


def _decode_release(candidate: bytes, route_id: str) -> dict[str, Any]:
    try:
        value = json.loads(candidate)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "release_json") from None
    if not isinstance(value, dict) or _canonical(value) != candidate:
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "release_canonical")
    common = {"schema_version", "route_id", "repository", "commit_sha", "tree_sha"}
    if (
        value.get("schema_version") != RELEASE_SCHEMA
        or value.get("route_id") != route_id
        or value.get("repository") != REPOSITORY
        or not _HEX40.fullmatch(str(value.get("commit_sha", "")))
        or not _HEX40.fullmatch(str(value.get("tree_sha", "")))
    ):
        raise RexHybridRefusal("FINAL_BYTES_INVALID", "release_shape")
    if route_id == "BLG-09":
        if set(value) != common | {
            "branch",
            "subject_manifest_sha256s",
            "local_effect_evidence_sha256s",
        }:
            raise RexHybridRefusal("FINAL_BYTES_INVALID", "release_keys")
        if (
            not isinstance(value["branch"], str)
            or not _BRANCH.fullmatch(value["branch"])
            or value["branch"] in {"main", "master"}
            or not isinstance(value["subject_manifest_sha256s"], list)
            or not value["subject_manifest_sha256s"]
            or any(
                not isinstance(item, str)
                or len(item) != 64
                or any(character not in "0123456789abcdef" for character in item)
                for item in value["subject_manifest_sha256s"]
            )
            or not isinstance(value["local_effect_evidence_sha256s"], list)
            or not value["local_effect_evidence_sha256s"]
            or any(
                not isinstance(item, str)
                or len(item) != 64
                or any(character not in "0123456789abcdef" for character in item)
                for item in value["local_effect_evidence_sha256s"]
            )
        ):
            raise RexHybridRefusal("PRE_MAIN_BOUNDARY_INVALID", "branch_subject")
    elif route_id == "BLG-10":
        if set(value) != common | {"workflow_sha256", "main_push_receipt_sha256"}:
            raise RexHybridRefusal("FINAL_BYTES_INVALID", "deploy_keys")
        if any(
            not isinstance(value.get(key), str)
            or len(value[key]) != 64
            or any(character not in "0123456789abcdef" for character in value[key])
            for key in ("workflow_sha256", "main_push_receipt_sha256")
        ):
            raise RexHybridRefusal("FINAL_BYTES_INVALID", "deploy_digests")
    return value


def branch_push_plan(candidate: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _decode_release(candidate, "BLG-09")
    plan = _closed_plan("BLG-09", "push_pr_branch", {"branch": value["branch"]})
    target = {
        "repository": REPOSITORY,
        "branch": value["branch"],
        "commit_sha": value["commit_sha"],
        "tree_sha": value["tree_sha"],
        "boundary": "PRE_MAIN_BOUNDARY",
    }
    return plan, target


def _write_state_receipt(
    context: RexHybridContext, route_id: str, commit_sha: str, receipt: dict[str, Any]
) -> Path:
    path = context.state_root / "release-receipts" / f"{route_id.lower()}-{commit_sha}.json"
    _atomic_write(path, _canonical(receipt) + b"\n")
    return path


def _portable_admissions(
    state_root: Path, manifest_sha256s: set[str]
) -> list[bytes]:
    root = state_root / "local-effect-evidence"
    selected: list[bytes] = []
    covered: set[str] = set()
    coverage_count = {value: 0 for value in manifest_sha256s}
    for path in sorted(root.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise RexHybridRefusal("ADMISSION_TRANSPORT_INVALID", str(path))
        raw = path.read_bytes()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            raise RexHybridRefusal("ADMISSION_TRANSPORT_INVALID", f"{path}:json") from None
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != LOCAL_EFFECT_SCHEMA
            or _canonical(value) + b"\n" != raw
            or not isinstance(value.get("target"), dict)
            or not isinstance(value["target"].get("members"), list)
        ):
            raise RexHybridRefusal("ADMISSION_TRANSPORT_INVALID", f"{path}:shape")
        receipt_manifests = {
            row["sha256"]
            for row in value["target"]["members"]
            if isinstance(row, dict)
            and str(row.get("path", "")).startswith(
                ".rea/c3/hybrid-subject-manifests/"
            )
            and isinstance(row.get("sha256"), str)
        }
        if receipt_manifests & manifest_sha256s:
            if not receipt_manifests <= manifest_sha256s:
                raise RexHybridRefusal(
                    "ADMISSION_TRANSPORT_INVALID", f"{path}:manifest_scope"
                )
            selected.append(raw)
            covered.update(receipt_manifests)
            for manifest in receipt_manifests:
                coverage_count[manifest] += 1
    if covered != manifest_sha256s:
        raise RexHybridRefusal(
            "ADMISSION_TRANSPORT_INVALID", "manifest_coverage"
        )
    if any(count != 1 for count in coverage_count.values()):
        raise RexHybridRefusal(
            "ADMISSION_TRANSPORT_INVALID", "manifest_coverage_ambiguous"
        )
    return selected


def _git_input(repo: Path, arguments: list[str], raw: bytes, *, environment=None) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments],
            input=raw,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=45,
        ).stdout.decode("ascii").strip()
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        raise RexHybridRefusal(
            "ADMISSION_TRANSPORT_INCOMPLETE", type(exc).__name__
        ) from None


def _push_admission_transport(
    repo_root: Path, head_sha: str, receipts: list[bytes]
) -> dict[str, Any]:
    transport = _canonical(
        {
            "schema_version": TRANSPORT_SCHEMA,
            "repository": REPOSITORY,
            "head_sha": head_sha,
            "semantic_boundary": "AUTHORIZATION_TRANSPORT_ONLY",
            "server_effect_established": False,
            "durable_spend_proof_included": False,
            "receipts": [json.loads(raw) for raw in receipts],
        }
    ) + b"\n"
    reference = f"refs/heads/rea-c3-admission/{head_sha}"
    receipt_sha256s = [_sha256(raw) for raw in receipts]

    def reuse_existing(prior_commit: str) -> dict[str, Any]:
        _git(repo_root, "fetch", "--no-tags", "origin", reference)
        if _git(repo_root, "rev-parse", "FETCH_HEAD") != prior_commit:
            raise RexHybridRefusal(
                "ADMISSION_TRANSPORT_INCOMPLETE", "fetch_head_mismatch"
            )
        observed = _git_bytes(
            repo_root, "show", f"{prior_commit}:admission-transport.json"
        )
        if observed != transport:
            raise RexHybridRefusal(
                "ADMISSION_TRANSPORT_INCOMPLETE", "ref_content_mismatch"
            )
        blob = hashlib.sha1(
            b"blob " + str(len(transport)).encode("ascii") + b"\0" + transport
        ).hexdigest()
        tree = _git(repo_root, "rev-parse", f"{prior_commit}^{{tree}}")
        if _git(repo_root, "ls-tree", "-r", "--full-tree", prior_commit) != (
            f"100644 blob {blob}\tadmission-transport.json"
        ):
            raise RexHybridRefusal(
                "ADMISSION_TRANSPORT_INCOMPLETE", "ref_tree_mismatch"
            )
        return {
            "reference": reference,
            "transport_commit_sha": prior_commit,
            "transport_tree_sha": tree,
            "transport_sha256": _sha256(transport),
            "receipt_sha256s": receipt_sha256s,
            "reused_existing_ref": True,
        }

    prior = _git(repo_root, "ls-remote", "--heads", "origin", reference).split()
    if prior:
        if len(prior) != 2 or prior[1] != reference or not _HEX40.fullmatch(prior[0]):
            raise RexHybridRefusal(
                "ADMISSION_TRANSPORT_INCOMPLETE", "remote_ref_shape"
            )
        return reuse_existing(prior[0])

    blob = _git_input(repo_root, ["hash-object", "-w", "--stdin"], transport)
    tree = _git_input(
        repo_root,
        ["mktree"],
        f"100644 blob {blob}\tadmission-transport.json\n".encode("ascii"),
    )
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "REA C3 Admission Transport",
        "GIT_AUTHOR_EMAIL": "rea-c3@invalid",
        "GIT_COMMITTER_NAME": "REA C3 Admission Transport",
        "GIT_COMMITTER_EMAIL": "rea-c3@invalid",
    }
    commit = _git_input(
        repo_root,
        ["commit-tree", tree, "-m", f"REA C3 admission transport {head_sha}"],
        b"",
        environment=environment,
    )
    try:
        _git(repo_root, "push", "origin", f"{commit}:{reference}")
    except RexHybridRefusal as exc:
        raced = _git(
            repo_root, "ls-remote", "--heads", "origin", reference
        ).split()
        if (
            len(raced) == 2
            and raced[1] == reference
            and _HEX40.fullmatch(raced[0])
        ):
            return reuse_existing(raced[0])
        raise exc
    remote = _git(repo_root, "ls-remote", "--heads", "origin", reference).split()
    if remote != [commit, reference]:
        raise RexHybridRefusal("ADMISSION_TRANSPORT_INCOMPLETE", "remote_ref")
    return {
        "reference": reference,
        "transport_commit_sha": commit,
        "transport_tree_sha": tree,
        "transport_sha256": _sha256(transport),
        "receipt_sha256s": receipt_sha256s,
        "reused_existing_ref": False,
    }


def _consume_branch_push(
    *,
    candidate: bytes,
    effect_plan: dict[str, Any],
    target: dict[str, Any],
    context: RexHybridContext,
) -> dict[str, Any]:
    _require_context(context)
    value = _decode_release(candidate, "BLG-09")
    expected_plan, projected = branch_push_plan(candidate)
    if effect_plan != expected_plan or target != projected:
        raise RexHybridRefusal("PLAN_TARGET_MISMATCH", "BLG-09")
    if _git(context.repo_root, "status", "--porcelain", "--untracked-files=all"):
        raise RexHybridRefusal("PRE_MAIN_BOUNDARY_INVALID", "worktree_dirty")
    if (
        _git(context.repo_root, "branch", "--show-current") != value["branch"]
        or _git(context.repo_root, "rev-parse", "HEAD") != value["commit_sha"]
        or _git(context.repo_root, "rev-parse", "HEAD^{tree}") != value["tree_sha"]
        or _git(context.repo_root, "remote", "get-url", "origin") != ORIGIN
    ):
        raise RexHybridRefusal("PRE_MAIN_BOUNDARY_INVALID", "git_subject")
    context.state_root.mkdir(parents=True, exist_ok=True)
    lock_path = context.state_root / "route-locks/rex-release.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        plan_sha256 = _sha256(_canonical(effect_plan))
        destination = (
            f"git://{REPOSITORY}/refs/heads/{value['branch']}"
            f"#plan-sha256={plan_sha256}"
        )
        try:
            _git(
                context.repo_root,
                "push",
                "origin",
                f"HEAD:refs/heads/{value['branch']}",
            )
            remote = _git(
                context.repo_root,
                "ls-remote",
                "--heads",
                "origin",
                f"refs/heads/{value['branch']}",
            )
            fields = remote.split()
            if fields != [value["commit_sha"], f"refs/heads/{value['branch']}"]:
                raise RexHybridRefusal("PUSH_RECEIPT_MISMATCH", remote)
            portable = _portable_admissions(
                context.state_root,
                set(value["subject_manifest_sha256s"]),
            )
            if [_sha256(raw) for raw in portable] != value["local_effect_evidence_sha256s"]:
                raise RexHybridRefusal(
                    "ADMISSION_TRANSPORT_INVALID", "release_subject"
                )
            admission_transport = _push_admission_transport(
                context.repo_root, value["commit_sha"], portable
            )
        except BaseException as exc:
            raise
        receipt = {
            "schema_version": EFFECT_SCHEMA,
            "verdict": "PRE_MAIN_BOUNDARY",
            "boundary_for_route": "BLG-09",
            "transport_effect": "PUSH_PR_BRANCH",
            "repository": REPOSITORY,
            "branch": value["branch"],
            "pushed_commit_sha": value["commit_sha"],
            "pushed_tree_sha": value["tree_sha"],
            "remote_ref": f"refs/heads/{value['branch']}",
            "main_effect_established": False,
            "required_next_boundary": "PROTECTED_PR_MERGE_AND_EXACT_MAIN_RECEIPT",
            "candidate_sha256": _sha256(candidate),
            "plan_sha256": plan_sha256,
            "destination": destination,
            "admission_transport": admission_transport,
            "server_effect_established": False,
        }
        try:
            path = _write_state_receipt(
                context, "BLG-09", value["commit_sha"], receipt
            )
        except BaseException as exc:
            raise RexHybridRefusal(
                "RECEIPT_PERSISTENCE_INCOMPLETE", "ROLLBACK_INCOMPLETE"
            ) from exc
        return {**receipt, "receipt_path": str(path)}


def push_pr_branch(
    *, candidate: bytes, effect_plan: dict[str, Any], target: dict[str, Any]
) -> dict[str, Any]:
    """Push exact PR transport. This is not registered BLG-09 authority."""
    return _consume_branch_push(
        candidate=candidate,
        effect_plan=effect_plan,
        target=target,
        context=RexHybridContext.canonical(),
    )


def _gh_json(*arguments: str) -> Any:
    try:
        raw = subprocess.run(
            ["gh", *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
        ).stdout
        return json.loads(raw)
    except (
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        raise RexHybridRefusal("GITHUB_RECEIPT_UNAVAILABLE", type(exc).__name__) from None


def _release_receipt(context: RexHybridContext, name: str) -> tuple[Path, dict[str, Any], bytes]:
    path = context.state_root / "release-receipts" / name
    if path.is_symlink() or not path.is_file():
        raise RexHybridRefusal("RELEASE_RECEIPT_INVALID", name)
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise RexHybridRefusal("RELEASE_RECEIPT_INVALID", f"{name}:json") from None
    if not isinstance(value, dict) or _canonical(value) + b"\n" != raw:
        raise RexHybridRefusal("RELEASE_RECEIPT_INVALID", f"{name}:canonical")
    return path, value, raw


def record_protected_main_merge(pr_number: int) -> dict[str, Any]:
    """Detect and durably bind the exact protected-main result of BLG-09."""
    context = RexHybridContext.canonical()
    _require_context(context)
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "pr_number")
    value = _gh_json(
        "pr",
        "view",
        str(pr_number),
        "--repo",
        REPOSITORY,
        "--json",
        "number,state,baseRefName,headRefOid,mergeCommit,mergedAt,url",
    )
    merge = value.get("mergeCommit") if isinstance(value, dict) else None
    main_sha = merge.get("oid") if isinstance(merge, dict) else None
    head_sha = value.get("headRefOid") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("number") != pr_number
        or value.get("state") != "MERGED"
        or value.get("baseRefName") != "main"
        or not _HEX40.fullmatch(str(head_sha or ""))
        or not _HEX40.fullmatch(str(main_sha or ""))
        or not isinstance(value.get("mergedAt"), str)
        or not isinstance(value.get("url"), str)
    ):
        raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "github_pr")
    _git(context.repo_root, "fetch", "origin", "main")
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(context.repo_root),
                "merge-base",
                "--is-ancestor",
                head_sha,
                main_sha,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(context.repo_root),
                "merge-base",
                "--is-ancestor",
                main_sha,
                "origin/main",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "ancestry") from None
    main_tree = _git(context.repo_root, "rev-parse", f"{main_sha}^{{tree}}")
    current_main = _git(context.repo_root, "rev-parse", "origin/main")
    _path, pre_main, pre_main_raw = _release_receipt(
        context, f"blg-09-{head_sha}.json"
    )
    if (
        pre_main.get("verdict") != "PRE_MAIN_BOUNDARY"
        or pre_main.get("boundary_for_route") != "BLG-09"
        or pre_main.get("pushed_commit_sha") != head_sha
        or pre_main.get("main_effect_established") is not False
    ):
        raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "pre_main_receipt")
    receipt = {
        "schema_version": EFFECT_SCHEMA,
        "verdict": "PROTECTED_MAIN_TRANSITION_DETECTED",
        "route_id": "BLG-09",
        "repository": REPOSITORY,
        "pr_number": pr_number,
        "pr_url": value["url"],
        "pr_head_sha": head_sha,
        "main_commit_sha": main_sha,
        "main_tree_sha": main_tree,
        "current_origin_main_sha": current_main,
        "merged_at": value["mergedAt"],
        "pre_main_receipt_sha256": _sha256(pre_main_raw),
        "merge_head_ancestor": True,
        "merge_main_ancestor_of_current": True,
        "main_transition_detected": True,
        "server_acceptance": "NOT_ESTABLISHED",
        "main_effect_established": False,
    }
    path = _write_state_receipt(context, "BLG-09-main", main_sha, receipt)
    return {**receipt, "receipt_path": str(path)}


def build_deploy_subject(main_receipt_path: Path) -> bytes:
    if main_receipt_path.is_symlink() or not main_receipt_path.is_file():
        raise RexHybridRefusal("MAIN_RECEIPT_INVALID", str(main_receipt_path))
    main_raw = main_receipt_path.read_bytes()
    try:
        main = json.loads(main_raw)
    except json.JSONDecodeError:
        raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "json") from None
    if (
        not isinstance(main, dict)
        or main.get("schema_version") != EFFECT_SCHEMA
        or main.get("route_id") != "BLG-09"
        or main.get("verdict") != "PROTECTED_MAIN_TRANSITION_DETECTED"
        or main.get("main_transition_detected") is not True
        or main.get("server_acceptance") != "NOT_ESTABLISHED"
        or main.get("main_effect_established") is not False
        or not _HEX40.fullmatch(str(main.get("main_commit_sha", "")))
        or not _HEX40.fullmatch(str(main.get("main_tree_sha", "")))
        or _canonical(main) + b"\n" != main_raw
    ):
        raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "shape")
    workflow_raw = _git_bytes(
        CANONICAL_REPO,
        "show",
        f"{main['main_commit_sha']}:.github/workflows/deploy.yml",
    )
    return _canonical(
        {
            "schema_version": RELEASE_SCHEMA,
            "route_id": "BLG-10",
            "repository": REPOSITORY,
            "commit_sha": main["main_commit_sha"],
            "tree_sha": main["main_tree_sha"],
            "workflow_sha256": _sha256(workflow_raw),
            "main_push_receipt_sha256": _sha256(main_raw),
        }
    )


def deploy_plan(candidate: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _decode_release(candidate, "BLG-10")
    parameters = {
        "commit_sha": value["commit_sha"],
        "workflow_sha256": value["workflow_sha256"],
        "main_push_receipt_sha256": value["main_push_receipt_sha256"],
    }
    plan = _closed_plan("BLG-10", "dispatch_deploy", parameters)
    target = {
        "repository": REPOSITORY,
        "main_commit_sha": value["commit_sha"],
        "main_tree_sha": value["tree_sha"],
        "workflow_sha256": value["workflow_sha256"],
        "main_push_receipt_sha256": value["main_push_receipt_sha256"],
    }
    return plan, target


def _dispatch_and_wait(
    *, commit_sha: str, dispatch_nonce: str, timeout_seconds: int = 600
) -> dict[str, Any]:
    try:
        subprocess.run(
            [
                "gh",
                "workflow",
                "run",
                "deploy.yml",
                "--repo",
                REPOSITORY,
                "--ref",
                "main",
                "-f",
                f"target_sha={commit_sha}",
                "-f",
                f"dispatch_nonce={dispatch_nonce}",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RexHybridRefusal("DEPLOY_DISPATCH_REFUSED", type(exc).__name__) from None
    deadline = time.monotonic() + timeout_seconds
    inspected: set[int] = set()
    while time.monotonic() < deadline:
        runs = _gh_json(
            "run",
            "list",
            "--repo",
            REPOSITORY,
            "--workflow",
            "deploy.yml",
            "--event",
            "workflow_dispatch",
            "--commit",
            commit_sha,
            "--json",
            "databaseId,headSha,status,conclusion,url",
            "--limit",
            "20",
        )
        if not isinstance(runs, list):
            raise RexHybridRefusal("DEPLOY_RECEIPT_INVALID", "run_list")
        for run in runs:
            run_id = run.get("databaseId") if isinstance(run, dict) else None
            if (
                not isinstance(run_id, int)
                or run_id in inspected
                or run.get("headSha") != commit_sha
                or run.get("status") != "completed"
            ):
                continue
            inspected.add(run_id)
            if run.get("conclusion") != "success":
                continue
            with tempfile.TemporaryDirectory(prefix="rea-c3-rex-deploy-") as temporary:
                try:
                    subprocess.run(
                        [
                            "gh",
                            "run",
                            "download",
                            str(run_id),
                            "--repo",
                            REPOSITORY,
                            "--name",
                            f"rex-deploy-receipt-{run_id}",
                            "--dir",
                            temporary,
                        ],
                        check=True,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=45,
                    )
                    raw = (Path(temporary) / "deploy-receipt.json").read_bytes()
                    receipt = json.loads(raw)
                except (
                    OSError,
                    subprocess.SubprocessError,
                    json.JSONDecodeError,
                ):
                    continue
            if (
                isinstance(receipt, dict)
                and receipt.get("schema_version") == DEPLOY_RECEIPT_SCHEMA
                and receipt.get("repository") == REPOSITORY
                and receipt.get("run_id") == run_id
                and receipt.get("dispatch_nonce") == dispatch_nonce
                and receipt.get("target_sha") == commit_sha
                and receipt.get("checked_out_sha") == commit_sha
                and receipt.get("deployed_sha") == commit_sha
                and receipt.get("deployment_status") == "success"
            ):
                run_api = _gh_json(
                    "api",
                    f"repos/{REPOSITORY}/actions/runs/{run_id}",
                )
                if (
                    not isinstance(run_api, dict)
                    or run_api.get("id") != run_id
                    or run_api.get("head_sha") != commit_sha
                    or run_api.get("event") != "workflow_dispatch"
                    or run_api.get("status") != "completed"
                    or run_api.get("conclusion") != "success"
                ):
                    continue
                deployments = _gh_json(
                    "api",
                    (
                        f"repos/{REPOSITORY}/deployments"
                        f"?sha={commit_sha}&environment=github-pages&per_page=100"
                    ),
                )
                independent = None
                if isinstance(deployments, list):
                    for deployment in deployments:
                        deployment_id = (
                            deployment.get("id")
                            if isinstance(deployment, dict)
                            else None
                        )
                        if (
                            not isinstance(deployment_id, int)
                            or deployment.get("sha") != commit_sha
                            or deployment.get("environment") != "github-pages"
                            or deployment.get("ref") != "main"
                            or (
                                not isinstance(deployment.get("creator"), dict)
                                or deployment["creator"].get("login")
                                != "rexcoleman"
                            )
                            or (
                                not isinstance(
                                    deployment.get("performed_via_github_app"),
                                    dict,
                                )
                                or deployment["performed_via_github_app"].get("slug")
                                != "github-actions"
                                or deployment["performed_via_github_app"].get("id")
                                != 15368
                            )
                        ):
                            continue
                        statuses = _gh_json(
                            "api",
                            f"repos/{REPOSITORY}/deployments/{deployment_id}/statuses",
                        )
                        if not isinstance(statuses, list):
                            continue
                        status = next(
                            (
                                row
                                for row in statuses
                                if isinstance(row, dict)
                                and row.get("state") == "success"
                                and (
                                    f"/actions/runs/{run_id}"
                                    in str(row.get("log_url", ""))
                                )
                            ),
                            None,
                        )
                        if status is not None:
                            independent = {
                                "deployment_id": deployment_id,
                                "deployment_sha": deployment["sha"],
                                "deployment_ref": deployment["ref"],
                                "deployment_environment": deployment["environment"],
                                "status_id": status.get("id"),
                                "status_state": status["state"],
                                "status_log_url": status.get("log_url"),
                                "environment_url": status.get("environment_url"),
                            }
                            break
                if independent is None:
                    continue
                return {
                    "run_id": run_id,
                    "run_url": run["url"],
                    "artifact_sha256": _sha256(raw),
                    "deploy_receipt": receipt,
                    "github_run_evidence": {
                        "id": run_api["id"],
                        "head_sha": run_api["head_sha"],
                        "event": run_api["event"],
                        "status": run_api["status"],
                        "conclusion": run_api["conclusion"],
                        "html_url": run_api.get("html_url"),
                    },
                    "github_deployment_evidence": independent,
                }
        time.sleep(5)
    raise RexHybridRefusal("DEPLOY_RECEIPT_UNAVAILABLE", commit_sha)


def _consume_deploy(
    *,
    candidate: bytes,
    effect_plan: dict[str, Any],
    target: dict[str, Any],
    context: RexHybridContext,
) -> dict[str, Any]:
    _require_context(context)
    value = _decode_release(candidate, "BLG-10")
    expected_plan, projected = deploy_plan(candidate)
    if effect_plan != expected_plan or target != projected:
        raise RexHybridRefusal("PLAN_TARGET_MISMATCH", "BLG-10")
    if (
        _git(context.repo_root, "ls-remote", "--heads", "origin", "refs/heads/main").split()
        != [value["commit_sha"], "refs/heads/main"]
        or _git(context.repo_root, "rev-parse", f"{value['commit_sha']}^{{tree}}")
        != value["tree_sha"]
        or _sha256(
            _git_bytes(
                context.repo_root,
                "show",
                f"{value['commit_sha']}:.github/workflows/deploy.yml",
            )
        )
        != value["workflow_sha256"]
    ):
        raise RexHybridRefusal("DEPLOY_SUBJECT_MISMATCH", value["commit_sha"])
    context.state_root.mkdir(parents=True, exist_ok=True)
    lock_path = context.state_root / "route-locks/rex-release.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        plan_sha256 = _sha256(_canonical(effect_plan))
        destination = (
            f"deploy://{REPOSITORY}/workflow-dispatch/{value['commit_sha']}"
            f"#plan-sha256={plan_sha256}"
        )
        (
            _protocol,
            _spend_module,
            store,
            payload,
            capability,
            lineage,
            request,
        ) = _authority(
            context=context,
            route_id="BLG-10",
            candidate=candidate,
            destination=destination,
            requested_effect="deploy_workflow_dispatch",
            target=projected,
            plan_sha256=plan_sha256,
            preimage_sha256=None,
        )
        try:
            effect_result = _dispatch_and_wait(
                commit_sha=value["commit_sha"],
                dispatch_nonce=payload["attempt_nonce"],
            )
        except BaseException as exc:
            try:
                store.record_outcome(
                    payload["attempt_nonce"],
                    status="ROLLBACK_INCOMPLETE",
                    postimage_sha256=None,
                    effect_receipt=None,
                    failure_code=getattr(exc, "reason_code", type(exc).__name__),
                )
            except BaseException:
                raise RexHybridRefusal(
                    "RECEIPT_PERSISTENCE_INCOMPLETE", "ROLLBACK_INCOMPLETE"
                ) from exc
            raise
        receipt = {
            "schema_version": EFFECT_SCHEMA,
            "verdict": "DEPLOYMENT_EFFECT_ESTABLISHED",
            "route_id": "BLG-10",
            "repository": REPOSITORY,
            "deployed_commit_sha": value["commit_sha"],
            "deployed_tree_sha": value["tree_sha"],
            "candidate_sha256": _sha256(candidate),
            "attempt_nonce": payload["attempt_nonce"],
            "capability_id": payload["capability_id"],
            "capability": capability,
            "lineage": lineage,
            "wea": request["wea"],
            "effect_result": effect_result,
        }
        try:
            store.record_outcome(
                payload["attempt_nonce"],
                status="EFFECT_COMMITTED",
                postimage_sha256=value["commit_sha"],
                effect_receipt=receipt,
            )
            path = _write_state_receipt(
                context, "BLG-10", value["commit_sha"], receipt
            )
        except BaseException as exc:
            raise RexHybridRefusal(
                "RECEIPT_PERSISTENCE_INCOMPLETE", "ROLLBACK_INCOMPLETE"
            ) from exc
        return {**receipt, "receipt_path": str(path)}


def consume_deploy(
    *, candidate: bytes, effect_plan: dict[str, Any], target: dict[str, Any]
) -> dict[str, Any]:
    return _consume_deploy(
        candidate=candidate,
        effect_plan=effect_plan,
        target=target,
        context=RexHybridContext.canonical(),
    )


def refuse_unmanaged_mutation(name: str) -> None:
    raise RexHybridRefusal("UNMANAGED_PRODUCTION_ROUTE", name)
