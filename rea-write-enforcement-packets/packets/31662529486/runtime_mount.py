#!/usr/bin/env python3
"""Fail-closed runtime mount for exact-byte write effects.

This module is the only supported bridge from live emitters to the tranche-2
gate and atomic consumer.  A caller supplies final bytes and an effect callback;
the callback is unreachable until the resolver-backed gate admits the complete
lineage and the one-attempt authorization is consumed.
"""

from __future__ import annotations

import hashlib
import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import fcntl
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parents[2]
REFUSAL_EXIT = 3
ALLOWED_SURFACES = frozenset({"report", "blog", "publication", "distribution"})
EVENT_SINK = Path.home() / ".local/state/rea_enforcement/write_integrity_mount_events.jsonl"
HYBRID_STATE = Path.home() / ".local/state/rea_enforcement/hybrid"
HYBRID_PROVIDER = Path.home() / ".local/libexec/rea_enforcement/hybrid_capability_provider"
HYBRID_RUNTIME = Path.home() / ".local/libexec/rea_enforcement/runtime_mount.py"
HYBRID_TEST_CONTEXT_ENV = "REA_WRITE_INTEGRITY_ISOLATED_HYBRID_CONTEXT"
HYBRID_CONTEXT_KEYS = frozenset({
    "schema_version", "isolated_fixture", "trust_store", "revocations",
    "spend_store", "capability", "lineage", "wea",
})


class MountRefusal(RuntimeError):
    """Raised after a structured refusal has been written to stderr."""

    def __init__(self, receipt: dict[str, Any]) -> None:
        self.receipt = receipt
        self.raw_exit = REFUSAL_EXIT
        super().__init__(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


class _AuthorityRefusal(RuntimeError):
    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}:{detail}")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reserve_event_sink(
    route_id: str,
    surface: str,
    run_id: str,
    destination: str,
    requested_effect: str,
) -> TextIO:
    """Persist a unique attempt identity before the effect can be reached."""
    try:
        EVENT_SINK.parent.mkdir(parents=True, exist_ok=True)
        handle = EVENT_SINK.open("a+", encoding="utf-8")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        seen: set[str] = set()
        for line_number, line in enumerate(handle, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f"malformed_line:{line_number}") from None
            observed = event.get("run_id")
            if not isinstance(observed, str) or not observed:
                raise ValueError(f"missing_run_id:{line_number}")
            seen.add(observed)
    except (OSError, ValueError) as exc:
        try:
            handle.close()
        except (NameError, OSError):
            pass
        _refuse(route_id, surface, run_id, "EVENT_SINK_UNAVAILABLE", type(exc).__name__)
    if run_id in seen:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
        _refuse(route_id, surface, run_id, "DUPLICATE_RUN_ID", run_id)
    reservation = {
        "schema_version": "rea.write.mount-event.v1",
        "event_class": "MOUNT_ATTEMPT_RESERVED",
        "route_id": route_id,
        "surface": surface,
        "run_id": run_id,
        "destination": destination,
        "requested_effect": requested_effect,
        "mutation_authorized": False,
    }
    try:
        handle.seek(0, os.SEEK_END)
        handle.write(json.dumps(reservation, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    except OSError as exc:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
        _refuse(route_id, surface, run_id, "EVENT_SINK_UNAVAILABLE", type(exc).__name__)
    return handle


def _persist_event_result(handle: TextIO, result: dict[str, Any]) -> None:
    event = {
        "schema_version": "rea.write.mount-event.v1",
        "event_class": "MOUNT_EFFECT_RESULT",
        **result,
    }
    handle.seek(0, os.SEEK_END)
    handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    handle.flush()
    os.fsync(handle.fileno())


def _release_event_sink(handle: TextIO) -> None:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _refuse(route_id: str, surface: str, run_id: str, reason: str, detail: str,
            state_digest: str | None = None) -> None:
    receipt = {
        "schema_version": "rea.write.mount-result.v1",
        "route_id": route_id,
        "surface": surface,
        "run_id": run_id,
        "verdict": "REFUSE",
        "reason_code": reason,
        "detail": detail,
        "raw_exit": REFUSAL_EXIT,
        "mutation_authorized": False,
        "state_digest": state_digest,
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")), file=sys.stderr)
    raise MountRefusal(receipt)


def _read_json(path: Path, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _AuthorityRefusal(reason, type(exc).__name__) from None
    if not isinstance(value, dict):
        raise _AuthorityRefusal(reason, "not_object")
    return value


class _RegistrySpendStore:
    """Durably reserve one local attempt after signed-registry verification."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise RuntimeError("spend_store_symlink")
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
                # The provider derives verification_id deterministically from
                # signed authority, the exact request binding, and classified
                # claims. A unique index makes that one decision single-spend
                # across threads and processes. Existing duplicate decisions
                # make index creation fail closed instead of legitimizing
                # historical replay.
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                    registry_verification_spends_verification_id_unique
                    ON registry_verification_spends (verification_id)
                    """
                )
        except sqlite3.IntegrityError:
            raise RuntimeError(
                "registry_spend_store_migration_duplicate_decision"
            ) from None
        except sqlite3.Error as exc:
            raise RuntimeError(
                f"registry_spend_store_unavailable:{type(exc).__name__}"
            ) from None

    def reserve(self, decision: dict[str, Any]) -> dict[str, Any]:
        attempt = uuid.uuid4().hex
        verification = decision.get("verification_id")
        if (
            not isinstance(verification, str)
            or not verification.startswith("registry-verification-")
        ):
            raise RuntimeError("registry_decision_identity")
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
            raise RuntimeError("registry_attempt_replayed") from None
        return {**decision, "attempt_nonce": attempt}

    def record_outcome(
        self,
        attempt_nonce: str,
        *,
        status: str,
        postimage_sha256: str | None,
        effect_receipt: dict[str, Any] | None,
        failure_code: str | None = None,
    ) -> None:
        if status not in {"EFFECT_COMMITTED", "EFFECT_FAILED"}:
            raise RuntimeError("registry_outcome_invalid")
        receipt = (
            json.dumps(effect_receipt, sort_keys=True, separators=(",", ":"))
            if effect_receipt is not None
            else None
        )
        with sqlite3.connect(self.path, timeout=30) as connection:
            changed = connection.execute(
                """
                UPDATE registry_verification_spends
                SET status=?, postimage_sha256=?, effect_receipt_json=?,
                    failure_code=?
                WHERE attempt_nonce=? AND status='RESERVED'
                """,
                (
                    status,
                    postimage_sha256,
                    receipt,
                    failure_code,
                    attempt_nonce,
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeError("registry_outcome_transition")


def _hybrid_authority(
    *,
    route_id: str,
    surface: str,
    candidate: bytes,
    destination: str,
    requested_effect: str,
) -> dict[str, Any]:
    isolated = os.environ.get(HYBRID_TEST_CONTEXT_ENV)
    if isolated:
        from write_integrity.hybrid import (
            DurableSpendStore,
            HybridRefusal,
            HybridVerifier,
        )

        # The proof seam cannot become a developer-local production opt-out.
        # It is accepted only from an isolated /tmp worktree; canonical and
        # installed consumers always resolve the production authority below.
        try:
            ROOT.resolve().relative_to(Path("/tmp").resolve())
        except ValueError:
            raise _AuthorityRefusal(
                "ISOLATED_HARNESS_REQUIRED", "runtime_not_under_tmp"
            ) from None
        context = _read_json(Path(isolated), "HYBRID_TEST_CONTEXT_UNAVAILABLE")
        if (
            set(context) != HYBRID_CONTEXT_KEYS
            or context.get("schema_version")
            != "rea.write.runtime-hybrid-test-context.v1"
            or context.get("isolated_fixture") is not True
        ):
            raise _AuthorityRefusal("HYBRID_TEST_CONTEXT_INVALID", "closed_shape")
        paths = {
            key: Path(context[key]).resolve()
            for key in (
                "trust_store", "revocations", "spend_store",
                "capability", "lineage",
            )
        }
        root = Path(isolated).resolve().parent
        if any(root not in (path, *path.parents) for path in paths.values()):
            raise _AuthorityRefusal("FIXTURE_SEPARATION_REQUIRED", "hybrid_paths")
        verifier = HybridVerifier.from_files(
            paths["trust_store"],
            paths["revocations"],
            production=False,
            revocation_watermark_path=paths["spend_store"],
        )
        return {
            "mode": "isolated",
            "verifier": verifier,
            "store": DurableSpendStore(paths["spend_store"]),
            "capability": _read_json(
                paths["capability"], "HYBRID_CAPABILITY_UNAVAILABLE"
            ),
            "lineage": _read_json(paths["lineage"], "HYBRID_LINEAGE_UNAVAILABLE"),
            "wea": context["wea"],
        }

    wea = {"provider_verified": True}
    if (
        not HYBRID_PROVIDER.is_file()
        or not os.access(HYBRID_PROVIDER, os.X_OK)
    ):
        raise _AuthorityRefusal(
            "TRUSTED_CAPABILITY_ISSUER_UNAVAILABLE", "production_custody"
        )
    target = {"artifact_path": destination}
    effect_plan = {
        "schema_version": "rea.c3.closed-effect-plan.v1",
        "route_id": route_id,
        "operation": requested_effect,
        "parameters": target,
    }
    try:
        preimage = Path(destination).read_bytes()
    except FileNotFoundError:
        preimage = None
    except OSError as exc:
        raise _AuthorityRefusal(
            "PREIMAGE_SNAPSHOT_FAILED", type(exc).__name__
        ) from None
    request = {
        "schema_version": "rea.c3.hybrid.capability-request.v2",
        "route_id": route_id,
        "surface": surface,
        "destination": destination,
        "requested_effect": requested_effect,
        "candidate_sha256": _sha256(candidate),
        "candidate_byte_length": len(candidate),
        "candidate_b64": base64.b64encode(candidate).decode("ascii"),
        "target_sha256": _sha256(
            json.dumps(
                target, sort_keys=True, separators=(",", ":")
            ).encode()
        ),
        "plan_sha256": _sha256(
            json.dumps(
                effect_plan, sort_keys=True, separators=(",", ":")
            ).encode()
        ),
        "preimage_sha256": (
            _sha256(preimage) if preimage is not None else None
        ),
        "wea": wea,
    }
    try:
        completed = subprocess.run(
            [os.fspath(HYBRID_PROVIDER)],
            input=json.dumps(
                request, sort_keys=True, separators=(",", ":")
            ).encode(),
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _AuthorityRefusal(
            "TRUSTED_CAPABILITY_ISSUER_UNAVAILABLE", type(exc).__name__
        )
    if completed.returncode != 0:
        try:
            refusal = json.loads(completed.stderr)
        except (UnicodeDecodeError, json.JSONDecodeError):
            refusal = {}
        reason = refusal.get("reason_code", "TRUSTED_CAPABILITY_ISSUER_UNAVAILABLE")
        detail = refusal.get("detail", f"raw_exit={completed.returncode}")
        raise _AuthorityRefusal(reason, detail)
    try:
        response = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _AuthorityRefusal("CAPABILITY_RESPONSE_INVALID", "not_json") from None
    if (
        not isinstance(response, dict)
        or set(response) != {"schema_version", "authorization", "decision"}
        or response.get("schema_version")
        != "rea.write.registry-verification-response.v1"
        or not isinstance(response.get("authorization"), dict)
        or not isinstance(response.get("decision"), dict)
    ):
        raise _AuthorityRefusal("CAPABILITY_RESPONSE_INVALID", "closed_shape")
    binding = response["decision"].get("request_binding")
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
    if (
        response["decision"].get("verdict") != "ADMIT"
        or not isinstance(binding, dict)
        or set(binding) != binding_keys
        or any(binding.get(key) != request.get(key) for key in binding)
        or binding.get("candidate_sha256") != _sha256(candidate)
        or binding.get("candidate_byte_length") != len(candidate)
    ):
        raise _AuthorityRefusal("CAPABILITY_RESPONSE_INVALID", "request_binding")
    return {
        "mode": "registry",
        "store": _RegistrySpendStore(
            HYBRID_STATE / "capability_spends.sqlite3"
        ),
        "decision": response["decision"],
        "wea": wea,
    }


def consume_effect(
    *,
    route_id: str,
    surface: str,
    candidate: bytes,
    destination: str,
    requested_effect: str,
    run_id: str,
    effect_callback: Callable[[bytes], Any],
    request_path: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify, reserve, and spend one hybrid capability around an exact effect."""
    del request_path, environment
    if surface not in ALLOWED_SURFACES or not isinstance(candidate, bytes) or not candidate:
        _refuse(route_id, surface, run_id, "CANNOT_EVALUATE", "surface_or_candidate")
    if not all(isinstance(item, str) and item for item in (route_id, destination, requested_effect, run_id)):
        _refuse(str(route_id), str(surface), str(run_id), "CANNOT_EVALUATE", "effect_subject")
    if not callable(effect_callback):
        _refuse(route_id, surface, run_id, "CANNOT_EVALUATE", "effect_callback")
    hybrid_effect = (
        "atomic_write" if requested_effect == "write" else requested_effect
    )
    try:
        authority = _hybrid_authority(
            route_id=route_id,
            surface=surface,
            candidate=candidate,
            destination=destination,
            requested_effect=hybrid_effect,
        )
        store = authority["store"]
        if authority["mode"] == "isolated":
            payload = store.reserve(
                authority["capability"],
                authority["verifier"],
                candidate=candidate,
                lineage=authority["lineage"],
                route_id=route_id,
                surface=surface,
                destination=destination,
                requested_effect=hybrid_effect,
                wea=authority["wea"],
            )
        else:
            payload = store.reserve(authority["decision"])
    except Exception as exc:
        _refuse(
            route_id,
            surface,
            run_id,
            str(getattr(exc, "reason_code", "CAPABILITY_AUTHORITY_FAILURE")),
            str(getattr(exc, "detail", type(exc).__name__)),
        )

    event_handle = _reserve_event_sink(
        route_id, surface, run_id, destination, hybrid_effect
    )
    try:
        effect_result = effect_callback(candidate)
        result = {
            "schema_version": "rea.write.runtime-hybrid-result.v1",
            "verdict": "EFFECT_COMMITTED",
            "route_id": route_id,
            "surface": surface,
            "run_id": run_id,
            "destination": destination,
            "requested_effect": hybrid_effect,
            "candidate_sha256": _sha256(candidate),
            "candidate_byte_length": len(candidate),
            "attempt_nonce": payload["attempt_nonce"],
            "authorization_id": (
                payload.get("verification_id") or payload.get("capability_id")
            ),
            "effect_result": effect_result,
            "mutation_authorized": True,
        }
        try:
            _persist_event_result(event_handle, result)
            store.record_outcome(
                payload["attempt_nonce"],
                status="EFFECT_COMMITTED",
                postimage_sha256=_sha256(candidate),
                effect_receipt=result,
            )
        except (OSError, RuntimeError) as exc:
            _refuse(
                route_id, surface, run_id,
                "EFFECT_RECEIPT_PERSISTENCE_INCOMPLETE",
                type(exc).__name__,
            )
    except MountRefusal:
        raise
    except BaseException as exc:
        try:
            store.record_outcome(
                payload["attempt_nonce"],
                status="EFFECT_FAILED",
                postimage_sha256=None,
                effect_receipt=None,
                failure_code=type(exc).__name__,
            )
        except Exception:
            pass
        _refuse(route_id, surface, run_id, "EFFECT_FAILED", type(exc).__name__)
    finally:
        _release_event_sink(event_handle)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return result


def atomic_write(
    *,
    route_id: str,
    surface: str,
    candidate: bytes,
    destination: str | Path,
    requested_effect: str,
    run_id: str,
    request_path: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Atomically replace a file only inside the consumed authorization."""
    target = Path(destination)

    def commit(exact: bytes) -> dict[str, Any]:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.rea-", dir=target.parent)
        temporary_path = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(exact)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, target)
            directory_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
        return {"kind": "atomic_file_replace", "destination": str(target), "sha256": _sha256(exact), "byte_length": len(exact)}

    return consume_effect(
        route_id=route_id,
        surface=surface,
        candidate=candidate,
        destination=str(target),
        requested_effect=requested_effect,
        run_id=run_id,
        effect_callback=commit,
        request_path=request_path,
        environment=environment,
    )
