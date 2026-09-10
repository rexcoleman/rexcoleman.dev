#!/usr/bin/env python3
"""Record and verify the commit-bound pre-commit boundary receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import subprocess
from pathlib import Path
from typing import Any


SCHEMA = "rea.pre-commit-boundary.v1"
RECEIPT_PATH = ".governance/pre_commit_boundary.json"
CALLER = "git-pre-commit"
MODE = "commit-preflight"
ASSERTION = "COMMIT_PREFLIGHT_PASS"
ZERO_PARENT = "0" * 40
HEX40 = re.compile(r"[0-9a-f]{40}")


class Refusal(RuntimeError):
    def __init__(self, reason: str, detail: Any) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


def checked_git(root: Path, *args: str) -> str:
    result = git(root, *args)
    if result.returncode != 0:
        raise Refusal(
            "GIT_COMMAND_FAILED",
            {"args": list(args), "raw_exit": result.returncode, "stderr": result.stderr},
        )
    return result.stdout


def current_parent(root: Path) -> str:
    result = git(root, "rev-parse", "--verify", "HEAD")
    if result.returncode != 0:
        return ZERO_PARENT
    head = result.stdout.strip()
    if not HEX40.fullmatch(head):
        raise Refusal("CURRENT_HEAD_MALFORMED", head)
    return head


def commit_first_parent(root: Path, commit: str) -> str:
    parents = checked_git(root, "rev-list", "--parents", "-n", "1", commit).split()
    if not parents or parents[0] != commit:
        raise Refusal("COMMIT_PARENT_LINE_MALFORMED", parents)
    if len(parents) == 1:
        return ZERO_PARENT
    return parents[1]


def _stable_paths_digest(paths: list[str]) -> str:
    return hashlib.sha256(("\n".join(paths) + "\n").encode("utf-8")).hexdigest()


def _without_receipt(paths: list[str]) -> list[str]:
    return sorted({path for path in paths if path and path != RECEIPT_PATH})


def staged_paths(root: Path) -> list[str]:
    if current_parent(root) == ZERO_PARENT:
        raw = checked_git(root, "diff", "--cached", "--name-only")
    else:
        raw = checked_git(root, "diff", "--cached", "--name-only", "HEAD", "--")
    return _without_receipt(raw.splitlines())


def changed_paths(root: Path, commit: str) -> list[str]:
    parent = commit_first_parent(root, commit)
    if parent == ZERO_PARENT:
        raw = checked_git(root, "ls-tree", "-r", "--name-only", commit)
    else:
        raw = checked_git(root, "diff", "--name-only", parent, commit)
    return sorted({line for line in raw.splitlines() if line})


def record(root: Path, *, fired_at: str, run_id: str | None = None) -> dict[str, Any]:
    parent = current_parent(root)
    paths = staged_paths(root)
    if not run_id:
        run_id = "pre-commit-" + secrets.token_hex(12)
    receipt = {
        "assertion": ASSERTION,
        "caller": CALLER,
        "changed_paths": paths,
        "changed_paths_count": len(paths),
        "changed_paths_sha256": _stable_paths_digest(paths),
        "mode": MODE,
        "parent_head": parent,
        "run_id": run_id,
        "schema_version": SCHEMA,
        "utc_asserted_at": fired_at,
    }
    receipt_file = root / RECEIPT_PATH
    receipt_file.parent.mkdir(parents=True, exist_ok=True)
    receipt_file.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checked_git(root, "add", "--", RECEIPT_PATH)
    return receipt


def _read_head_receipt(root: Path, commit: str) -> dict[str, Any]:
    result = git(root, "show", f"{commit}:{RECEIPT_PATH}")
    if result.returncode != 0:
        raise Refusal(
            "PRE_COMMIT_BOUNDARY_RECEIPT_ABSENT",
            {"path": RECEIPT_PATH, "stderr": result.stderr},
        )
    try:
        receipt = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal("PRE_COMMIT_BOUNDARY_RECEIPT_JSON_INVALID", str(exc)) from exc
    if not isinstance(receipt, dict):
        raise Refusal("PRE_COMMIT_BOUNDARY_RECEIPT_SHAPE_INVALID", type(receipt).__name__)
    return receipt


def verify(root: Path, expected_head: str) -> dict[str, Any]:
    if not HEX40.fullmatch(expected_head):
        raise Refusal("EXPECTED_HEAD_MALFORMED", expected_head)

    observed_head = checked_git(root, "rev-parse", "HEAD").strip()
    if observed_head != expected_head:
        raise Refusal(
            "EXPECTED_HEAD_MISMATCH",
            {"expected": expected_head, "observed": observed_head},
        )

    all_changed = changed_paths(root, expected_head)
    if RECEIPT_PATH not in all_changed:
        raise Refusal(
            "PRE_COMMIT_BOUNDARY_RECEIPT_NOT_CHANGED",
            {"commit": expected_head, "path": RECEIPT_PATH, "changed_paths": all_changed},
        )
    subject_paths = _without_receipt(all_changed)
    receipt = _read_head_receipt(root, expected_head)

    expected = {
        "assertion": ASSERTION,
        "caller": CALLER,
        "mode": MODE,
        "parent_head": commit_first_parent(root, expected_head),
        "schema_version": SCHEMA,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise Refusal(
                "PRE_COMMIT_BOUNDARY_RECEIPT_FIELD_MISMATCH",
                {"field": key, "expected": value, "observed": receipt.get(key)},
            )
    if receipt.get("changed_paths") != subject_paths:
        raise Refusal(
            "PRE_COMMIT_BOUNDARY_CHANGESET_MISMATCH",
            {"expected": subject_paths, "observed": receipt.get("changed_paths")},
        )
    if receipt.get("changed_paths_count") != len(subject_paths):
        raise Refusal(
            "PRE_COMMIT_BOUNDARY_CHANGESET_COUNT_MISMATCH",
            {"expected": len(subject_paths), "observed": receipt.get("changed_paths_count")},
        )
    digest = _stable_paths_digest(subject_paths)
    if receipt.get("changed_paths_sha256") != digest:
        raise Refusal(
            "PRE_COMMIT_BOUNDARY_CHANGESET_DIGEST_MISMATCH",
            {"expected": digest, "observed": receipt.get("changed_paths_sha256")},
        )
    run_id = receipt.get("run_id")
    if not isinstance(run_id, str) or not run_id.startswith("pre-commit-"):
        raise Refusal("PRE_COMMIT_BOUNDARY_RUN_ID_INVALID", run_id)
    asserted_at = receipt.get("utc_asserted_at")
    if not isinstance(asserted_at, str) or not asserted_at.endswith("Z"):
        raise Refusal("PRE_COMMIT_BOUNDARY_ASSERTION_TIME_INVALID", asserted_at)

    return {
        "authorized": True,
        "boundary": MODE,
        "caller": CALLER,
        "changed_paths_count": len(subject_paths),
        "changed_paths_sha256": digest,
        "exact_head": expected_head,
        "outcome": "PASS",
        "raw_exit": 0,
        "receipt_path": RECEIPT_PATH,
        "schema_version": SCHEMA,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    record_parser = sub.add_parser("record")
    record_parser.add_argument("--project-dir", type=Path, default=Path.cwd())
    record_parser.add_argument("--fired-at", required=True)
    record_parser.add_argument("--run-id")

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--project-dir", type=Path, default=Path.cwd())
    verify_parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()

    try:
        if args.command == "record":
            result = record(args.project_dir.resolve(), fired_at=args.fired_at, run_id=args.run_id)
        else:
            result = verify(args.project_dir.resolve(), args.expected_head)
    except (OSError, UnicodeError, ValueError, Refusal) as exc:
        reason = exc.reason if isinstance(exc, Refusal) else type(exc).__name__
        detail = exc.detail if isinstance(exc, Refusal) else str(exc)
        print(
            json.dumps(
                {
                    "authorized": False,
                    "detail": detail,
                    "outcome": "FAIL",
                    "raw_exit": 3,
                    "reason_code": reason,
                    "schema_version": SCHEMA,
                },
                sort_keys=True,
            )
        )
        return 3

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
