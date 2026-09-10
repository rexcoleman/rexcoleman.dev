#!/usr/bin/env python3
"""Emit fail-closed evidence for the exact GitHub event commit."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


SCHEMA = "exact-commit-integrity.v1"
WORKFLOW = ".github/workflows/artifact-integrity.yml"
LOCAL_REPOSITORY = "rexcoleman.dev"
PROSE_BINDING_SCHEMA = "rea.prose-artifact-bindings.v1"
PROSE_BINDING_SUFFIX = ".prose-bindings.json"
HASH_TOKEN_RE = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{8})(?![0-9a-f])"
)


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


def changed_paths(root: Path) -> list[str]:
    parents = checked_git(root, "rev-list", "--parents", "-n", "1", "HEAD").split()
    if len(parents) > 1:
        raw = checked_git(root, "diff", "--name-only", parents[1], "HEAD")
    else:
        shallow = checked_git(root, "rev-parse", "--is-shallow-repository").strip()
        if shallow == "true":
            raise Refusal("CHANGESET_PARENT_UNAVAILABLE", "fetch at least depth 2")
        raw = checked_git(root, "ls-tree", "-r", "--name-only", "HEAD")
    return sorted({line for line in raw.splitlines() if line})


def is_handoff_markdown(path: str) -> bool:
    name = Path(path).name.upper()
    return path.endswith(".md") and (
        "HANDOFF" in name
        or "HANDBACK" in name
        or path.startswith("artifacts/codex_handbacks/")
    )


def _regular_tracked_path(root: Path, path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise Refusal("PROSE_LOCAL_PATH_INVALID", path)
    resolved = root / candidate
    if resolved.is_symlink() or not resolved.is_file():
        raise Refusal("PROSE_LOCAL_PATH_MISSING_OR_SYMLINK", path)
    line = checked_git(root, "ls-tree", "HEAD", "--", path).strip()
    if not line:
        raise Refusal("PROSE_LOCAL_PATH_NOT_TRACKED", path)
    metadata, recorded = line.split("\t", 1)
    mode, object_type, _blob = metadata.split(" ", 2)
    if recorded != path or object_type != "blob" or mode not in {"100644", "100755"}:
        raise Refusal(
            "PROSE_LOCAL_PATH_NOT_REGULAR_BLOB",
            {"path": path, "mode": mode, "object_type": object_type},
        )
    return resolved


def verify_prose_bindings(root: Path, paths: list[str]) -> dict[str, Any]:
    documents = [path for path in paths if is_handoff_markdown(path)]
    local_count = 0
    foreign_count = 0
    checked_documents: list[dict[str, Any]] = []

    for document in documents:
        document_path = _regular_tracked_path(root, document)
        raw = document_path.read_text(encoding="utf-8")
        observed = Counter(HASH_TOKEN_RE.findall(raw))
        manifest_rel = document + PROSE_BINDING_SUFFIX
        manifest_path = _regular_tracked_path(root, manifest_rel)
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise Refusal("PROSE_BINDING_MANIFEST_INVALID", str(exc)) from exc
        if not isinstance(manifest, dict) or manifest.get("schema_version") != PROSE_BINDING_SCHEMA:
            raise Refusal("PROSE_BINDING_SCHEMA_INVALID", manifest_rel)
        if manifest.get("document") != document:
            raise Refusal(
                "PROSE_BINDING_DOCUMENT_MISMATCH",
                {"manifest": manifest_rel, "expected": document, "observed": manifest.get("document")},
            )
        rows = manifest.get("tokens")
        if not isinstance(rows, list):
            raise Refusal("PROSE_BINDING_ROWS_INVALID", manifest_rel)

        declared: Counter[str] = Counter()
        seen: set[str] = set()
        document_local = 0
        document_foreign = 0
        for row in rows:
            if not isinstance(row, dict):
                raise Refusal("PROSE_BINDING_ROW_INVALID", row)
            token = row.get("token")
            occurrences = row.get("occurrences")
            if not isinstance(token, str) or not HASH_TOKEN_RE.fullmatch(token):
                raise Refusal("PROSE_BINDING_TOKEN_INVALID", token)
            if token in seen:
                raise Refusal("PROSE_BINDING_TOKEN_DUPLICATE", token)
            seen.add(token)
            if not isinstance(occurrences, int) or isinstance(occurrences, bool) or occurrences < 1:
                raise Refusal("PROSE_BINDING_OCCURRENCES_INVALID", row)
            declared[token] = occurrences

            bucket = row.get("bucket")
            kind = row.get("binding_kind")
            if bucket == "repo-local-artifact-binding":
                if kind == "path-sha256":
                    if len(token) != 64:
                        raise Refusal("PROSE_LOCAL_DIGEST_SHAPE_INVALID", token)
                    path = row.get("path")
                    if not isinstance(path, str):
                        raise Refusal("PROSE_LOCAL_PATH_INVALID", path)
                    local_path = _regular_tracked_path(root, path)
                    observed_sha = hashlib.sha256(local_path.read_bytes()).hexdigest()
                    if observed_sha != token:
                        raise Refusal(
                            "PROSE_LOCAL_DIGEST_MISMATCH",
                            {"path": path, "expected": token, "observed": observed_sha},
                        )
                elif kind == "git-commit":
                    if len(token) != 40 or row.get("repository") != LOCAL_REPOSITORY:
                        raise Refusal("PROSE_LOCAL_COMMIT_DECLARATION_INVALID", row)
                    object_type = checked_git(root, "cat-file", "-t", token).strip()
                    if object_type != "commit":
                        raise Refusal(
                            "PROSE_LOCAL_COMMIT_UNRESOLVED",
                            {"token": token, "object_type": object_type},
                        )
                else:
                    raise Refusal("PROSE_LOCAL_BINDING_KIND_INVALID", row)
                local_count += 1
                document_local += 1
            elif bucket == "foreign-object-citation":
                repository = row.get("repository")
                if (
                    kind not in {"git-commit", "run-digest"}
                    or not isinstance(repository, str)
                    or not repository.strip()
                    or repository == LOCAL_REPOSITORY
                ):
                    raise Refusal("PROSE_FOREIGN_CITATION_INVALID", row)
                if kind == "git-commit" and len(token) not in {8, 40}:
                    raise Refusal("PROSE_FOREIGN_COMMIT_SHAPE_INVALID", row)
                if kind == "run-digest" and len(token) != 64:
                    raise Refusal("PROSE_FOREIGN_RUN_DIGEST_SHAPE_INVALID", row)
                # Ownership is explicit, but foreign truth is intentionally not
                # inferred from or resolved against this repository.
                foreign_count += 1
                document_foreign += 1
            else:
                raise Refusal("PROSE_BINDING_BUCKET_INVALID", row)

        if observed != declared:
            raise Refusal(
                "PROSE_HASH_TOKEN_CLASSIFICATION_INCOMPLETE",
                {"document": document, "observed": dict(observed), "declared": dict(declared)},
            )
        checked_documents.append(
            {
                "document": document,
                "foreign_citations": document_foreign,
                "local_bindings": document_local,
                "token_occurrences": sum(observed.values()),
                "unique_tokens": len(observed),
            }
        )

    return {
        "documents": checked_documents,
        "foreign_citation_count": foreign_count,
        "local_binding_count": local_count,
    }


def verify(root: Path, expected_head: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise Refusal("EXPECTED_HEAD_MALFORMED", expected_head)

    observed_head = checked_git(root, "rev-parse", "HEAD").strip()
    if observed_head != expected_head:
        raise Refusal(
            "EXPECTED_HEAD_MISMATCH",
            {"expected": expected_head, "observed": observed_head},
        )

    dirty = checked_git(root, "status", "--porcelain", "--untracked-files=all")
    if dirty:
        raise Refusal("EXACT_CHECKOUT_DIRTY", dirty.splitlines())

    workflow = root / WORKFLOW
    if workflow.is_symlink() or not workflow.is_file():
        raise Refusal("WORKFLOW_MISSING_OR_SYMLINK", WORKFLOW)

    tree_line = checked_git(root, "ls-tree", "HEAD", "--", WORKFLOW).strip()
    blob = checked_git(root, "hash-object", "--no-filters", "--", WORKFLOW).strip()
    if not tree_line:
        raise Refusal("WORKFLOW_NOT_TRACKED_AT_HEAD", WORKFLOW)
    metadata, recorded_path = tree_line.split("\t", 1)
    mode, object_type, expected_blob = metadata.split(" ", 2)
    if (
        recorded_path != WORKFLOW
        or mode != "100644"
        or object_type != "blob"
        or blob != expected_blob
    ):
        raise Refusal(
            "WORKFLOW_NOT_EXACT_HEAD_BLOB",
            {
                "recorded_path": recorded_path,
                "mode": mode,
                "object_type": object_type,
                "tree_blob": expected_blob,
                "worktree_blob": blob,
            },
        )

    tree_oid = checked_git(root, "rev-parse", "HEAD^{tree}").strip()
    listing = checked_git(root, "ls-tree", "-r", "--full-tree", "HEAD")
    changed = changed_paths(root)
    prose_bindings = verify_prose_bindings(root, changed)
    return {
        "authorized": True,
        "changed_path_count": len(changed),
        "changed_paths_sha256": hashlib.sha256(
            ("\n".join(sorted(changed)) + "\n").encode("utf-8")
        ).hexdigest(),
        "exact_head": observed_head,
        "outcome": "PASS",
        "prose_bindings": prose_bindings,
        "raw_exit": 0,
        "schema_version": SCHEMA,
        "tree_listing_sha256": hashlib.sha256(listing.encode("utf-8")).hexdigest(),
        "tree_oid": tree_oid,
        "workflow_blob": blob,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-dir", type=Path, default=Path.cwd())
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()

    try:
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
