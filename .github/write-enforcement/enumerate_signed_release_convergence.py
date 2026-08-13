#!/usr/bin/env python3
"""Reconcile the signed-release inventory by tree identity and semantic search."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], text=True, capture_output=True
    )
    if result.returncode:
        raise SystemExit(
            f"REFUSE(INVENTORY_GIT_FAILED): {root} {' '.join(args)}: "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def git_grep(root: Path, marker: str, ref: str, path: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), "grep", "-l", "-F", marker, ref, "--", path],
        text=True, capture_output=True,
    )
    if result.returncode not in (0, 1):
        raise SystemExit(
            f"REFUSE(INVENTORY_GREP_FAILED): {root} {path}: "
            f"{result.stderr.strip()}"
        )
    return result.returncode == 0 and bool(result.stdout.strip())


def validate_path(value: str) -> None:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise SystemExit(f"REFUSE(INVENTORY_PATH_INVALID): {value}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--repo", action="append", required=True,
                        help="repository_id=/clean/repository/root")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    value = json.loads(args.index.read_text(encoding="utf-8"))
    roots = {}
    for item in args.repo:
        repository, separator, raw_root = item.partition("=")
        if not separator or repository in roots:
            raise SystemExit("REFUSE(INVENTORY_REPOSITORY_ARGUMENT_INVALID)")
        roots[repository] = Path(raw_root).resolve()
    if set(roots) != set(value["repositories"]):
        raise SystemExit("REFUSE(INVENTORY_REPOSITORY_SET_MISMATCH)")

    results = []
    for entry in value["entries"]:
        root = roots[entry["repository"]]
        branch = value["repositories"][entry["repository"]]["default_branch"]
        ref = f"origin/{branch}"
        validate_path(entry["path"])
        tree = set(git(root, "ls-tree", "-r", "--name-only", ref).splitlines())
        prefix = entry["path"].rstrip("/")
        tree_found = prefix in tree or any(
            candidate.startswith(prefix + "/") for candidate in tree
        )
        semantic_found = False
        for marker in entry["markers"]:
            if git_grep(root, marker, ref, prefix):
                semantic_found = True
                break
        results.append({
            "id": entry["id"], "repository": entry["repository"],
            "session": entry["session"], "path": entry["path"],
            "tree_found": tree_found, "semantic_found": semantic_found,
        })
    tree_count = sum(row["tree_found"] for row in results)
    semantic_count = sum(row["semantic_found"] for row in results)
    denominator = max(tree_count, semantic_count, 1)
    delta_percent = abs(tree_count - semantic_count) * 100.0 / denominator
    report = {
        "schema_version": "rea.signed-release-convergence-enumeration.v1",
        "inventory_entries": len(results),
        "method_a_tree_identity_count": tree_count,
        "method_b_semantic_search_count": semantic_count,
        "delta_percent": round(delta_percent, 3),
        "within_five_percent": delta_percent <= 5.0,
        "rows": results,
    }
    rendered = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if tree_count != len(results) or semantic_count != len(results):
        return 2
    return 0 if delta_percent <= 5.0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
