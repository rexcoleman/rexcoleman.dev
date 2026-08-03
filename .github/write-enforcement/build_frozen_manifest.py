#!/usr/bin/env python3
"""Build (never sign) the later frozen bundle manifest from reviewed commits."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

from member_contract import (
    AUTHORITY_GENERATION,
    EXPECTED_MEMBERS,
    GENERATION_MANIFEST_NAME,
    REQUIRED_MEMBER_CLASSES,
    RULESET_ID,
    grouped_members,
    normalize_ruleset,
)

MEMBERS = grouped_members()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def head(root: Path) -> str:
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()


def committed_member_bytes(root: Path, commit: str, path: str) -> bytes:
    """Read one bound member from HEAD, refusing a dirty bound worktree path."""
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"member path: {path}")
    committed = subprocess.run(
        ["git", "-C", str(root), "show", f"{commit}:{path}"],
        check=False,
        capture_output=True,
    )
    if committed.returncode:
        raise ValueError(f"member unavailable: {root.name}:{path}")
    clean = subprocess.run(
        ["git", "-C", str(root), "diff", "--quiet", commit, "--", path],
        check=False,
    )
    if clean.returncode:
        raise ValueError(f"dirty bound member: {root.name}:{path}")
    return committed.stdout


def verify_remote_reachability(repository: str, commit: str) -> None:
    """Derive reachability from the authoritative GitHub commit endpoint."""
    result = subprocess.run(
        ["gh", "api", f"repos/rexcoleman/{repository}/commits/{commit}",
         "--jq", ".sha"],
        check=False, capture_output=True, text=True, timeout=30,
    )
    observed = result.stdout.strip()
    if result.returncode or observed != commit:
        raise ValueError(
            f"authoritative remote member unreachable: {repository}@{commit};"
            f"raw_exit={result.returncode};observed={observed!r}"
        )


def validate_installed_population(govml_root: Path) -> None:
    module_path = (
        govml_root / "templates/build/enforcement/managed_enforcement_inventory.py"
    )
    spec = importlib.util.spec_from_file_location("managed_inventory", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("managed enforcement inventory unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    installed = {
        ("govML", f"templates/build/enforcement/{path}")
        for path in module.all_installed_sources()
    }
    frozen = {
        value for value in EXPECTED_MEMBERS.values()
        if value[0] == "govML"
    }
    missing = sorted(installed - frozen)
    if missing:
        raise ValueError(f"unsigned installed members: {missing}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ruleset-json", type=Path, required=True)
    for name in MEMBERS:
        slug = name.lower().replace("_", "-").replace(".", "-")
        parser.add_argument("--root-" + slug, dest="root_" + name.lower().replace(".", "_"),
                            type=Path, required=True)
    args = parser.parse_args()
    if args.output.name != GENERATION_MANIFEST_NAME:
        raise ValueError(
            f"generation-{AUTHORITY_GENERATION} manifest path must end in "
            f"{GENERATION_MANIFEST_NAME}"
        )
    roots = {name: getattr(args, "root_" + name.lower().replace(".", "_")) for name in MEMBERS}
    if "govML" in roots:
        validate_installed_population(roots["govML"])
    subjects = {(repository, head(roots[repository])) for repository in MEMBERS}
    # Unit fixtures use a synthetic repository name.  Production's closed
    # contract contains only the five authoritative repositories.
    if set(MEMBERS) == set(grouped_members()):
        for repository, commit in sorted(subjects):
            verify_remote_reachability(repository, commit)
        for repository, specs in sorted(MEMBERS.items()):
            commit = head(roots[repository])
            for member_id, path in specs:
                print(
                    f"REMOTE_REACHABLE member_id={member_id} "
                    f"repository={repository} commit={commit} path={path}"
                )
    rows = []
    for repository, specs in MEMBERS.items():
        commit = head(roots[repository])
        for member_id, path in specs:
            raw = committed_member_bytes(roots[repository], commit, path)
            rows.append({"member_id": member_id, "repository": repository, "commit": commit,
                         "path": path, "sha256": sha(raw), "byte_length": len(raw)})
    ruleset = json.loads(args.ruleset_json.read_bytes())
    normalized = normalize_ruleset(ruleset)
    manifest = {
        "schema_version": "rea.write.enforcement-bundle-manifest.v1",
        "authority_generation": AUTHORITY_GENERATION,
        "ruleset_id": RULESET_ID,
        "normalized_ruleset_sha256": sha(canonical(normalized)),
        "required_member_classes": list(REQUIRED_MEMBER_CLASSES),
        "members": rows,
    }
    manifest["manifest_digest"] = sha(canonical(manifest))
    args.output.write_bytes(canonical(manifest) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
