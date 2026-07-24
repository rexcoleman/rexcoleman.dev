#!/usr/bin/env python3
"""Build (never sign) the later frozen bundle manifest from reviewed commits."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from member_contract import (
    AUTHORITY_GENERATION,
    GENERATION_MANIFEST_NAME,
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
        "required_member_classes": [
            "boundary_gate", "resolver", "readiness_consumer", "live_emitter_binding",
            "master_runner_binding", "project_runner_binding", "scaffold_installer",
            "remote_workflow", "remote_ruleset", "claim_policy", "profile_registry",
            "trusted_public_key",
        ],
        "members": rows,
    }
    manifest["manifest_digest"] = sha(canonical(manifest))
    args.output.write_bytes(canonical(manifest) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
