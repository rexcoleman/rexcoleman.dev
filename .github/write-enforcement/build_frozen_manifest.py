#!/usr/bin/env python3
"""Build (never sign) the later frozen bundle manifest from reviewed commits."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import types
from pathlib import Path

from member_contract import (
    AUTHORITY_GENERATION,
    EXPECTED_EMITTER_RUNTIME_INSTALLATIONS,
    EXPECTED_MEMBERS,
    GENERATION_MANIFEST_NAME,
    REQUIRED_MEMBER_CLASSES,
    RULESET_ID,
    STAGED_NONPRODUCTION_MANIFEST_SCHEMA,
    group_member_contract,
    grouped_members,
    normalize_ruleset,
    staged_nonproduction_members,
)

MEMBERS = grouped_members()
AUTHORITATIVE_REPOSITORY_SLUGS = (
    ("research_enforcement_activation", "research_enforcement_activation"),
    ("govML", "govML"),
    ("Moonshots_Career_Thesis_v2", "Moonshots_Career_Thesis"),
    ("newsletter", "newsletter"),
    ("rexcoleman.dev", "rexcoleman.dev"),
)


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


def open_frozen_population(
    roots: dict[str, Path],
    commits: dict[str, str],
    expected_members=None,
) -> dict[str, bytes]:
    """Open every declared member at its selected immutable repository ref."""
    contract = expected_members or EXPECTED_MEMBERS
    repositories = set(group_member_contract(contract))
    root_names = set(roots)
    commit_names = set(commits)
    if root_names != repositories or commit_names != repositories:
        raise ValueError(
            "frozen population repository mapping invalid:"
            f"roots_missing={sorted(repositories - root_names)}:"
            f"roots_extra={sorted(root_names - repositories)}:"
            f"commits_missing={sorted(repositories - commit_names)}:"
            f"commits_extra={sorted(commit_names - repositories)}"
        )
    loaded = {}
    for member_id, (repository, path) in sorted(contract.items()):
        commit = commits[repository]
        if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise ValueError(
                f"frozen population selected commit invalid:{repository}:{commit!r}"
            )
        try:
            loaded[member_id] = committed_member_bytes(
                roots[repository], commit, path
            )
        except ValueError as exc:
            raise ValueError(
                "frozen population member unavailable:"
                f"{member_id}:{repository}@{commit}:{path}:{exc}"
            ) from None
    if set(loaded) != set(contract):
        raise ValueError("frozen population member set incomplete")
    return loaded


def authoritative_repository_slug(repository: str, expected_members=None) -> str:
    """Resolve one logical contract name through the closed remote mapping."""
    expected = set(group_member_contract(expected_members or EXPECTED_MEMBERS))
    logical_names = [logical for logical, _slug in AUTHORITATIVE_REPOSITORY_SLUGS]
    slugs = [slug for _logical, slug in AUTHORITATIVE_REPOSITORY_SLUGS]
    duplicate_logical = sorted({name for name in logical_names
                                if logical_names.count(name) > 1})
    duplicate_slugs = sorted({slug for slug in slugs if slugs.count(slug) > 1})
    observed = set(logical_names)
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    invalid_slugs = sorted(
        repr(slug) for slug in slugs
        if not isinstance(slug, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]+", slug) is None
    )
    if duplicate_logical or duplicate_slugs or missing or extra or invalid_slugs:
        raise ValueError(
            "authoritative repository mapping invalid:"
            f"missing={missing}:extra={extra}:"
            f"duplicate_logical={duplicate_logical}:"
            f"duplicate_slugs={duplicate_slugs}:invalid_slugs={invalid_slugs}"
        )
    if repository not in expected:
        raise ValueError(f"unknown logical repository: {repository}")
    return dict(AUTHORITATIVE_REPOSITORY_SLUGS)[repository]


def verify_remote_reachability(
    repository: str, commit: str, expected_members=None
) -> None:
    """Derive reachability from the authoritative GitHub commit endpoint."""
    slug = authoritative_repository_slug(repository, expected_members)
    result = subprocess.run(
        ["gh", "api", f"repos/rexcoleman/{slug}/commits/{commit}",
         "--jq", ".sha"],
        check=False, capture_output=True, text=True, timeout=30,
    )
    observed = result.stdout.strip()
    if result.returncode or observed != commit:
        raise ValueError(
            f"authoritative remote member unreachable: "
            f"{repository}[rexcoleman/{slug}]@{commit};"
            f"raw_exit={result.returncode};observed={observed!r}"
        )


def validate_installed_population(
    govml_root: Path, commit: str, expected_members=None
) -> None:
    module_relative = (
        "templates/build/enforcement/managed_enforcement_inventory.py"
    )
    module_path = govml_root / module_relative
    module_raw = committed_member_bytes(govml_root, commit, module_relative)
    module = types.ModuleType("managed_inventory")
    module.__file__ = str(module_path)
    exec(compile(module_raw, str(module_path), "exec"), module.__dict__)
    expected = EXPECTED_EMITTER_RUNTIME_INSTALLATIONS
    observed_names = set(module.emitter_runtime_names())
    expected_names = {
        destination.rsplit("/", 1)[-1] for destination in expected
    }
    if observed_names != expected_names:
        raise ValueError(
            "installed emitter runtime set mismatch:"
            f"missing={sorted(expected_names - observed_names)}:"
            f"extra={sorted(observed_names - expected_names)}"
        )
    installed = {
        ("govML", f"templates/build/enforcement/{path}")
        for path in module.all_installed_sources()
    }
    contract = expected_members or EXPECTED_MEMBERS
    frozen = {
        value for value in contract.values()
        if value[0] == "govML"
    }
    frozen_subjects = set(contract.values())
    for destination, subjects in sorted(expected.items()):
        authoring = tuple(subjects["authoring"])
        installed_subject = tuple(subjects["installed"])
        if authoring not in frozen_subjects or installed_subject not in frozen_subjects:
            raise ValueError(
                f"unsigned installed runtime path: {destination}:"
                f"authoring={authoring}:installed={installed_subject}"
            )
        try:
            authoring_raw = committed_member_bytes(
                govml_root, commit, authoring[1]
            )
            installed_raw = committed_member_bytes(
                govml_root, commit, installed_subject[1]
            )
        except ValueError as exc:
            raise ValueError(
                f"missing installed runtime path: {destination}:{exc}"
            ) from None
        if authoring_raw != installed_raw:
            raise ValueError(
                f"installed runtime digest divergence: {destination}:"
                f"authoring_sha256={sha(authoring_raw)}:"
                f"installed_sha256={sha(installed_raw)}"
            )
    missing = sorted(installed - frozen)
    if missing:
        raise ValueError(f"unsigned installed members: {missing}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ruleset-json", type=Path, required=True)
    parser.add_argument("--staged-nonproduction", action="store_true")
    for name in MEMBERS:
        slug = name.lower().replace("_", "-").replace(".", "-")
        parser.add_argument("--root-" + slug, dest="root_" + name.lower().replace(".", "_"),
                            type=Path, required=True)
    args = parser.parse_args()
    expected_members = (
        staged_nonproduction_members()
        if args.staged_nonproduction
        else EXPECTED_MEMBERS
    )
    synthetic_contract = (
        not args.staged_nonproduction and MEMBERS != grouped_members()
    )
    if synthetic_contract:
        # Unit fixtures may replace the closed production map with a synthetic
        # repository contract; production and staging never enter this branch.
        members = MEMBERS
        expected_members = {
            member_id: (repository, path)
            for repository, rows in MEMBERS.items()
            for member_id, path in rows
        }
    else:
        members = group_member_contract(expected_members)
    if args.output.name != GENERATION_MANIFEST_NAME:
        raise ValueError(
            f"generation-{AUTHORITY_GENERATION} manifest path must end in "
            f"{GENERATION_MANIFEST_NAME}"
        )
    roots = {name: getattr(args, "root_" + name.lower().replace(".", "_")) for name in members}
    commits = {repository: head(root) for repository, root in roots.items()}
    loaded = open_frozen_population(roots, commits, expected_members)
    if "govML" in roots:
        validate_installed_population(
            roots["govML"], commits["govML"], expected_members
        )
    subjects = set(commits.items())
    # Unit fixtures use a synthetic repository name.  Production's closed
    # contract contains only the five authoritative repositories.
    if not synthetic_contract:
        for repository, commit in sorted(subjects):
            verify_remote_reachability(repository, commit, expected_members)
        for repository, specs in sorted(members.items()):
            commit = head(roots[repository])
            for member_id, path in specs:
                print(
                    f"REMOTE_REACHABLE member_id={member_id} "
                    f"repository={repository} commit={commit} path={path}"
                )
    rows = []
    for repository, specs in members.items():
        commit = commits[repository]
        for member_id, path in specs:
            raw = loaded[member_id]
            rows.append({"member_id": member_id, "repository": repository, "commit": commit,
                         "path": path, "sha256": sha(raw), "byte_length": len(raw)})
    ruleset = json.loads(args.ruleset_json.read_bytes())
    normalized = normalize_ruleset(ruleset)
    manifest = {
        "schema_version": (
            STAGED_NONPRODUCTION_MANIFEST_SCHEMA
            if args.staged_nonproduction
            else "rea.write.enforcement-bundle-manifest.v1"
        ),
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
