#!/usr/bin/env python3
"""Build (never sign) the later frozen bundle manifest from reviewed commits."""

from __future__ import annotations

import argparse
import ast
import base64
import gzip
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
    EXACT_MEMBER_BYTE_ALIASES,
    GENERATION_MANIFEST_NAME,
    HISTORICAL_AUTHORITY_GENERATION,
    HISTORICAL_GENERATION_MANIFEST_NAME,
    REQUIRED_MEMBER_CLASSES,
    RULESET_ID,
    PACKAGED_BUILD_PROFILE_GATE_SOURCES,
    STAGED_NONPRODUCTION_MANIFEST_SCHEMA,
    authenticated_head_rebase_successor_members,
    group_member_contract,
    grouped_members,
    hosted_principal_successor_members,
    normalize_ruleset,
    staged_nonproduction_members,
    successor_members,
    validate_managed_live_member_aliases,
    validate_hosted_principal_member_ids,
    validate_authenticated_head_rebase_member_ids,
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


def committed_member_mode(root: Path, commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-tree", commit, "--", path],
        check=False,
        capture_output=True,
        text=True,
    )
    rows = [row for row in result.stdout.splitlines() if row]
    if result.returncode or len(rows) != 1:
        raise ValueError(f"member mode unavailable: {root.name}:{path}")
    match = re.fullmatch(r"(100644|100755) blob [0-9a-f]{40}\t(.+)", rows[0])
    if match is None or match.group(2) != path:
        raise ValueError(f"member mode invalid: {root.name}:{path}")
    return match.group(1)


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
    source_modes = {}
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
            source_modes[member_id] = committed_member_mode(
                roots[repository], commit, path
            )
        except ValueError as exc:
            raise ValueError(
                "frozen population member unavailable:"
                f"{member_id}:{repository}@{commit}:{path}:{exc}"
            ) from None
    if set(loaded) != set(contract):
        raise ValueError("frozen population member set incomplete")
    validate_exact_member_byte_aliases(loaded, contract)
    validate_managed_live_member_aliases(loaded, source_modes, contract)
    return loaded


def validate_exact_member_byte_aliases(
    loaded: dict[str, bytes], contract=None
) -> None:
    expected = contract or EXPECTED_MEMBERS
    for authoring_id, runtime_id in EXACT_MEMBER_BYTE_ALIASES:
        present = {authoring_id, runtime_id} & set(expected)
        if not present:
            continue
        if present != {authoring_id, runtime_id}:
            raise ValueError("exact member byte alias absent from contract")
        if expected[authoring_id] == expected[runtime_id]:
            raise ValueError("exact member byte aliases collapse onto one subject")
        if loaded.get(authoring_id) != loaded.get(runtime_id):
            raise ValueError(
                f"exact member byte alias divergence:{authoring_id}:{runtime_id}"
            )


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
        if installed_subject not in frozen_subjects:
            raise ValueError(
                f"unsigned installed runtime path: {destination}:"
                f"installed={installed_subject}"
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

    bundle_relative = (
        "templates/build/enforcement/installed_build_profile_gate_bundle.py"
    )
    bundle_raw = committed_member_bytes(govml_root, commit, bundle_relative)
    tree = subprocess.run(
        ["git", "-C", str(govml_root), "ls-tree", commit, bundle_relative],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    if not tree or tree[0] != "100755" or tree[1] != "blob":
        raise ValueError("installed build-profile bundle mode/type invalid")
    try:
        syntax = ast.parse(bundle_raw.decode("ascii"), bundle_relative)
        assignment = next(
            node for node in syntax.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "ENTRIES"
                    for target in node.targets)
        )
        entries = ast.literal_eval(assignment.value)
    except (UnicodeDecodeError, StopIteration, SyntaxError, ValueError) as exc:
        raise ValueError(
            f"installed build-profile bundle metadata invalid:{type(exc).__name__}"
        ) from None
    expected_ids = set(PACKAGED_BUILD_PROFILE_GATE_SOURCES)
    if not isinstance(entries, dict) or set(entries) != expected_ids:
        raise ValueError("installed build-profile bundle logical population invalid")
    seen_paths = set()
    for logical_id, expected_source in sorted(
        PACKAGED_BUILD_PROFILE_GATE_SOURCES.items()
    ):
        repository, relative, expected_mode = expected_source
        row = entries[logical_id]
        if not isinstance(row, dict) or set(row) != {
            "path", "mode", "sha256", "byte_length", "gzip_base64",
        }:
            raise ValueError(f"installed build-profile bundle row invalid:{logical_id}")
        path = Path(row["path"]) if isinstance(row.get("path"), str) else Path("/")
        if (
            repository != "govML" or path.is_absolute() or ".." in path.parts
            or path.as_posix() != relative or relative in seen_paths
            or row.get("mode") != expected_mode
        ):
            raise ValueError(f"installed build-profile bundle path/mode invalid:{logical_id}")
        source_tree = subprocess.run(
            ["git", "-C", str(govml_root), "ls-tree", commit, relative],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        if not source_tree or source_tree[0] != "100755" or source_tree[1] != "blob":
            raise ValueError(f"installed build-profile source mode/type invalid:{logical_id}")
        source_raw = committed_member_bytes(govml_root, commit, relative)
        try:
            payload = gzip.decompress(base64.b64decode(
                row["gzip_base64"].encode("ascii"), validate=True,
            ))
        except Exception as exc:
            raise ValueError(
                f"installed build-profile payload invalid:{logical_id}:{type(exc).__name__}"
            ) from None
        if (
            payload != source_raw or row.get("sha256") != sha(source_raw)
            or row.get("byte_length") != len(source_raw)
        ):
            raise ValueError(f"installed build-profile payload divergence:{logical_id}")
        seen_paths.add(relative)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ruleset-json", type=Path, required=True)
    parser.add_argument("--staged-nonproduction", action="store_true")
    parser.add_argument("--successor-ci-materialization", action="store_true")
    parser.add_argument("--hosted-external-judge-principal", action="store_true")
    parser.add_argument("--authenticated-head-rebase-successor", action="store_true")
    for name in MEMBERS:
        slug = name.lower().replace("_", "-").replace(".", "-")
        parser.add_argument("--root-" + slug, dest="root_" + name.lower().replace(".", "_"),
                            type=Path, required=True)
    args = parser.parse_args()
    selected_contracts = sum((
        args.staged_nonproduction,
        args.successor_ci_materialization,
        args.hosted_external_judge_principal,
        args.authenticated_head_rebase_successor,
    ))
    if selected_contracts > 1:
        raise ValueError("staged and successor contracts are mutually exclusive")
    expected_members = (
        staged_nonproduction_members() if args.staged_nonproduction
        else authenticated_head_rebase_successor_members()
        if args.authenticated_head_rebase_successor
        else hosted_principal_successor_members()
        if args.hosted_external_judge_principal
        else successor_members() if args.successor_ci_materialization
        else EXPECTED_MEMBERS
    )
    if args.hosted_external_judge_principal:
        validate_hosted_principal_member_ids(expected_members)
    if args.authenticated_head_rebase_successor:
        validate_authenticated_head_rebase_member_ids(expected_members)
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
    # A staged artifact rehearses the current active successor population.
    # Treating it as historical generation 4 allowed release additions to be
    # absent from the rehearsal even while the installed-population check saw
    # their bytes and refused.  Staging differs in trust domain, not member
    # generation.
    active_contract = (
        args.successor_ci_materialization
        or args.hosted_external_judge_principal
        or args.authenticated_head_rebase_successor
        or args.staged_nonproduction
    )
    authority_generation = (
        AUTHORITY_GENERATION if active_contract
        else HISTORICAL_AUTHORITY_GENERATION
    )
    manifest_name = (
        GENERATION_MANIFEST_NAME if active_contract
        else HISTORICAL_GENERATION_MANIFEST_NAME
    )
    if args.output.name != manifest_name:
        raise ValueError(
            f"generation-{authority_generation} manifest path must end in "
            f"{manifest_name}"
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
        "authority_generation": authority_generation,
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
