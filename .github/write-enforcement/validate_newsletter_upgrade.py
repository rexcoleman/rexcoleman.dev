#!/usr/bin/env python3
"""Validate the newsletter bootstrap PR without executing candidate code."""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import sys
from pathlib import Path


CHECKOUT_PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"
TARGET_AUTHORITY_PIN = "179b7d30a5904fbc2cde9e3bee0bfe3771114feb"
LEGACY_WORKFLOW = Path(".github/workflows/newsletter-integrity.yml")
UPGRADE_WORKFLOW = Path(".github/workflows/newsletter-upgrade-integrity.yml")
CAPABILITY = Path(".github/integrity/newsletter/bootstrap-capability.json")
ALLOWED_CONTROL_PATHS = {
    str(LEGACY_WORKFLOW), str(UPGRADE_WORKFLOW), str(CAPABILITY),
}


class Refusal(RuntimeError):
    pass


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise Refusal(f"GIT_REFUSED:{args}:{detail}")
    return result.stdout


def regular_bytes(repo: Path, relative: Path) -> bytes:
    path = repo / relative
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise Refusal(f"CONTROL_ABSENT:{relative}") from exc
    if not stat.S_ISREG(mode):
        raise Refusal(f"CONTROL_NONREGULAR:{relative}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise Refusal(f"CONTROL_UNREADABLE:{relative}") from exc


def workflow_text(repo: Path, relative: Path) -> str:
    try:
        raw = regular_bytes(repo, relative).decode("utf-8")
    except UnicodeError as exc:
        raise Refusal(f"WORKFLOW_UTF8:{relative}") from exc
    if "\r" in raw or "\t" in raw:
        raise Refusal(f"WORKFLOW_NONCANONICAL_WHITESPACE:{relative}")
    if re.search(r"(?m)^[^#\n]*(?:<<:|&[A-Za-z0-9_-]+|\*[A-Za-z0-9_-]+)", raw):
        raise Refusal(f"WORKFLOW_YAML_INDIRECTION:{relative}")
    return raw


def event_names(raw: str, relative: Path) -> set[str]:
    lines = raw.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "on:"]
    if len(starts) != 1:
        raise Refusal(f"WORKFLOW_EVENT_SHAPE:{relative}")
    names: set[str] = set()
    for line in lines[starts[0] + 1:]:
        if line and not line.startswith(" "):
            break
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):(?:.*)?", line)
        if match:
            names.add(match.group(1))
    if not names:
        raise Refusal(f"WORKFLOW_EVENT_EMPTY:{relative}")
    return names


def permission_maps(raw: str, relative: Path) -> list[dict[str, str]]:
    lines = raw.splitlines()
    maps: list[dict[str, str]] = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"( *)permissions:[ ]*(.*)", line)
        if not match:
            continue
        indent = len(match.group(1))
        if match.group(2):
            raise Refusal(f"WORKFLOW_PERMISSION_SCALAR:{relative}")
        values: dict[str, str] = {}
        for child in lines[index + 1:]:
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            child_indent = len(child) - len(child.lstrip(" "))
            if child_indent <= indent:
                break
            item = re.fullmatch(
                rf" {{{indent + 2}}}([A-Za-z0-9_-]+):[ ]*(read|none)", child
            )
            if not item or item.group(1) in values:
                raise Refusal(f"WORKFLOW_PERMISSION_MAPPING:{relative}")
            values[item.group(1)] = item.group(2)
        if not values:
            raise Refusal(f"WORKFLOW_PERMISSION_EMPTY:{relative}")
        maps.append(values)
    if not maps:
        raise Refusal(f"WORKFLOW_PERMISSION_ABSENT:{relative}")
    return maps


def reject_unsafe_permissions(raw: str, relative: Path) -> None:
    if re.search(
        r"(?im)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$"
        r"|^\s*[A-Za-z0-9_-]+\s*:\s*write\s*(?:#.*)?$"
        r"|^\s*permissions\s*:\s*\{[^\n}]*\bwrite(?:-all)?\b",
        raw,
    ):
        raise Refusal(f"WORKFLOW_WRITE_PERMISSION:{relative}")


def authority_commit(authority_root: Path) -> str:
    commit = git(authority_root, "rev-parse", "HEAD").decode().strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise Refusal("AUTHORITY_COMMIT_SHAPE")
    script = Path(__file__).resolve()
    try:
        script.relative_to(authority_root.resolve(strict=True))
    except ValueError as exc:
        raise Refusal("AUTHORITY_SCRIPT_OUTSIDE_CHECKOUT") from exc
    return commit


def expected_upgrade_workflow(commit: str) -> str:
    return f"""name: newsletter-upgrade-integrity

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  newsletter-pr-head-upgrade:
    name: newsletter-pr-head-upgrade
    runs-on: ubuntu-24.04
    timeout-minutes: 8
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v4.2.2
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
          path: candidate
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/checkout@{CHECKOUT_PIN} # v4.2.2
        with:
          repository: rexcoleman/rexcoleman.dev
          ref: {commit}
          path: authority
          fetch-depth: 1
          persist-credentials: false
      - name: Validate exact upgrade head without executing candidate code
        env:
          EVENT_SHA: ${{{{ github.event.pull_request.head.sha }}}}
          BASE_SHA: ${{{{ github.event.pull_request.base.sha }}}}
          REPOSITORY: ${{{{ github.event.pull_request.head.repo.full_name }}}}
        run: |
          set -euo pipefail
          test "$(git -C candidate rev-parse HEAD)" = "$EVENT_SHA"
          test "$(git -C authority rev-parse HEAD)" = "{commit}"
          python3 -I authority/.github/write-enforcement/validate_newsletter_upgrade.py \\
            --repo candidate --repository "$REPOSITORY" \\
            --base-sha "$BASE_SHA" --event-sha "$EVENT_SHA" \\
            --authority-root authority
          echo 'CONTROL_UPGRADE_PASS candidate_code_executed=false mutation_authorized=false secrets=absent writes=absent'
"""


def expected_capability(commit: str) -> bytes:
    value = {
        "schema_version": "rea.newsletter.control-bootstrap-capability.v1",
        "repository": "rexcoleman/newsletter",
        "candidate_event_source": str(UPGRADE_WORKFLOW),
        "candidate_event": "pull_request",
        "candidate_self_bootstraps": True,
        "validator_authority": (
            "rexcoleman/rexcoleman.dev@" + commit
            + ":.github/write-enforcement/validate_newsletter_upgrade.py"
        ),
        "candidate_code_executed": False,
        "secrets_available": False,
        "mutation_authorized": False,
    }
    return (json.dumps(value, indent=2) + "\n").encode()


def validate_upgrade_workflow(raw: str, commit: str) -> None:
    if raw != expected_upgrade_workflow(commit):
        raise Refusal("UPGRADE_WORKFLOW_BYTES_NOT_APPROVED")
    reject_unsafe_permissions(raw, UPGRADE_WORKFLOW)
    if event_names(raw, UPGRADE_WORKFLOW) != {"pull_request"}:
        raise Refusal("UPGRADE_EVENT_NOT_PULL_REQUEST_ONLY")
    if permission_maps(raw, UPGRADE_WORKFLOW) != [{"contents": "read"}]:
        raise Refusal("UPGRADE_PERMISSIONS_NOT_READ_ONLY")
    uses = re.findall(r"(?m)^\s*- uses:\s*(\S+)\s*(?:#.*)?$", raw)
    if uses != [f"actions/checkout@{CHECKOUT_PIN}"] * 2:
        raise Refusal("UPGRADE_ACTION_PIN_SET")
    if raw.count("persist-credentials: false") != 2:
        raise Refusal("UPGRADE_CHECKOUT_CREDENTIALS")
    if "secrets." in raw or "pull_request_target:" in raw:
        raise Refusal("UPGRADE_PRIVILEGED_INPUT")
    if (
        f"repository: rexcoleman/rexcoleman.dev" not in raw
        or f"ref: {commit}" not in raw
        or "python3 -I authority/.github/write-enforcement/validate_newsletter_upgrade.py"
        not in raw
        or "candidate_code_executed=false" not in raw
    ):
        raise Refusal("UPGRADE_AUTHORITY_BOUNDARY")


def validate_legacy_workflow(raw: str) -> None:
    reject_unsafe_permissions(raw, LEGACY_WORKFLOW)
    if event_names(raw, LEGACY_WORKFLOW) != {"pull_request_target"}:
        raise Refusal("LEGACY_EVENT_NOT_PULL_REQUEST_TARGET_ONLY")
    if permission_maps(raw, LEGACY_WORKFLOW) != [
        {"contents": "read"}, {"contents": "read"}
    ]:
        raise Refusal("LEGACY_PERMISSIONS_NOT_READ_ONLY")
    uses = re.findall(r"(?m)^\s+uses:\s*(\S+)\s*(?:#.*)?$", raw)
    expected = (
        "rexcoleman/Moonshots_Career_Thesis/.github/workflows/"
        f"newsletter-integrity-authority.yml@{TARGET_AUTHORITY_PIN}"
    )
    if uses != [expected]:
        raise Refusal("LEGACY_REUSABLE_WORKFLOW_PIN")
    if re.search(r"(?m)^\s*(?:steps|run):", raw) or "actions/checkout" in raw:
        raise Refusal("LEGACY_CANDIDATE_EXECUTION")
    expected_secret_lines = {
        "REA_WEA_READ_TOKEN: ${{ secrets.REA_WEA_READ_TOKEN }}",
        "REA_BUNDLE_READ_TOKEN: ${{ secrets.REA_BUNDLE_READ_TOKEN }}",
    }
    observed = {line.strip() for line in raw.splitlines() if "secrets." in line}
    if observed != expected_secret_lines:
        raise Refusal("LEGACY_SECRET_SCOPE")


def validate(
    repo: Path,
    repository: str,
    base_sha: str,
    event_sha: str,
    authority_root: Path,
) -> dict:
    repo = repo.resolve(strict=True)
    authority_root = authority_root.resolve(strict=True)
    commit = authority_commit(authority_root)
    if repository != "rexcoleman/newsletter":
        raise Refusal("REPOSITORY_IDENTITY")
    if git(repo, "rev-parse", "HEAD").decode().strip() != event_sha:
        raise Refusal("CHECKOUT_SHA_MISMATCH")
    changed_raw = git(
        repo, "diff", "--name-only", "-z", "--no-renames", base_sha, event_sha
    )
    try:
        changed = [path for path in changed_raw.decode("utf-8").split("\0") if path]
    except UnicodeError as exc:
        raise Refusal("CHANGED_PATH_UTF8") from exc
    observed = set(changed)
    if observed != ALLOWED_CONTROL_PATHS:
        raise Refusal(
            "CONTROL_CHANGE_SET:"
            f"missing={sorted(ALLOWED_CONTROL_PATHS - observed)}:"
            f"extra={sorted(observed - ALLOWED_CONTROL_PATHS)}"
        )
    upgrade = workflow_text(repo, UPGRADE_WORKFLOW)
    validate_upgrade_workflow(upgrade, commit)
    validate_legacy_workflow(workflow_text(repo, LEGACY_WORKFLOW))
    if regular_bytes(repo, CAPABILITY) != expected_capability(commit):
        raise Refusal("BOOTSTRAP_CAPABILITY_BYTES_NOT_APPROVED")
    return {
        "schema_version": "rea.newsletter.control-upgrade-validation.v2",
        "verdict": "PASS",
        "raw_exit": 0,
        "repository": repository,
        "base_sha": base_sha,
        "event_sha": event_sha,
        "authority_commit": commit,
        "changed": sorted(changed),
        "candidate_code_executed": False,
        "mutation_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--event-sha", required=True)
    parser.add_argument("--authority-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(
            args.repo, args.repository, args.base_sha, args.event_sha,
            args.authority_root,
        ), sort_keys=True))
        return 0
    except (OSError, UnicodeError, Refusal) as exc:
        print(json.dumps({
            "schema_version": "rea.newsletter.control-upgrade-validation.v2",
            "verdict": "REFUSE", "raw_exit": 3, "reason": str(exc),
            "candidate_code_executed": False, "mutation_authorized": False,
        }, sort_keys=True), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
