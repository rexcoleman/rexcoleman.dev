#!/usr/bin/env python3
"""Validate the newsletter bootstrap PR without executing candidate code."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path


CHECKOUT_PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"
# Generation-5 authority. Moonshots e86a3c4e pins rexcoleman.dev
# verify-write-enforcement.yml@13f6efd2 (control_sha 13f6efd2), the
# generation-5 verifier that expects the 11-artifact PUBLIC_ARTIFACTS set
# including predecessor_write_enforcement_attestation.json. The superseded
# 71c78352 pinned the generation-4 verifier c68062541f, which refuses the
# live manifest with WEA_WRONG_BUNDLE: authority_generation.
TARGET_AUTHORITY_PIN = "e86a3c4ebeec7a1f5cf4cc3c3e849a978a096a54"
LEGACY_WORKFLOW = Path(".github/workflows/newsletter-integrity.yml")
UPGRADE_WORKFLOW = Path(".github/workflows/newsletter-upgrade-integrity.yml")
CAPABILITY = Path(".github/integrity/newsletter/bootstrap-capability.json")
TRANSITION_INDEX = Path(
    ".github/write-enforcement/newsletter_upgrade_transition_index.v1.json"
)
ALLOWED_CONTROL_PATHS = {
    str(LEGACY_WORKFLOW), str(UPGRADE_WORKFLOW), str(CAPABILITY),
}


class Refusal(RuntimeError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal(f"TRANSITION_INDEX_DUPLICATE_KEY:{key}")
        result[key] = value
    return result


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


def git_tree_bytes(repo: Path, commit: str, relative: str) -> bytes | None:
    raw = git(repo, "ls-tree", "-z", commit, "--", relative)
    if not raw:
        return None
    entries = [entry for entry in raw.split(b"\0") if entry]
    if len(entries) != 1:
        raise Refusal(f"REGISTERED_PATH_TREE_SHAPE:{relative}")
    try:
        metadata, observed_path = entries[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        decoded_path = observed_path.decode("utf-8")
    except (UnicodeError, ValueError) as exc:
        raise Refusal(f"REGISTERED_PATH_TREE_SHAPE:{relative}") from exc
    if decoded_path != relative:
        raise Refusal(f"REGISTERED_PATH_IDENTITY:{relative}")
    if mode != "100644" or object_type != "blob" or re.fullmatch(
        r"[0-9a-f]{40,64}", object_id
    ) is None:
        raise Refusal(f"REGISTERED_PATH_NOT_REGULAR:{relative}")
    return git(repo, "cat-file", "blob", object_id)


def load_transition_index(authority_root: Path) -> list[dict[str, object]]:
    raw = regular_bytes(authority_root, TRANSITION_INDEX)
    try:
        loaded = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Refusal("TRANSITION_INDEX_JSON") from exc
    if not isinstance(loaded, dict) or set(loaded) != {
        "schema_version", "repository", "transitions"
    }:
        raise Refusal("TRANSITION_INDEX_SHAPE")
    if loaded["schema_version"] != "rea.newsletter.control-transition-index.v1":
        raise Refusal("TRANSITION_INDEX_SCHEMA")
    if loaded["repository"] != "rexcoleman/newsletter":
        raise Refusal("TRANSITION_INDEX_REPOSITORY")
    transitions = loaded["transitions"]
    if not isinstance(transitions, list) or not transitions:
        raise Refusal("TRANSITION_INDEX_EMPTY")
    if raw != (json.dumps(loaded, indent=2) + "\n").encode():
        raise Refusal("TRANSITION_INDEX_NONCANONICAL")
    return transitions


def _validate_state_shape(
    transition_id: str, relative: str, side: str, state: object
) -> dict[str, object]:
    if not isinstance(state, dict) or set(state) not in (
        {"present"}, {"present", "byte_length", "sha256"}
    ):
        raise Refusal(f"TRANSITION_STATE_SHAPE:{transition_id}:{relative}:{side}")
    present = state.get("present")
    if not isinstance(present, bool):
        raise Refusal(f"TRANSITION_STATE_PRESENT:{transition_id}:{relative}:{side}")
    if present:
        if set(state) != {"present", "byte_length", "sha256"}:
            raise Refusal(f"TRANSITION_STATE_SHAPE:{transition_id}:{relative}:{side}")
        if not isinstance(state["byte_length"], int) or state["byte_length"] < 0:
            raise Refusal(f"TRANSITION_STATE_LENGTH:{transition_id}:{relative}:{side}")
        if not isinstance(state["sha256"], str) or re.fullmatch(
            r"[0-9a-f]{64}", state["sha256"]
        ) is None:
            raise Refusal(f"TRANSITION_STATE_DIGEST:{transition_id}:{relative}:{side}")
    elif set(state) != {"present"}:
        raise Refusal(f"TRANSITION_STATE_ABSENT_FIELDS:{transition_id}:{relative}:{side}")
    return state


def validate_registered_transition(
    repo: Path,
    base_sha: str,
    event_sha: str,
    authority_root: Path,
    changed: list[str],
    transitions: list[dict[str, object]] | None = None,
) -> str:
    observed_paths = sorted(changed)
    matched: list[str] = []
    seen_ids: set[str] = set()
    registered = (
        load_transition_index(authority_root) if transitions is None else transitions
    )
    byte_mismatches: list[str] = []
    for transition in registered:
        if not isinstance(transition, dict) or set(transition) != {
            "transition_id", "purpose", "files"
        }:
            raise Refusal("TRANSITION_ENTRY_SHAPE")
        transition_id = transition["transition_id"]
        if not isinstance(transition_id, str) or re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,95}", transition_id
        ) is None:
            raise Refusal("TRANSITION_ID_SHAPE")
        if transition_id in seen_ids:
            raise Refusal(f"TRANSITION_ID_DUPLICATE:{transition_id}")
        seen_ids.add(transition_id)
        if not isinstance(transition["purpose"], str) or not transition["purpose"]:
            raise Refusal(f"TRANSITION_PURPOSE:{transition_id}")
        files = transition["files"]
        if not isinstance(files, list) or not files:
            raise Refusal(f"TRANSITION_FILES_EMPTY:{transition_id}")
        paths: list[str] = []
        file_states: list[tuple[str, dict[str, object], dict[str, object]]] = []
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"path", "before", "after"}:
                raise Refusal(f"TRANSITION_FILE_SHAPE:{transition_id}")
            relative = entry["path"]
            if (
                not isinstance(relative, str)
                or not relative
                or Path(relative).is_absolute()
            ):
                raise Refusal(f"TRANSITION_PATH_SHAPE:{transition_id}")
            if (
                "\\" in relative
                or relative != Path(relative).as_posix()
                or Path(relative).parts
                != tuple(part for part in relative.split("/") if part)
            ):
                raise Refusal(f"TRANSITION_PATH_CANONICAL:{transition_id}:{relative}")
            if ".." in Path(relative).parts or relative in paths:
                raise Refusal(
                    "TRANSITION_PATH_DUPLICATE_OR_TRAVERSAL:"
                    f"{transition_id}:{relative}"
                )
            before = _validate_state_shape(
                transition_id, relative, "before", entry["before"]
            )
            after = _validate_state_shape(
                transition_id, relative, "after", entry["after"]
            )
            if before == after:
                raise Refusal(f"TRANSITION_FILE_UNCHANGED:{transition_id}:{relative}")
            paths.append(relative)
            file_states.append((relative, before, after))
        if paths != sorted(paths):
            raise Refusal(f"TRANSITION_PATH_ORDER:{transition_id}")
        if paths != observed_paths:
            continue
        mismatch = None
        for relative, before, after in file_states:
            for side, commit, expected in (
                ("before", base_sha, before), ("after", event_sha, after)
            ):
                raw = git_tree_bytes(repo, commit, relative)
                if bool(expected["present"]) != (raw is not None):
                    mismatch = (
                        f"REGISTERED_TRANSITION_{side.upper()}_PRESENCE:"
                        f"{transition_id}:{relative}"
                    )
                    break
                if raw is not None and (
                    len(raw) != expected["byte_length"]
                    or hashlib.sha256(raw).hexdigest() != expected["sha256"]
                ):
                    mismatch = (
                        f"REGISTERED_TRANSITION_{side.upper()}_BYTES:"
                        f"{transition_id}:{relative}"
                    )
                    break
            if mismatch is not None:
                break
        if mismatch is not None:
            byte_mismatches.append(mismatch)
            continue
        matched.append(transition_id)
    if not matched and byte_mismatches:
        raise Refusal(
            "REGISTERED_TRANSITION_NO_EXACT_MATCH:" + ":".join(byte_mismatches)
        )
    if len(matched) != 1:
        raise Refusal(
            "CONTROL_CHANGE_SET:"
            f"registered_transition_matches={matched}:changed={observed_paths}"
        )
    return matched[0]


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
    transition_id = None
    if observed == ALLOWED_CONTROL_PATHS:
        upgrade = workflow_text(repo, UPGRADE_WORKFLOW)
        validate_upgrade_workflow(upgrade, commit)
        validate_legacy_workflow(workflow_text(repo, LEGACY_WORKFLOW))
        if regular_bytes(repo, CAPABILITY) != expected_capability(commit):
            raise Refusal("BOOTSTRAP_CAPABILITY_BYTES_NOT_APPROVED")
    else:
        transition_id = validate_registered_transition(
            repo, base_sha, event_sha, authority_root, changed
        )
    return {
        "schema_version": "rea.newsletter.control-upgrade-validation.v2",
        "verdict": "PASS",
        "raw_exit": 0,
        "repository": repository,
        "base_sha": base_sha,
        "event_sha": event_sha,
        "authority_commit": commit,
        "changed": sorted(changed),
        "registered_transition": transition_id,
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
