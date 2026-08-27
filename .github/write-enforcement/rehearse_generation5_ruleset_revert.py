#!/usr/bin/env python3
"""Rebuild the generation-5 manifest twice from post-revert ruleset bytes.

This is a rehearsal only. It clones the five immutable member commits from the
gios-dev object stores, invokes the existing frozen-manifest builder twice, and
persists command-level evidence plus a deterministic summary. It never edits a
ruleset, repository, tag, workflow, mirror, or installed authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


SCHEMA = "rea.generation5-ruleset-revert-rehearsal.v1"
EXPECTED_REPOSITORIES = {
    "research_enforcement_activation": Path("/home/azureuser/rea150m/rea"),
    "govML": Path("/home/azureuser/rea150m/govml"),
    "Moonshots_Career_Thesis_v2": Path("/home/azureuser/rea150m/moonshots"),
    "newsletter": Path("/home/azureuser/rea150m/newsletter"),
    "rexcoleman.dev": Path("/home/azureuser/rea150m/rexdev"),
}
EXPECTED_RULESET_ID = 19564990
EXPECTED_MEMBER_COUNT = 259


class Refusal(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise Refusal(f"JSON_REFUSED:{path}:{type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise Refusal(f"JSON_OBJECT_REFUSED:{path}")
    return value


def manifest_commits(manifest: dict) -> dict[str, str]:
    members = manifest.get("members")
    if not isinstance(members, list) or len(members) != EXPECTED_MEMBER_COUNT:
        raise Refusal("MANIFEST_MEMBER_COUNT_REFUSED")
    observed: dict[str, set[str]] = {}
    for row in members:
        if not isinstance(row, dict):
            raise Refusal("MANIFEST_MEMBER_ROW_REFUSED")
        repository, commit = row.get("repository"), row.get("commit")
        if repository not in EXPECTED_REPOSITORIES:
            raise Refusal(f"MANIFEST_REPOSITORY_REFUSED:{repository}")
        if not isinstance(commit, str) or len(commit) != 40:
            raise Refusal(f"MANIFEST_COMMIT_REFUSED:{repository}")
        observed.setdefault(repository, set()).add(commit)
    if set(observed) != set(EXPECTED_REPOSITORIES):
        raise Refusal("MANIFEST_REPOSITORY_SET_REFUSED")
    if any(len(commits) != 1 for commits in observed.values()):
        raise Refusal("MANIFEST_REPOSITORY_COMMIT_DIVERGENCE")
    return {name: next(iter(observed[name])) for name in sorted(observed)}


def validate_post_revert_ruleset(value: dict) -> None:
    if value.get("id") != EXPECTED_RULESET_ID:
        raise Refusal("RULESET_ID_REFUSED")
    if value.get("enforcement") != "active":
        raise Refusal("RULESET_ENFORCEMENT_REFUSED")
    if value.get("bypass_actors") != []:
        raise Refusal("RULESET_BYPASS_NOT_REVERTED")


class CommandRecorder:
    def __init__(self, root: Path):
        self.root = root
        self.counter = 0

    def run(self, argv: list[str], *, cwd: Path, subject: str,
            timeout_seconds: int) -> subprocess.CompletedProcess[bytes]:
        self.counter += 1
        command_dir = self.root / f"{self.counter:02d}"
        command_dir.mkdir(parents=True, exist_ok=False)
        (command_dir / "argv.json").write_bytes(canonical(argv) + b"\n")
        (command_dir / "cwd.txt").write_text(str(cwd.resolve()) + "\n")
        (command_dir / "subject.txt").write_text(subject + "\n")
        try:
            completed = subprocess.run(
                argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout_seconds, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            (command_dir / "stdout.raw").write_bytes(exc.stdout or b"")
            (command_dir / "stderr.raw").write_bytes(exc.stderr or b"")
            (command_dir / "rc.txt").write_text("124\n")
            raise Refusal(f"COMMAND_TIMEOUT:{subject}") from exc
        (command_dir / "stdout.raw").write_bytes(completed.stdout)
        (command_dir / "stderr.raw").write_bytes(completed.stderr)
        (command_dir / "rc.txt").write_text(f"{completed.returncode}\n")
        print(f"COMMAND_COMPLETE subject={subject} raw_exit={completed.returncode}", flush=True)
        if completed.returncode != 0:
            raise Refusal(f"COMMAND_REFUSED:{subject}:exit={completed.returncode}")
        return completed


def compare_manifests(baseline: dict, first: dict, second: dict) -> dict:
    if canonical(first) != canonical(second):
        raise Refusal("DOUBLE_BUILD_NONDETERMINISTIC")
    if len(first.get("members", [])) != EXPECTED_MEMBER_COUNT:
        raise Refusal("BUILT_MEMBER_COUNT_REFUSED")
    if canonical(first["members"]) != canonical(baseline.get("members")):
        raise Refusal("BUILT_MEMBER_ROWS_DIVERGED")
    changed = sorted(
        key for key in set(baseline) | set(first)
        if canonical(baseline.get(key)) != canonical(first.get(key))
    )
    if changed != ["manifest_digest", "normalized_ruleset_sha256"]:
        raise Refusal(f"BUILT_CHANGED_FIELDS_REFUSED:{changed}")
    return {
        "changed_fields": changed,
        "member_count": EXPECTED_MEMBER_COUNT,
        "members_byte_identical": True,
        "two_builds_byte_deterministic": True,
        "manifest_digest": first["manifest_digest"],
        "normalized_ruleset_sha256": first["normalized_ruleset_sha256"],
    }


def execute(ruleset_path: Path, output_dir: Path) -> int:
    script_root = Path(__file__).resolve().parent
    baseline_path = script_root / "frozen_bundle_manifest.generation-5.json"
    builder = script_root / "build_frozen_manifest.py"
    baseline = read_json(baseline_path)
    ruleset = read_json(ruleset_path)
    validate_post_revert_ruleset(ruleset)
    commits = manifest_commits(baseline)
    if output_dir.exists():
        raise Refusal(f"OUTPUT_EXISTS:{output_dir}")
    output_dir.mkdir(parents=True, mode=0o700)
    commands = CommandRecorder(output_dir / "commands")
    copied_ruleset = output_dir / "post_revert_ruleset.json"
    copied_ruleset.write_bytes(canonical(ruleset) + b"\n")
    os.chmod(copied_ruleset, 0o600)
    manifests = output_dir / "manifests"
    manifests.mkdir()
    with tempfile.TemporaryDirectory(prefix="rea-s165-revert-roots-") as temp_raw:
        temp = Path(temp_raw)
        roots: dict[str, Path] = {}
        for logical, store in EXPECTED_REPOSITORIES.items():
            if not store.is_dir():
                raise Refusal(f"OBJECT_STORE_ABSENT:{logical}:{store}")
            root = temp / logical.replace(".", "_")
            commands.run(
                ["git", "clone", "--no-checkout", str(store), str(root)],
                cwd=temp, subject=f"{store}@{commits[logical]}", timeout_seconds=300,
            )
            commands.run(
                ["git", "checkout", "--detach", commits[logical]],
                cwd=root, subject=f"{root}@{commits[logical]}", timeout_seconds=120,
            )
            roots[logical] = root
        fixed = [
            "/usr/bin/python3", str(builder), "--ruleset-json", str(copied_ruleset),
            "--successor-ci-materialization",
            "--root-research-enforcement-activation", str(roots["research_enforcement_activation"]),
            "--root-govml", str(roots["govML"]),
            "--root-moonshots-career-thesis-v2", str(roots["Moonshots_Career_Thesis_v2"]),
            "--root-newsletter", str(roots["newsletter"]),
            "--root-rexcoleman-dev", str(roots["rexcoleman.dev"]),
        ]
        for label in ("a", "b"):
            target_dir = manifests / label
            target_dir.mkdir()
            target = target_dir / "frozen_bundle_manifest.generation-5.json"
            commands.run(
                fixed[:2] + ["--output", str(target)] + fixed[2:],
                cwd=script_root.parent.parent, subject=str(builder), timeout_seconds=1200,
            )
    first_raw = (manifests / "a" / "frozen_bundle_manifest.generation-5.json").read_bytes()
    second_raw = (manifests / "b" / "frozen_bundle_manifest.generation-5.json").read_bytes()
    result = compare_manifests(baseline, json.loads(first_raw), json.loads(second_raw))
    result.update({
        "schema_version": SCHEMA,
        "baseline_path": str(baseline_path),
        "ruleset_input_sha256": sha256(copied_ruleset.read_bytes()),
        "build_a_sha256": sha256(first_raw), "build_b_sha256": sha256(second_raw),
        "remote_mutation": False, "owner_action": False,
        "installed_authority_mutation": False,
    })
    (output_dir / "summary.json").write_bytes(canonical(result) + b"\n")
    print(
        f"REVERT_REHEARSAL_PASS member_count={result['member_count']} "
        f"manifest_digest={result['manifest_digest']} remote_mutation=false",
        flush=True,
    )
    return 0


def self_test() -> int:
    repositories = sorted(EXPECTED_REPOSITORIES)
    members = [
        {"repository": repositories[index % len(repositories)],
         "commit": "a" * 40, "path": f"p{index}"}
        for index in range(EXPECTED_MEMBER_COUNT)
    ]
    baseline = {"members": members, "normalized_ruleset_sha256": "b" * 64,
                "manifest_digest": "c" * 64}
    built = json.loads(json.dumps(baseline))
    built["normalized_ruleset_sha256"] = "d" * 64
    built["manifest_digest"] = "e" * 64
    compare_manifests(baseline, built, json.loads(json.dumps(built)))
    try:
        validate_post_revert_ruleset({"id": EXPECTED_RULESET_ID,
                                      "enforcement": "active",
                                      "bypass_actors": [{"actor_id": 5}]})
    except Refusal as exc:
        if "RULESET_BYPASS_NOT_REVERTED" not in str(exc):
            raise
    else:
        raise AssertionError("bypass admitted")
    print("SELF_TEST_PASS checks=2")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--ruleset-json", type=Path)
    parser.add_argument("--output-dir", type=Path,
                        default=Path("generation5_revert_rehearsal"))
    args = parser.parse_args(argv)
    if args.self_test:
        if args.ruleset_json is not None or args.output_dir != Path("generation5_revert_rehearsal"):
            print("REFUSE(REVERT_REHEARSAL): SELF_TEST_ARGUMENT_REFUSED", file=sys.stderr)
            return 2
        return self_test()
    if args.ruleset_json is None:
        print("REFUSE(REVERT_REHEARSAL): RULESET_JSON_REQUIRED", file=sys.stderr)
        return 2
    try:
        return execute(args.ruleset_json.resolve(strict=True), args.output_dir.resolve())
    except Refusal as exc:
        print(f"REFUSE(REVERT_REHEARSAL): {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"REFUSE(REVERT_REHEARSAL): INTERNAL_{type(exc).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
