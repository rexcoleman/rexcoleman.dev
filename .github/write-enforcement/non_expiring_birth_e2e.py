#!/usr/bin/env python3
"""End-to-end birth proof for non-expiring REA enforcement releases."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPOSITORIES = {
    "Moonshots_Career_Thesis_v2": "https://github.com/rexcoleman/Moonshots_Career_Thesis.git",
    "govML": "https://github.com/rexcoleman/govML.git",
}


class Refusal(RuntimeError):
    pass


def run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
        timeout: int = 300) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed


def require(completed: subprocess.CompletedProcess, label: str) -> subprocess.CompletedProcess:
    if completed.returncode != 0:
        raise Refusal(
            f"{label} refused rc={completed.returncode}\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return completed


def manifest_commit(manifest: dict, repository: str) -> str:
    commits = {
        row.get("commit")
        for row in manifest.get("members", [])
        if isinstance(row, dict) and row.get("repository") == repository
    }
    if len(commits) != 1:
        raise Refusal(f"manifest does not bind exactly one {repository} commit")
    commit = next(iter(commits))
    if not isinstance(commit, str) or len(commit) != 40:
        raise Refusal(f"manifest {repository} commit is malformed")
    return commit


def materialize_repo(name: str, commit: str, root: Path, scratch: Path) -> Path:
    if root:
        observed = require(run(["git", "-C", str(root), "rev-parse", "HEAD"]), f"{name} head").stdout.strip()
        if observed != commit:
            raise Refusal(f"{name} root head {observed} != manifest {commit}")
        return root
    destination = scratch / f"{name}-source"
    require(run(["git", "clone", "--no-checkout", REPOSITORIES[name], str(destination)], timeout=600), f"{name} clone")
    require(run(["git", "-C", str(destination), "checkout", "--detach", commit], timeout=300), f"{name} checkout")
    return destination


def write_test_key(private_key: Path, public_key: Path) -> None:
    private = Ed25519PrivateKey.generate()
    private_key.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    private_key.chmod(0o600)
    public_key.chmod(0o644)


def issue_test_packet(args: argparse.Namespace, scratch: Path) -> Path:
    packet = scratch / "candidate-test-packet"
    key_dir = scratch / "test-key"
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = key_dir / "test-private.pem"
    public_key = key_dir / "test-public.pem"
    write_test_key(private_key, public_key)
    require(
        run(
            [
                sys.executable,
                str(args.site_root / ".github/write-enforcement/non_expiring_enforcement.py"),
                "issue",
                "--repo-root",
                str(args.site_root),
                "--source-manifest",
                str(args.source_manifest),
                "--private-key",
                str(private_key),
                "--trusted-public-key",
                str(public_key),
                "--output",
                str(packet),
                "--repository",
                "rexcoleman/rexcoleman.dev",
                "--ref",
                "refs/heads/main",
                "--packet-version",
                "rea-non-expiring-candidate-test-" + args.site_root_head[:12],
            ],
            timeout=300,
        ),
        "candidate test packet issue",
    )
    require(
        run(
            [
                sys.executable,
                str(args.site_root / ".github/write-enforcement/non_expiring_enforcement.py"),
                "verify",
                "--packet-root",
                str(packet),
                "--trusted-public-key",
                str(public_key),
            ],
            timeout=120,
        ),
        "candidate test packet verify",
    )
    return packet


def create_private_repo(owner: str, name: str) -> str:
    repo = f"{owner}/{name}"
    require(
        run(
            [
                "gh", "repo", "create", repo, "--private",
                "--disable-issues", "--disable-wiki",
            ],
            timeout=120,
        ),
        "scratch repo create",
    )
    return repo


def push_project(project: Path, repo: str) -> None:
    require(run(["gh", "auth", "setup-git"], timeout=120), "gh auth setup-git")
    require(run(["git", "-C", str(project), "config", "user.name", "REA birth proof"]), "git user.name")
    require(run(["git", "-C", str(project), "config", "user.email", "rea-birth-proof@example.invalid"]), "git user.email")
    require(run(["git", "-C", str(project), "add", "."]), "git add")
    require(run(["git", "-C", str(project), "commit", "-m", "Genesis birth proof"], timeout=120), "git commit")
    require(run(["git", "-C", str(project), "branch", "-M", "main"]), "git branch main")
    require(run(["git", "-C", str(project), "remote", "add", "origin", f"https://github.com/{repo}.git"]), "git remote add")
    require(run(["git", "-C", str(project), "push", "-u", "origin", "main"], timeout=300), "git push")


def scaffold_project(args: argparse.Namespace, moonshots: Path, govml: Path,
                     packet_root: Path | None, project: Path, repo_name: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("REA_NON_EXPIRING_") or key == "REA_STAGED_NONPRODUCTION":
            env.pop(key, None)
    env.pop("REA_WEA_STATE_ROOT", None)
    env.pop("REX_SITE_SOURCE_ROOT", None)
    env.pop("GOVML_OBJECT_REPO", None)
    if packet_root is not None:
        env["REA_NON_EXPIRING_PACKET_ROOT"] = str(packet_root)
        env["REA_NON_EXPIRING_TEST_TRUST_ROOT"] = "1"
        env["REX_SITE_SOURCE_ROOT"] = str(args.site_root)
        env["GOVML_OBJECT_REPO"] = str(govml)
    completed = run(
        [
            sys.executable,
            str(moonshots / "scripts/scaffold_research_project.py"),
            "--project-id",
            repo_name,
            "--research-type",
            "build",
            "--author-model-family",
            "anthropic",
            str(project),
        ],
        env=env,
        timeout=600,
    )
    return completed


def gate_env(packet_root: Path | None) -> dict[str, str]:
    env = os.environ.copy()
    if packet_root is not None:
        env["REA_NON_EXPIRING_PACKET_ROOT"] = str(packet_root)
        env["REA_NON_EXPIRING_TEST_TRUST_ROOT"] = "1"
    return env


def run_birth(args: argparse.Namespace) -> dict:
    args.site_root = args.site_root.resolve()
    args.source_manifest = args.source_manifest.resolve()
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        require(run(["gh", "auth", "setup-git"], timeout=120), "gh auth setup-git")
    args.site_root_head = require(
        run(["git", "-C", str(args.site_root), "rev-parse", "HEAD"]),
        "site head",
    ).stdout.strip()
    manifest = json.loads(args.source_manifest.read_text(encoding="utf-8"))
    scratch = args.scratch_root.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    moonshots_commit = manifest_commit(manifest, "Moonshots_Career_Thesis_v2")
    govml_commit = manifest_commit(manifest, "govML")
    moonshots = materialize_repo(
        "Moonshots_Career_Thesis_v2",
        moonshots_commit,
        args.moonshots_root.resolve() if args.moonshots_root else None,
        scratch,
    )
    govml = materialize_repo(
        "govML",
        govml_commit,
        args.govml_root.resolve() if args.govml_root else None,
        scratch,
    )
    packet_root = issue_test_packet(args, scratch) if args.mode == "candidate" else None
    repo_name = args.repo_name or (
        f"{args.repo_prefix}-{args.mode}-{args.site_root_head[:12]}-{int(time.time())}"
    )
    project = scratch / repo_name
    scaffold = scaffold_project(args, moonshots, govml, packet_root, project, repo_name)
    if scaffold.returncode != 0:
        raise Refusal(
            f"plain scaffold refused rc={scaffold.returncode}\n"
            f"STDOUT:\n{scaffold.stdout}\nSTDERR:\n{scaffold.stderr}"
        )
    repo = create_private_repo(args.repo_owner, repo_name)
    push_project(project, repo)
    honest = run(["bash", "scripts/run_gates.sh", "--engine-preflight"], cwd=project, env=gate_env(packet_root), timeout=300)
    if honest.returncode != 0:
        raise Refusal(
            f"honest gate refused rc={honest.returncode}\nSTDOUT:\n{honest.stdout}\nSTDERR:\n{honest.stderr}"
        )
    authority_source = project / "write_integrity/bundle/govML/templates/build/enforcement/project_run_gates.sh"
    with authority_source.open("a", encoding="utf-8") as handle:
        handle.write("\n# planted signed-control drift\n")
    planted = run(["bash", "scripts/run_gates.sh", "--engine-preflight"], cwd=project, env=gate_env(packet_root), timeout=300)
    if planted.returncode == 0 or "REFUSE" not in planted.stderr:
        raise Refusal(
            f"planted gate did not refuse rc={planted.returncode}\n"
            f"STDOUT:\n{planted.stdout}\nSTDERR:\n{planted.stderr}"
        )
    report = {
        "schema_version": "rea.non_expiring_birth_e2e.v1",
        "mode": args.mode,
        "site_commit": args.site_root_head,
        "moonshots_commit": moonshots_commit,
        "govml_commit": govml_commit,
        "repo": repo,
        "project_dir": str(project),
        "packet_root": str(packet_root) if packet_root else None,
        "scaffold_rc": scaffold.returncode,
        "honest_gate_rc": honest.returncode,
        "planted_gate_rc": planted.returncode,
        "honest_gate_stdout": honest.stdout,
        "honest_gate_stderr": honest.stderr,
        "planted_gate_stdout": planted.stdout,
        "planted_gate_stderr": planted.stderr,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("candidate", "release"), required=True)
    parser.add_argument("--site-root", type=Path, default=Path("."))
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--moonshots-root", type=Path)
    parser.add_argument("--govml-root", type=Path)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--repo-owner", default="rexcoleman")
    parser.add_argument("--repo-prefix", default="rea-s261-birth")
    parser.add_argument("--repo-name")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_birth(args)
    except Exception as exc:
        print(f"REFUSE(NON_EXPIRING_BIRTH_E2E): {exc}", file=sys.stderr)
        return 3
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "NON_EXPIRING_BIRTH_E2E_PASS "
        f"mode={report['mode']} repo={report['repo']} "
        f"moonshots={report['moonshots_commit']} govml={report['govml_commit']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
