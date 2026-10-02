#!/usr/bin/env python3
"""End-to-end birth proof for non-expiring REA enforcement releases."""

from __future__ import annotations

import argparse
import hashlib
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
RESEARCH_TYPES = ("build", "synthesis", "computational", "write_publish")
TEST_PACKET_PREFIX = "rea-non-expiring-candidate-test-"


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_identity(path: Path, manifest: dict) -> dict:
    digest = manifest.get("manifest_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise Refusal("source manifest does not carry a 64-hex manifest_digest")
    return {
        "manifest_digest": digest,
        "source_manifest_sha256": sha256_file(path),
    }


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


def materialize_clean_site_root(args: argparse.Namespace, scratch: Path) -> tuple[Path, Path]:
    destination = scratch / "rex-site-source"
    require(
        run(["git", "clone", "--no-checkout", str(args.site_root), str(destination)], timeout=300),
        "site clean clone",
    )
    require(
        run(["git", "-C", str(destination), "checkout", "--detach", args.site_root_head], timeout=120),
        "site clean checkout",
    )
    try:
        manifest_rel = args.source_manifest.relative_to(args.site_root)
    except ValueError as exc:
        raise Refusal("source manifest is not under site root") from exc
    return destination, destination / manifest_rel


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
    clean_site_root, clean_source_manifest = materialize_clean_site_root(args, scratch)
    require(
        run(
            [
                sys.executable,
                str(args.site_root / ".github/write-enforcement/non_expiring_enforcement.py"),
                "issue",
                "--repo-root",
                str(clean_site_root),
                "--source-manifest",
                str(clean_source_manifest),
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
                TEST_PACKET_PREFIX + args.site_root_head[:12],
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
    shutil.copyfile(clean_source_manifest, packet / "source_manifest.json")
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


def create_local_repo(scratch: Path, name: str) -> str:
    remote = scratch / "remotes" / f"{name}.git"
    remote.parent.mkdir(parents=True, exist_ok=True)
    require(run(["git", "init", "--bare", str(remote)], timeout=120), "scratch bare repo create")
    return str(remote)


def create_rehearsal_repo(args: argparse.Namespace, scratch: Path, name: str) -> str:
    if args.remote_kind == "github":
        return create_private_repo(args.repo_owner, name)
    if args.remote_kind == "local":
        return create_local_repo(scratch, name)
    raise Refusal(f"unknown remote kind: {args.remote_kind}")


def archive_repo(args: argparse.Namespace, repo: str) -> dict:
    if args.remote_kind == "local":
        return {
            "repo": repo,
            "archived": True,
            "archive_rc": 0,
            "archive_stdout": "LOCAL_SCRATCH_REMOTE_RETAINED\n",
            "archive_stderr": "",
        }
    completed = run(
        ["gh", "api", "--method", "PATCH", f"repos/{repo}", "-f", "archived=true"],
        timeout=120,
    )
    return {
        "repo": repo,
        "archived": completed.returncode == 0,
        "archive_rc": completed.returncode,
        "archive_stdout": completed.stdout,
        "archive_stderr": completed.stderr,
    }


def push_project(project: Path, repo: str, *, env: dict[str, str] | None = None) -> None:
    if "://" in repo or repo.count("/") == 1:
        remote_url = f"https://github.com/{repo}.git"
        require(run(["gh", "auth", "setup-git"], env=env, timeout=120), "gh auth setup-git")
    else:
        remote_url = repo
    require(run(["git", "-C", str(project), "config", "user.name", "REA birth proof"], env=env), "git user.name")
    require(run(["git", "-C", str(project), "config", "user.email", "rea-birth-proof@example.invalid"], env=env), "git user.email")
    require(run(["git", "-C", str(project), "add", "."], env=env), "git add")
    require(run(["git", "-C", str(project), "commit", "-m", "Genesis birth proof"], env=env, timeout=120), "git commit")
    require(run(["git", "-C", str(project), "branch", "-M", "main"], env=env), "git branch main")
    require(run(["git", "-C", str(project), "remote", "add", "origin", remote_url], env=env), "git remote add")
    require(run(["git", "-C", str(project), "push", "-u", "origin", "main"], env=env, timeout=300), "git push")


def scaffold_project(args: argparse.Namespace, moonshots: Path, govml: Path,
                     packet_root: Path | None, project: Path, repo_name: str,
                     research_type: str) -> subprocess.CompletedProcess:
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
        env["REA_NON_EXPIRING_CANDIDATE_REHEARSAL"] = "1"
        env["REX_SITE_SOURCE_ROOT"] = str(args.site_root)
        env["GOVML_OBJECT_REPO"] = str(govml)
    argv = [
        sys.executable,
        str(moonshots / "scripts/scaffold_research_project.py"),
        "--project-id",
        repo_name,
        "--research-type",
        research_type,
        "--author-model-family",
        "anthropic",
    ]
    if packet_root is not None:
        argv.append("--allow-non-expiring-test-trust")
    argv.append(str(project))
    completed = run(argv, env=env, timeout=600)
    return completed


def gate_env(packet_root: Path | None) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("REA_WEA_STATE_ROOT", None)
    if packet_root is not None:
        env["REA_NON_EXPIRING_PACKET_ROOT"] = str(packet_root)
        env["REA_NON_EXPIRING_TEST_TRUST_ROOT"] = "1"
        env["REA_NON_EXPIRING_CANDIDATE_REHEARSAL"] = "1"
    return env


def run_birth(args: argparse.Namespace) -> dict:
    started = time.monotonic()
    args.site_root = args.site_root.resolve()
    args.source_manifest = args.source_manifest.resolve()
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        require(run(["gh", "auth", "setup-git"], timeout=120), "gh auth setup-git")
    args.site_root_head = require(
        run(["git", "-C", str(args.site_root), "rev-parse", "HEAD"]),
        "site head",
    ).stdout.strip()
    manifest = json.loads(args.source_manifest.read_text(encoding="utf-8"))
    manifest_id = manifest_identity(args.source_manifest, manifest)
    scratch = args.scratch_root.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    run_id = args.run_id or f"{args.mode}-{args.site_root_head[:12]}-{int(time.time())}"
    if len(RESEARCH_TYPES) > args.max_rehearsal_repos:
        raise Refusal(
            f"rehearsal repo cap too low: need {len(RESEARCH_TYPES)} "
            f"cap={args.max_rehearsal_repos}"
        )
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
    type_reports = []
    for research_type in RESEARCH_TYPES:
        repo_name = (
            f"{args.repo_name}-{research_type}"
            if args.repo_name
            else f"rea-rehearsal-{research_type}-{run_id}"
        )
        project = scratch / repo_name
        repo = None
        archived = None
        type_report = {
            "research_type": research_type,
            "repo_name": repo_name,
            "project_dir": str(project),
        }
        try:
            scaffold = scaffold_project(
                args, moonshots, govml, packet_root, project, repo_name,
                research_type,
            )
            type_report.update({
                "scaffold_rc": scaffold.returncode,
                "scaffold_stdout": scaffold.stdout,
                "scaffold_stderr": scaffold.stderr,
            })
            if scaffold.returncode != 0:
                raise Refusal(
                    f"{research_type} scaffold refused rc={scaffold.returncode}\n"
                    f"STDOUT:\n{scaffold.stdout}\nSTDERR:\n{scaffold.stderr}"
                )
            repo = create_rehearsal_repo(args, scratch, repo_name)
            type_report["repo"] = repo
            type_report["remote_kind"] = args.remote_kind
            push_project(project, repo, env=gate_env(packet_root))
            honest = run(
                ["bash", "scripts/run_gates.sh", "--engine-preflight"],
                cwd=project,
                env=gate_env(packet_root),
                timeout=args.per_type_gate_timeout,
            )
            type_report.update({
                "honest_gate_rc": honest.returncode,
                "honest_gate_stdout": honest.stdout,
                "honest_gate_stderr": honest.stderr,
            })
            if honest.returncode != 0:
                raise Refusal(
                    f"{research_type} honest gate refused rc={honest.returncode}\n"
                    f"STDOUT:\n{honest.stdout}\nSTDERR:\n{honest.stderr}"
                )
            authority_source = (
                project / "write_integrity/bundle/govML/templates/build/"
                "enforcement/project_run_gates.sh"
            )
            with authority_source.open("a", encoding="utf-8") as handle:
                handle.write("\n# planted signed-control drift\n")
            planted = run(
                ["bash", "scripts/run_gates.sh", "--engine-preflight"],
                cwd=project,
                env=gate_env(packet_root),
                timeout=args.per_type_gate_timeout,
            )
            type_report.update({
                "planted_gate_rc": planted.returncode,
                "planted_gate_stdout": planted.stdout,
                "planted_gate_stderr": planted.stderr,
            })
            if planted.returncode == 0 or "REFUSE" not in (
                planted.stdout + planted.stderr
            ):
                raise Refusal(
                    f"{research_type} planted gate did not refuse "
                    f"rc={planted.returncode}\nSTDOUT:\n{planted.stdout}\n"
                    f"STDERR:\n{planted.stderr}"
                )
        finally:
            if repo:
                archived = archive_repo(args, repo)
                type_report["archive"] = archived
            type_reports.append(type_report)
        if archived and not archived["archived"]:
            raise Refusal(
                f"{research_type} rehearsal repo archive refused rc="
                f"{archived['archive_rc']} stderr={archived['archive_stderr']}"
            )
    runtime_seconds = round(time.monotonic() - started, 3)
    if runtime_seconds > args.max_runtime_seconds:
        raise Refusal(
            f"birth gate runtime exceeded bound seconds={runtime_seconds} "
            f"bound={args.max_runtime_seconds}"
        )
    report = {
        "schema_version": "rea.non_expiring_birth_gate.receipt.v1",
        "mode": args.mode,
        "run_id": run_id,
        "site_commit": args.site_root_head,
        "source_manifest": str(args.source_manifest),
        **manifest_id,
        "moonshots_commit": moonshots_commit,
        "govml_commit": govml_commit,
        "packet_root": str(packet_root) if packet_root else None,
        "research_types": list(RESEARCH_TYPES),
        "rehearsal_repo_count": len(type_reports),
        "max_rehearsal_repos": args.max_rehearsal_repos,
        "runtime_seconds": runtime_seconds,
        "max_runtime_seconds": args.max_runtime_seconds,
        "types": type_reports,
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
    parser.add_argument("--remote-kind", choices=("github", "local"), default="github")
    parser.add_argument("--run-id")
    parser.add_argument("--max-rehearsal-repos", type=int, default=20)
    parser.add_argument("--max-runtime-seconds", type=float, default=3600.0)
    parser.add_argument("--per-type-gate-timeout", type=int, default=600)
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
        f"mode={report['mode']} run_id={report['run_id']} "
        f"repos={report['rehearsal_repo_count']} "
        f"moonshots={report['moonshots_commit']} govml={report['govml_commit']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
