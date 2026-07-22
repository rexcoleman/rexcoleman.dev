#!/usr/bin/env python3
"""Verify opaque seal transport at exact committed SHAs; mint no authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

EXIT_VERIFY = 0
EXIT_REFUSE = 3
GIT = "/usr/bin/git"
SHA_RE = re.compile(r"[0-9a-f]{40}")
MANIFEST_REL = PurePosixPath(".rea/hosted-authority/frozen-manifest.json")
MANIFEST_KEYS = {
    "schema_version", "manifest_id", "status", "authority_kind",
    "repository_origin", "baseline_target_sha", "seal_id", "routes",
    "verification_scope", "default", "semantic_authorization",
    "deployment_authorization", "private_authority_material_included",
    "target_tree", "target_members", "control_members", "reason_codes",
    "receipt_schema_version",
}
MEMBER_KEYS = {"path", "byte_length", "sha256"}
REASONS = (
    "VERIFIED", "ARGUMENT_INVALID", "CONTROL_ROOT_INVALID",
    "CONTROL_SHA_MISMATCH", "CONTROL_WORKTREE_DIRTY",
    "CONTROL_MANIFEST_PATH_MISMATCH", "MANIFEST_MALFORMED",
    "MANIFEST_SCHEMA_MISMATCH", "MANIFEST_SEMANTICS_MISMATCH",
    "TARGET_CHECKOUT_INVALID", "TARGET_SHA_MISMATCH",
    "TARGET_NOT_SEALED_SHA",
    "TARGET_WORKTREE_DIRTY", "TARGET_TREE_MISMATCH",
    "TARGET_MEMBER_MISSING", "TARGET_MEMBER_TYPE_REFUSED",
    "SEALED_AUTHORITY_LENGTH_MISMATCH", "SEALED_AUTHORITY_DIGEST_MISMATCH",
    "CONTROL_MEMBER_MISSING", "CONTROL_MEMBER_TYPE_REFUSED",
    "CONTROL_MEMBER_LENGTH_MISMATCH", "CONTROL_MEMBER_DIGEST_MISMATCH",
    "CANNOT_EVALUATE",
)
GIT_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
    "XDG_CONFIG_HOME": "/nonexistent", "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
}


@dataclass(frozen=True)
class Refusal(Exception):
    reason: str
    detail: str


def refuse(reason: str, detail: str) -> None:
    if reason not in REASONS or reason == "VERIFIED":
        raise Refusal("CANNOT_EVALUATE", "invalid_internal_reason")
    raise Refusal(reason, detail)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(
            [GIT, "-C", str(root), *args], env=GIT_ENV, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=15,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        refuse("CANNOT_EVALUATE", "git_failure")


def root_path(raw: str, reason: str) -> Path:
    try:
        root = Path(raw).resolve(strict=True)
    except OSError:
        refuse(reason, "root_missing")
    if not root.is_dir():
        refuse(reason, "root_not_directory")
    return root


def relative(raw: object) -> PurePosixPath:
    if not isinstance(raw, str) or not raw:
        refuse("MANIFEST_SCHEMA_MISMATCH", "path_type")
    path = PurePosixPath(raw)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        refuse("MANIFEST_SCHEMA_MISMATCH", "path_escape")
    return path


def read_regular(root: Path, rel: PurePosixPath, missing: str, wrong_type: str) -> bytes:
    path = root.joinpath(*rel.parts)
    try:
        mode = path.lstat().st_mode
    except OSError:
        refuse(missing, rel.as_posix())
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        refuse(wrong_type, rel.as_posix())
    try:
        path.resolve(strict=True).relative_to(root)
        return path.read_bytes()
    except (OSError, ValueError):
        refuse(wrong_type, rel.as_posix())


def parse_member(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != MEMBER_KEYS:
        refuse("MANIFEST_SCHEMA_MISMATCH", "member_shape")
    path = relative(value["path"])
    length, sha = value["byte_length"], value["sha256"]
    if not isinstance(length, int) or length < 0:
        refuse("MANIFEST_SCHEMA_MISMATCH", "member_length")
    if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{64}", sha) is None:
        refuse("MANIFEST_SCHEMA_MISMATCH", "member_digest")
    return {"path": path, "byte_length": length, "sha256": sha}


def parse_manifest(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse("MANIFEST_MALFORMED", "json")
    if not isinstance(value, dict) or set(value) != MANIFEST_KEYS:
        refuse("MANIFEST_SCHEMA_MISMATCH", "top_level")
    fixed = (
        value["schema_version"] == "rea.hosted-authority-manifest.v1"
        and value["status"] == "FROZEN"
        and value["authority_kind"] == "OPAQUE_SEAL_TRANSPORT_INTEGRITY"
        and value["verification_scope"] == "EXACT_PUSHED_SHA_TRANSPORT_ONLY"
        and value["default"] == "REFUSE"
        and value["semantic_authorization"] is False
        and value["deployment_authorization"] is False
        and value["private_authority_material_included"] is False
        and value["routes"] == ["BLG-09", "BLG-10"]
        and value["reason_codes"] == list(REASONS)
        and value["receipt_schema_version"] == "rea.hosted-authority-receipt.v1"
    )
    if not fixed:
        refuse("MANIFEST_SEMANTICS_MISMATCH", "fail_closed_contract")
    if value["repository_origin"] != "https://github.com/rexcoleman/rexcoleman.dev.git":
        refuse("MANIFEST_SCHEMA_MISMATCH", "origin")
    if not isinstance(value["manifest_id"], str) or not value["manifest_id"]:
        refuse("MANIFEST_SCHEMA_MISMATCH", "manifest_id")
    if not isinstance(value["seal_id"], str) or re.fullmatch(r"[0-9a-f]{32}", value["seal_id"]) is None:
        refuse("MANIFEST_SCHEMA_MISMATCH", "seal_id")
    if not isinstance(value["baseline_target_sha"], str) or SHA_RE.fullmatch(value["baseline_target_sha"]) is None:
        refuse("MANIFEST_SCHEMA_MISMATCH", "baseline_sha")
    tree = value["target_tree"]
    if not isinstance(tree, dict) or set(tree) != {"root", "exact_files"}:
        refuse("MANIFEST_SCHEMA_MISMATCH", "tree_shape")
    tree_root = relative(tree["root"])
    if not isinstance(tree["exact_files"], list) or not tree["exact_files"]:
        refuse("MANIFEST_SCHEMA_MISMATCH", "tree_files")
    tree_files = [relative(item) for item in tree["exact_files"]]
    if len(tree_files) != len(set(tree_files)):
        refuse("MANIFEST_SCHEMA_MISMATCH", "tree_duplicates")
    if not isinstance(value["target_members"], list) or not isinstance(value["control_members"], list):
        refuse("MANIFEST_SCHEMA_MISMATCH", "member_lists")
    targets = [parse_member(item) for item in value["target_members"]]
    controls = [parse_member(item) for item in value["control_members"]]
    for name, members in (("target", targets), ("control", controls)):
        paths = [item["path"] for item in members]
        if not paths or len(paths) != len(set(paths)):
            refuse("MANIFEST_SCHEMA_MISMATCH", name + "_paths")
    prefix = tree_root.as_posix() + "/"
    bound = {
        PurePosixPath(item["path"].as_posix()[len(prefix):])
        for item in targets if item["path"].as_posix().startswith(prefix)
    }
    if bound != set(tree_files):
        refuse("MANIFEST_SEMANTICS_MISMATCH", "tree_binding")
    value["target_tree"] = {"root": tree_root, "exact_files": tree_files}
    value["target_members"], value["control_members"] = targets, controls
    return value


def git_identity(root: Path, sha: str, control: bool) -> None:
    if git(root, "rev-parse", "HEAD") != sha:
        refuse("CONTROL_SHA_MISMATCH" if control else "TARGET_CHECKOUT_INVALID", "head")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        refuse("CONTROL_WORKTREE_DIRTY" if control else "TARGET_WORKTREE_DIRTY", "dirty")


def verify_tree(root: Path, tree: dict[str, object]) -> None:
    path = root.joinpath(*tree["root"].parts)
    try:
        mode = path.lstat().st_mode
    except OSError:
        refuse("TARGET_TREE_MISMATCH", "missing")
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        refuse("TARGET_TREE_MISMATCH", "type")
    actual = set()
    for item in path.rglob("*"):
        mode = item.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        rel = PurePosixPath(item.relative_to(path).as_posix())
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            refuse("TARGET_MEMBER_TYPE_REFUSED", rel.as_posix())
        actual.add(rel)
    if actual != set(tree["exact_files"]):
        refuse("TARGET_TREE_MISMATCH", "exact_files")


def verify_members(root: Path, members: list[dict[str, object]], control: bool) -> int:
    for item in members:
        raw = read_regular(
            root, item["path"],
            "CONTROL_MEMBER_MISSING" if control else "TARGET_MEMBER_MISSING",
            "CONTROL_MEMBER_TYPE_REFUSED" if control else "TARGET_MEMBER_TYPE_REFUSED",
        )
        if len(raw) != item["byte_length"]:
            refuse("CONTROL_MEMBER_LENGTH_MISMATCH" if control else "SEALED_AUTHORITY_LENGTH_MISMATCH", item["path"].as_posix())
        if digest(raw) != item["sha256"]:
            refuse("CONTROL_MEMBER_DIGEST_MISMATCH" if control else "SEALED_AUTHORITY_DIGEST_MISMATCH", item["path"].as_posix())
    return len(members)


def emit(path: str, verdict: str, reason: str, detail: str, args: argparse.Namespace,
         manifest: dict[str, object] | None, manifest_sha: str | None, matched: int) -> None:
    value = {
        "schema_version": "rea.hosted-authority-receipt.v1",
        "verdict": verdict, "reason_code": reason, "detail": detail,
        "control_sha": args.control_sha, "target_sha": args.target_sha,
        "expected_sha": args.expected_sha,
        "baseline_target_sha": manifest.get("baseline_target_sha") if manifest else None,
        "manifest_id": manifest.get("manifest_id") if manifest else None,
        "manifest_sha256": manifest_sha,
        "seal_id": manifest.get("seal_id") if manifest else None,
        "matched_member_count": matched,
        "semantic_authorization": False, "deployment_authorization": False,
    }
    receipt = Path(path)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(value, sort_keys=True))


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    for name in ("manifest", "control-root", "control-sha", "target-root", "target-sha", "expected-sha", "receipt"):
        parser.add_argument("--" + name, required=True)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    manifest = None
    manifest_sha = None
    matched = 0
    try:
        if any(SHA_RE.fullmatch(item) is None for item in (args.control_sha, args.target_sha, args.expected_sha)):
            refuse("ARGUMENT_INVALID", "sha")
        control = root_path(args.control_root, "CONTROL_ROOT_INVALID")
        target = root_path(args.target_root, "TARGET_CHECKOUT_INVALID")
        if Path(args.manifest).resolve(strict=True) != control.joinpath(*MANIFEST_REL.parts):
            refuse("CONTROL_MANIFEST_PATH_MISMATCH", "manifest")
        raw = read_regular(control, MANIFEST_REL, "MANIFEST_MALFORMED", "MANIFEST_MALFORMED")
        manifest_sha, manifest = digest(raw), parse_manifest(raw)
        git_identity(control, args.control_sha, True)
        git_identity(target, args.target_sha, False)
        actual_origin = git(target, "remote", "get-url", "origin")
        allowed_origins = {
            manifest["repository_origin"],
            manifest["repository_origin"].removesuffix(".git"),
        }
        if actual_origin not in allowed_origins:
            refuse("TARGET_CHECKOUT_INVALID", "origin")
        if args.target_sha != args.expected_sha:
            refuse("TARGET_SHA_MISMATCH", "expected_sha")
        matched += verify_members(control, manifest["control_members"], True)
        verify_tree(target, manifest["target_tree"])
        matched += verify_members(target, manifest["target_members"], False)
        if args.target_sha != manifest["baseline_target_sha"]:
            refuse("TARGET_NOT_SEALED_SHA", "baseline_target_sha")
        emit(args.receipt, "VERIFY", "VERIFIED", "exact_sha_and_public_digests", args, manifest, manifest_sha, matched)
        return EXIT_VERIFY
    except Refusal as exc:
        emit(args.receipt, "REFUSE", exc.reason, exc.detail, args, manifest, manifest_sha, matched)
        return EXIT_REFUSE
    except Exception as exc:
        emit(args.receipt, "REFUSE", "CANNOT_EVALUATE", type(exc).__name__, args, manifest, manifest_sha, matched)
        return EXIT_REFUSE


if __name__ == "__main__":
    raise SystemExit(main())
