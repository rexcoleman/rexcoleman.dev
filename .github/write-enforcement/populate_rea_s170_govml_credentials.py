#!/usr/bin/env python3
"""One-time hidden entry of the two owner-held REA enrollment tokens."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


CREDENTIAL_FILE = Path("/home/azureuser/.config/govml/env")
REQUIRED = (
    "GOVML_AUTHORITY_TOKEN",
    "REA_BUNDLE_READ_TOKEN",
)
TOKEN_PATTERN = re.compile(r"(?:github_pat_|ghp_)[A-Za-z0-9_]+")
NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Refusal(RuntimeError):
    pass


def parse(raw: bytes) -> tuple[list[str], dict[str, str]]:
    try:
        rows = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise Refusal("CREDENTIAL_FILE_UTF8_REFUSED") from exc
    found: dict[str, str] = {}
    for number, source in enumerate(rows, 1):
        row = source.strip()
        if not row or row.startswith("#"):
            continue
        if row.startswith("export "):
            row = row[7:].lstrip()
        if "=" not in row:
            raise Refusal(f"CREDENTIAL_FILE_PARSE_REFUSED line={number}")
        name, value = row.split("=", 1)
        name = name.strip()
        if NAME_PATTERN.fullmatch(name) is None:
            raise Refusal(f"CREDENTIAL_FILE_PARSE_REFUSED line={number}")
        if name not in REQUIRED:
            continue
        if name in found:
            raise Refusal(f"CREDENTIAL_FILE_DUPLICATE_REFUSED name={name}")
        value = value.strip()
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1:] != value[:1]:
                raise Refusal(f"CREDENTIAL_FILE_PARSE_REFUSED line={number}")
            value = value[1:-1]
        found[name] = value
    return rows, found


def secure_file(path: Path = CREDENTIAL_FILE) -> bytes:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise Refusal("CREDENTIAL_FILE_UNREADABLE") from exc
    if (
        not stat.S_ISREG(observed.st_mode)
        or path.is_symlink()
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise Refusal("CREDENTIAL_FILE_SECURITY_REFUSED")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise Refusal("CREDENTIAL_FILE_UNREADABLE") from exc


def presence(path: Path = CREDENTIAL_FILE) -> tuple[list[str], bytes, dict[str, str]]:
    raw = secure_file(path)
    rows, found = parse(raw)
    states = {name: "SET" if found.get(name) else "UNSET" for name in REQUIRED}
    if len(set(states.values())) != 1:
        raise Refusal("PARTIAL_REQUIRED_CREDENTIAL_SET_REFUSED")
    return rows, raw, states


def gh_json(token: str, endpoint: str):
    environment = {
        "GH_TOKEN": token,
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", ""),
    }
    completed = subprocess.run(
        ["gh", "api", endpoint],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=60,
    )
    if completed.returncode:
        raise Refusal(f"TOKEN_CAPABILITY_REFUSED endpoint={endpoint}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal(f"TOKEN_RESPONSE_REFUSED endpoint={endpoint}") from exc


def validate_token(token: str, repository: str) -> None:
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise Refusal("TOKEN_FORMAT_REFUSED")
    user = gh_json(token, "user")
    if not isinstance(user, dict) or user.get("login") != "rexcoleman":
        raise Refusal("TOKEN_OWNER_REFUSED")
    repo = gh_json(token, f"repos/{repository}")
    if not isinstance(repo, dict) or repo.get("full_name") != repository:
        raise Refusal(f"TOKEN_REPOSITORY_REFUSED repository={repository}")
    permissions = repo.get("permissions")
    if (
        not isinstance(permissions, dict)
        or permissions.get("pull") is not True
        or any(
            permissions.get(name) is not False
            for name in ("admin", "maintain", "push", "triage")
        )
    ):
        raise Refusal(f"TOKEN_READ_ONLY_SCOPE_REFUSED repository={repository}")
    branch = repo.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise Refusal(f"TOKEN_DEFAULT_BRANCH_REFUSED repository={repository}")
    tree = gh_json(token, f"repos/{repository}/git/trees/{branch}")
    if not isinstance(tree, dict) or not isinstance(tree.get("sha"), str):
        raise Refusal(f"TOKEN_CONTENTS_READ_REFUSED repository={repository}")


def updated_rows(rows: list[str], values: dict[str, str]) -> bytes:
    retained = []
    for source in rows:
        row = source.strip()
        candidate = row[7:].lstrip() if row.startswith("export ") else row
        name = candidate.split("=", 1)[0].strip() if "=" in candidate else ""
        if name not in REQUIRED:
            retained.append(source)
    if retained and retained[-1] != "":
        retained.append("")
    retained.extend(f"{name}={values[name]}" for name in REQUIRED)
    return ("\n".join(retained) + "\n").encode("utf-8")


def atomic_replace(path: Path, raw: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".rea-s170-govml-env-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def preflight(path: Path = CREDENTIAL_FILE) -> dict[str, str]:
    unused_rows, raw, states = presence(path)
    status = "COMPLETE" if all(state == "SET" for state in states.values()) else "READY"
    if status == "COMPLETE":
        unused_rows, values = parse(raw)
        validate_token(values["GOVML_AUTHORITY_TOKEN"], "rexcoleman/govML")
        validate_token(
            values["REA_BUNDLE_READ_TOKEN"],
            "rexcoleman/research_enforcement_activation",
        )
    return {"status": status, **states}


def apply(path: Path = CREDENTIAL_FILE) -> dict[str, str]:
    before = preflight(path)
    if before["status"] == "COMPLETE":
        return before
    if not all(os.isatty(descriptor) for descriptor in (0, 1, 2)):
        raise Refusal("OWNER_TTY_REQUIRED")
    rows, original, states = presence(path)
    if any(state != "UNSET" for state in states.values()):
        raise Refusal("APPLY_PREFLIGHT_MOVED")
    print("NOT SAFE to paste back", flush=True)
    print("Prepare two fine-grained GitHub tokens with Contents read-only access.", flush=True)
    authority = getpass.getpass("govML read-only token: ")
    bundle = getpass.getpass("REA bundle read-only token: ")
    written = False
    try:
        validate_token(authority, "rexcoleman/govML")
        validate_token(bundle, "rexcoleman/research_enforcement_activation")
        atomic_replace(path, updated_rows(rows, {
            "GOVML_AUTHORITY_TOKEN": authority,
            "REA_BUNDLE_READ_TOKEN": bundle,
        }))
        written = True
        after = preflight(path)
        if after["status"] != "COMPLETE":
            raise Refusal("CREDENTIAL_POSTCONDITION_REFUSED")
    except BaseException:
        if written:
            try:
                atomic_replace(path, original)
                print("CREDENTIAL_ROLLBACK_COMPLETE", file=sys.stderr)
            except BaseException:
                print("CREDENTIAL_ROLLBACK_INCOMPLETE", file=sys.stderr)
        raise
    finally:
        authority = ""
        bundle = ""
    return after


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preflight", action="store_true")
    modes.add_argument("--apply", action="store_true")
    arguments = parser.parse_args()
    try:
        result = apply() if arguments.apply else preflight()
    except (OSError, Refusal, subprocess.TimeoutExpired) as exc:
        print(f"REA_S170_CREDENTIAL_REFUSED reason={exc}", file=sys.stderr)
        return 3
    print(
        "REA_S170_CREDENTIAL_" + ("COMPLETE" if result["status"] == "COMPLETE" else "PREFLIGHT")
        + " " + " ".join(f"{name}={result[name]}" for name in REQUIRED)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
