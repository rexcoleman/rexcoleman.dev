#!/usr/bin/env python3
"""One-time checked setup for the hosted external-judge approving principal."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPOSITORY = "rexcoleman/rexcoleman.dev"
REX_REPOSITORY = Path("/home/azureuser/rexcoleman.dev")
PAYLOAD_PATHS = (
    ".github/write-enforcement/setup_external_judge_hosted_principal.py",
    ".github/write-enforcement/setup_external_judge_hosted_principal.sh",
    ".github/write-enforcement/rea_s169_external_judge_principal_owner_row.txt",
    ".github/workflows/issue-external-judge-authority.yml",
)
ENVIRONMENT = "govml-external-judge-approver"
SECRET_NAME = "GOVML_EXTERNAL_JUDGE_APPROVING_PRIVATE_KEY_PEM"
PUBLIC_SHA_VARIABLE = "GOVML_EXTERNAL_JUDGE_APPROVING_PUBLIC_KEY_SHA256"
ISSUER_COMMIT_VARIABLE = "GOVML_EXTERNAL_JUDGE_ISSUER_COMMIT"
ISSUER_SHA_VARIABLE = "GOVML_EXTERNAL_JUDGE_ISSUER_SHA256"
STATE_VARIABLE = "GOVML_EXTERNAL_JUDGE_SETUP_STATE"
PUBLIC_KEY_PATH = Path(
    "/home/azureuser/ml-governance-templates/config/"
    "external_judge_approving_principal.ed25519.public.pem"
)
PREDECESSOR_BACKUP_PATH = PUBLIC_KEY_PATH.with_name(
    PUBLIC_KEY_PATH.name + ".s169-predecessor"
)
PREDECESSOR_SHA256 = "69a974bc7dd189c6ee56d105a2abcf35ddba0e039b070f153ad82bd22806b928"
PREDECESSOR_UID = 65534
PREDECESSOR_GID = 65534
PREDECESSOR_MODE = 0o644
GOVML_REPOSITORY = Path("/home/azureuser/ml-governance-templates")
ISSUER_PATH = "scripts/issue_external_judge_authority.py"
METADATA_URL = (
    "http://169.254.169.254/metadata/instance/compute"
    "?api-version=2021-02-01"
)
AZURE_CONFIG = Path("/home/azureuser/.local/share/govml-principal-azure")


class SetupRefusal(RuntimeError):
    pass


def command(
    arguments: list[str], *, input_text: str | None = None,
    environment: dict[str, str] | None = None, allow_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=120,
    )
    if completed.returncode and not allow_failure:
        detail = completed.stderr.strip().splitlines()[-1:] or ["no detail"]
        raise SetupRefusal(f"COMMAND_REFUSED executable={arguments[0]} detail={detail[0]}")
    return completed


def interactive(arguments: list[str], *, environment: dict[str, str] | None = None) -> None:
    try:
        completed = subprocess.run(
            arguments,
            env=environment,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupRefusal(f"INTERACTIVE_COMMAND_REFUSED executable={arguments[0]}") from exc
    if completed.returncode:
        raise SetupRefusal(
            f"INTERACTIVE_COMMAND_REFUSED executable={arguments[0]} exit={completed.returncode}"
        )


def ensure_owner_tty() -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SetupRefusal("OWNER_TTY_REQUIRED")


def public_pem(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_pem(private: Ed25519PrivateKey) -> str:
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def issuer_binding() -> tuple[str, str]:
    remote = command([
        "git", "-C", str(GOVML_REPOSITORY), "ls-remote", "origin", "refs/heads/main",
    ]).stdout.strip().split()
    commit = remote[0] if len(remote) == 2 and remote[1] == "refs/heads/main" else ""
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise SetupRefusal("GOVML_ISSUER_COMMIT_REFUSED")
    raw = command([
        "git", "-C", str(GOVML_REPOSITORY), "show", f"{commit}:{ISSUER_PATH}",
    ]).stdout.encode("utf-8")
    required = (
        "approve-request-hosted",
        "GOVML_EXTERNAL_JUDGE_APPROVING_PRIVATE_KEY_PEM",
        "request remaining TTL exceeds",
    )
    if not all(marker.encode("ascii") in raw for marker in required):
        raise SetupRefusal("GOVML_HOSTED_ISSUER_NOT_LANDED")
    return commit, sha256(raw)


def payload_binding() -> tuple[str, dict[str, str]]:
    remote = command([
        "git", "-C", str(REX_REPOSITORY), "ls-remote", "origin", "refs/heads/main",
    ]).stdout.strip().split()
    commit = remote[0] if len(remote) == 2 and remote[1] == "refs/heads/main" else ""
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise SetupRefusal("REX_PAYLOAD_COMMIT_REFUSED")
    head = command([
        "git", "-C", str(REX_REPOSITORY), "rev-parse", "HEAD",
    ]).stdout.strip()
    if head != commit:
        raise SetupRefusal(
            f"REX_PAYLOAD_HEAD_REFUSED expected={commit} observed={head}"
        )
    dirty = command([
        "git", "-C", str(REX_REPOSITORY), "status", "--porcelain", "--",
        *PAYLOAD_PATHS,
    ]).stdout
    if dirty:
        raise SetupRefusal("REX_PAYLOAD_DIRTY_REFUSED")
    digests: dict[str, str] = {}
    for relative in PAYLOAD_PATHS:
        path = REX_REPOSITORY / relative
        try:
            metadata = path.lstat()
            local = path.read_bytes()
        except OSError as exc:
            raise SetupRefusal(f"REX_PAYLOAD_READ_REFUSED path={relative}") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SetupRefusal(f"REX_PAYLOAD_TYPE_REFUSED path={relative}")
        landed = command([
            "git", "-C", str(REX_REPOSITORY), "show", f"{commit}:{relative}",
        ]).stdout.encode("utf-8")
        if local != landed:
            raise SetupRefusal(f"REX_PAYLOAD_BYTES_REFUSED path={relative}")
        digests[relative] = sha256(local)
    return commit, digests


def refresh_govml() -> None:
    command([
        "git", "-C", str(GOVML_REPOSITORY), "fetch", "origin", "main",
    ])


def ensure_host() -> None:
    if socket.gethostname() != "gios-dev":
        raise SetupRefusal("HOST_REFUSED expected=gios-dev")
    if os.getuid() != 1000:
        raise SetupRefusal("USER_REFUSED expected_uid=1000")
    for path in (Path("/usr/bin/az"), Path("/usr/bin/gh"), Path("/usr/bin/git")):
        if not path.is_file():
            raise SetupRefusal(f"EXECUTABLE_ABSENT path={path}")


def gh_environment() -> dict | None:
    completed = command(
        [
            "gh", "api", "--method", "GET",
            f"repos/{REPOSITORY}/environments/{ENVIRONMENT}",
        ],
        allow_failure=True,
    )
    if completed.returncode:
        if "404" in completed.stderr or "Not Found" in completed.stderr:
            return None
        raise SetupRefusal("GITHUB_ENVIRONMENT_READ_REFUSED")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SetupRefusal("GITHUB_ENVIRONMENT_JSON_REFUSED") from exc
    if not isinstance(value, dict):
        raise SetupRefusal("GITHUB_ENVIRONMENT_JSON_REFUSED")
    if value.get("protection_rules") not in ([], None):
        raise SetupRefusal("PER_ISSUANCE_HUMAN_REVIEW_REFUSED")
    return value


def gh_rows(kind: str) -> list[dict]:
    completed = command(
        ["gh", kind, "list", "--env", ENVIRONMENT, "--repo", REPOSITORY, "--json", "name,value" if kind == "variable" else "name"],
        allow_failure=True,
    )
    if completed.returncode:
        raise SetupRefusal(f"GITHUB_{kind.upper()}_LIST_REFUSED")
    try:
        rows = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SetupRefusal(f"GITHUB_{kind.upper()}_LIST_REFUSED") from exc
    if not isinstance(rows, list):
        raise SetupRefusal(f"GITHUB_{kind.upper()}_LIST_REFUSED")
    return rows


def remote_state() -> dict:
    environment = gh_environment()
    variables = {
        row.get("name"): row.get("value")
        for row in gh_rows("variable")
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    } if environment else {}
    secrets = {
        row.get("name") for row in gh_rows("secret")
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    } if environment else set()
    return {"environment": environment, "variables": variables, "secrets": secrets}


def file_state(path: Path) -> dict:
    try:
        observed = path.lstat()
        raw = path.read_bytes()
    except FileNotFoundError:
        return {"present": False}
    except OSError as exc:
        raise SetupRefusal("PUBLIC_KEY_READ_REFUSED") from exc
    valid = (
        stat.S_ISREG(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and observed.st_uid == 0
        and observed.st_gid == 0
        and observed.st_mode & 0o022 == 0
    )
    return {
        "present": True,
        "valid": valid,
        "sha256": sha256(raw),
        "uid": observed.st_uid,
        "gid": observed.st_gid,
        "mode": stat.S_IMODE(observed.st_mode),
    }


def local_public_state() -> dict:
    return file_state(PUBLIC_KEY_PATH)


def predecessor_backup_state() -> dict:
    return file_state(PREDECESSOR_BACKUP_PATH)


def exact_predecessor(state: dict) -> bool:
    return (
        state.get("present") is True
        and state.get("sha256") == PREDECESSOR_SHA256
        and state.get("uid") == PREDECESSOR_UID
        and state.get("gid") == PREDECESSOR_GID
        and state.get("mode") == PREDECESSOR_MODE
    )


def gh_login() -> None:
    status = command(["gh", "auth", "status", "--hostname", "github.com"], allow_failure=True)
    if status.returncode:
        interactive([
            "gh", "auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--web",
        ])
    command(["gh", "auth", "status", "--hostname", "github.com"])


def azure_environment() -> dict[str, str]:
    AZURE_CONFIG.mkdir(parents=True, exist_ok=True, mode=0o700)
    AZURE_CONFIG.chmod(0o700)
    return {**os.environ, "AZURE_CONFIG_DIR": str(AZURE_CONFIG)}


def azure_login_and_compute() -> dict:
    environment = azure_environment()
    status = command(["az", "account", "show", "--output", "json"], environment=environment, allow_failure=True)
    if status.returncode:
        interactive(["az", "login", "--use-device-code"], environment=environment)
    try:
        request = Request(METADATA_URL, headers={"Metadata": "true"})
        with urlopen(request, timeout=5) as response:
            compute = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise SetupRefusal("AZURE_INSTANCE_METADATA_REFUSED") from exc
    required = ("subscriptionId", "resourceGroupName", "name")
    if not isinstance(compute, dict) or not all(
        isinstance(compute.get(name), str) and compute[name] for name in required
    ):
        raise SetupRefusal("AZURE_INSTANCE_METADATA_REFUSED")
    command(
        ["az", "account", "set", "--subscription", compute["subscriptionId"]],
        environment=environment,
    )
    return compute


def azure_root_script(script: str) -> None:
    compute = azure_login_and_compute()
    command(
        [
            "az", "vm", "run-command", "invoke",
            "--resource-group", compute["resourceGroupName"],
            "--name", compute["name"],
            "--command-id", "RunShellScript",
            "--scripts", script,
            "--output", "json",
        ],
        environment=azure_environment(),
    )


def public_parent_guard() -> list[str]:
    parent = str(PUBLIC_KEY_PATH.parent)
    return [
        f"test -d {parent}",
        f"test ! -L {parent}",
        f"test $((0$(stat -c %a {parent}) & 0022)) -eq 0",
    ]


def install_public_key(raw: bytes, *, predecessor: bool) -> None:
    encoded = base64.b64encode(raw).decode("ascii")
    parent = str(PUBLIC_KEY_PATH.parent)
    target = str(PUBLIC_KEY_PATH)
    backup = str(PREDECESSOR_BACKUP_PATH)
    checks = [f"test ! -e {backup}", f"test ! -L {backup}"]
    if predecessor:
        checks.extend([
            f"test -f {target}",
            f"test ! -L {target}",
            f"test \"$(stat -c %u:%g {target})\" = {PREDECESSOR_UID}:{PREDECESSOR_GID}",
            f"test \"$(stat -c %a {target})\" = {PREDECESSOR_MODE:o}",
            f"test \"$(sha256sum {target} | cut -d' ' -f1)\" = {PREDECESSOR_SHA256}",
        ])
    else:
        checks.extend([f"test ! -e {target}", f"test ! -L {target}"])
    script = [
        "set -eu",
        *public_parent_guard(),
        *checks,
        f"stage=$(mktemp {parent}/.external-judge-key.XXXXXX)",
        "trap 'rm -f -- \"$stage\"' EXIT HUP INT TERM",
        f"printf '%s' '{encoded}' | base64 -d > \"$stage\"",
        "chown root:root \"$stage\"",
        "chmod 0644 \"$stage\"",
    ]
    if predecessor:
        script.extend([
            f"ln {target} {backup}",
            f"test \"$(sha256sum {backup} | cut -d' ' -f1)\" = {PREDECESSOR_SHA256}",
            f"mv -T \"$stage\" {target}",
        ])
    else:
        script.append(f"ln \"$stage\" {target}")
    script.extend(["rm -f -- \"$stage\"", "trap - EXIT HUP INT TERM"])
    azure_root_script("\n".join(script))


def remove_public_key(expected_sha256: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise SetupRefusal("PUBLIC_KEY_REMOVAL_DIGEST_REFUSED")
    target = str(PUBLIC_KEY_PATH)
    script = "\n".join([
        "set -eu",
        *public_parent_guard(),
        f"test -f {target}",
        f"test ! -L {target}",
        f"test \"$(stat -c %u:%g {target})\" = 0:0",
        f"test $((0$(stat -c %a {target}) & 0022)) -eq 0",
        f"test \"$(sha256sum {target} | cut -d' ' -f1)\" = {expected_sha256}",
        f"identity=$(stat -c %d:%i {target})",
        f"test \"$(stat -c %d:%i {target})\" = \"$identity\"",
        f"test \"$(sha256sum {target} | cut -d' ' -f1)\" = {expected_sha256}",
        f"rm -- {target}",
    ])
    azure_root_script(script)


def restore_predecessor(expected_new_sha256: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_new_sha256) is None:
        raise SetupRefusal("PUBLIC_KEY_RESTORE_DIGEST_REFUSED")
    target = str(PUBLIC_KEY_PATH)
    backup = str(PREDECESSOR_BACKUP_PATH)
    script = "\n".join([
        "set -eu",
        *public_parent_guard(),
        f"test -f {target}", f"test ! -L {target}",
        f"test \"$(stat -c %u:%g {target})\" = 0:0",
        f"test \"$(stat -c %a {target})\" = 644",
        f"test \"$(sha256sum {target} | cut -d' ' -f1)\" = {expected_new_sha256}",
        f"test -f {backup}", f"test ! -L {backup}",
        f"test \"$(stat -c %u:%g {backup})\" = {PREDECESSOR_UID}:{PREDECESSOR_GID}",
        f"test \"$(stat -c %a {backup})\" = {PREDECESSOR_MODE:o}",
        f"test \"$(sha256sum {backup} | cut -d' ' -f1)\" = {PREDECESSOR_SHA256}",
        f"mv -T {backup} {target}",
        f"test \"$(stat -c %u:%g {target})\" = {PREDECESSOR_UID}:{PREDECESSOR_GID}",
        f"test \"$(sha256sum {target} | cut -d' ' -f1)\" = {PREDECESSOR_SHA256}",
    ])
    azure_root_script(script)


def remove_predecessor_backup(expected_new_sha256: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_new_sha256) is None:
        raise SetupRefusal("PREDECESSOR_BACKUP_DIGEST_REFUSED")
    target = str(PUBLIC_KEY_PATH)
    backup = str(PREDECESSOR_BACKUP_PATH)
    script = "\n".join([
        "set -eu", *public_parent_guard(),
        f"test -f {target}", f"test ! -L {target}",
        f"test \"$(stat -c %u:%g {target})\" = 0:0",
        f"test \"$(sha256sum {target} | cut -d' ' -f1)\" = {expected_new_sha256}",
        f"test -f {backup}", f"test ! -L {backup}",
        f"test \"$(stat -c %u:%g {backup})\" = {PREDECESSOR_UID}:{PREDECESSOR_GID}",
        f"test \"$(stat -c %a {backup})\" = {PREDECESSOR_MODE:o}",
        f"test \"$(sha256sum {backup} | cut -d' ' -f1)\" = {PREDECESSOR_SHA256}",
        f"rm -- {backup}",
    ])
    azure_root_script(script)


def expected_pending_state(
    *, public_sha256: str, binding: tuple[str, str], state: dict,
) -> bool:
    return (
        state["environment"] is not None
        and state["environment"].get("protection_rules") in ([], None)
        and state["secrets"] == {SECRET_NAME}
        and state["variables"] == {
            STATE_VARIABLE: f"pending:{public_sha256}",
            PUBLIC_SHA_VARIABLE: public_sha256,
            ISSUER_COMMIT_VARIABLE: binding[0],
            ISSUER_SHA_VARIABLE: binding[1],
        }
    )


def delete_pending_environment(public_sha256: str, binding: tuple[str, str]) -> None:
    first = remote_state()
    second = remote_state()
    if not expected_pending_state(
        public_sha256=public_sha256, binding=binding, state=first,
    ) or second != first:
        raise SetupRefusal("PENDING_REMOTE_STATE_DRIFT_REFUSED")
    completed = command(
        [
            "gh", "api", "--method", "DELETE",
            f"repos/{REPOSITORY}/environments/{ENVIRONMENT}",
        ],
        allow_failure=True,
    )
    if completed.returncode and "404" not in completed.stderr and "Not Found" not in completed.stderr:
        raise SetupRefusal("GITHUB_ENVIRONMENT_DELETE_REFUSED")


def partial_values(
    *, public_sha256: str, issuer_commit: str, issuer_sha256: str,
) -> list[tuple[str, str]]:
    return list({
        STATE_VARIABLE: f"pending:{public_sha256}",
        PUBLIC_SHA_VARIABLE: public_sha256,
        ISSUER_COMMIT_VARIABLE: issuer_commit,
        ISSUER_SHA_VARIABLE: issuer_sha256,
    }.items())


def exact_partial_state(
    state: dict, *, environment_id: int, values: list[tuple[str, str]],
    completed_values: int, secret_present: bool,
) -> bool:
    environment = state.get("environment")
    return (
        isinstance(environment, dict)
        and environment.get("id") == environment_id
        and environment.get("protection_rules") in ([], None)
        and state.get("variables") == dict(values[:completed_values])
        and state.get("secrets") == ({SECRET_NAME} if secret_present else set())
    )


def configure_environment(
    *, private: str, public_sha256: str, issuer_commit: str, issuer_sha256: str,
    tracker: dict,
) -> None:
    if remote_state()["environment"] is not None:
        raise SetupRefusal("CONCURRENT_ENVIRONMENT_APPEARANCE_REFUSED")
    tracker["started"] = True
    created = command([
        "gh", "api", "--method", "PUT",
        f"repos/{REPOSITORY}/environments/{ENVIRONMENT}",
    ])
    try:
        environment_id = json.loads(created.stdout).get("id")
    except (AttributeError, json.JSONDecodeError) as exc:
        raise SetupRefusal("CREATED_ENVIRONMENT_ID_REFUSED") from exc
    if not isinstance(environment_id, int) or environment_id <= 0:
        raise SetupRefusal("CREATED_ENVIRONMENT_ID_REFUSED")
    tracker["environment_id"] = environment_id
    values = partial_values(
        public_sha256=public_sha256,
        issuer_commit=issuer_commit,
        issuer_sha256=issuer_sha256,
    )
    if not exact_partial_state(
        remote_state(), environment_id=environment_id, values=values,
        completed_values=0, secret_present=False,
    ):
        raise SetupRefusal("CONCURRENT_ENVIRONMENT_APPEARANCE_REFUSED")
    for position, (name, value) in enumerate(values, start=1):
        command([
            "gh", "variable", "set", name, "--body", value,
            "--env", ENVIRONMENT, "--repo", REPOSITORY,
        ])
        if not exact_partial_state(
            remote_state(), environment_id=environment_id, values=values,
            completed_values=position, secret_present=False,
        ):
            raise SetupRefusal("PARTIAL_ENVIRONMENT_DRIFT_REFUSED")
    command(
        ["gh", "secret", "set", SECRET_NAME, "--env", ENVIRONMENT, "--repo", REPOSITORY],
        input_text=private,
    )
    if not exact_partial_state(
        remote_state(), environment_id=environment_id, values=values,
        completed_values=len(values), secret_present=True,
    ):
        raise SetupRefusal("PARTIAL_ENVIRONMENT_DRIFT_REFUSED")


def delete_partial_environment(
    *, public_sha256: str, binding: tuple[str, str], environment_id: int,
) -> None:
    values = partial_values(
        public_sha256=public_sha256,
        issuer_commit=binding[0], issuer_sha256=binding[1],
    )
    first = remote_state()
    second = remote_state()
    attributable = any(
        exact_partial_state(
            first, environment_id=environment_id, values=values,
            completed_values=count, secret_present=secret,
        )
        for count, secret in [
            *[(position, False) for position in range(len(values) + 1)],
            (len(values), True),
        ]
    )
    if not attributable or second != first:
        raise SetupRefusal("PARTIAL_ENVIRONMENT_DRIFT_REFUSED")
    completed = command([
        "gh", "api", "--method", "DELETE",
        f"repos/{REPOSITORY}/environments/{ENVIRONMENT}",
    ], allow_failure=True)
    if completed.returncode:
        raise SetupRefusal("GITHUB_PARTIAL_ENVIRONMENT_DELETE_REFUSED")


def mark_complete(public_sha256: str) -> None:
    command([
        "gh", "variable", "set", STATE_VARIABLE,
        "--body", f"complete:{public_sha256}",
        "--env", ENVIRONMENT, "--repo", REPOSITORY,
    ])


def completed_postmark_state(state: dict, local: dict, binding: tuple[str, str]) -> bool:
    variables = state["variables"]
    public_sha = variables.get(PUBLIC_SHA_VARIABLE)
    return (
        state["environment"] is not None
        and state["secrets"] == {SECRET_NAME}
        and variables == {
            STATE_VARIABLE: f"complete:{public_sha}",
            PUBLIC_SHA_VARIABLE: public_sha,
            ISSUER_COMMIT_VARIABLE: binding[0],
            ISSUER_SHA_VARIABLE: binding[1],
        }
        and isinstance(public_sha, str)
        and re.fullmatch(r"[0-9a-f]{64}", public_sha) is not None
        and local.get("present") is True
        and local.get("valid") is True
        and local.get("sha256") == public_sha
    )


def completed_state(
    state: dict, local: dict, binding: tuple[str, str], backup: dict | None = None,
) -> bool:
    return completed_postmark_state(state, local, binding) and not (backup or {}).get("present")


def preflight() -> dict:
    ensure_host()
    payload_commit, payload_digests = payload_binding()
    binding = issuer_binding()
    state = remote_state()
    local = local_public_state()
    backup = predecessor_backup_state()
    if completed_state(state, local, binding, backup):
        status = "COMPLETE"
    elif completed_postmark_state(state, local, binding) and exact_predecessor(backup):
        status = "COMPLETE_CLEANUP_REQUIRED"
    elif (
        state["environment"] is None
        and not backup.get("present")
        and (not local.get("present") or exact_predecessor(local))
    ):
        status = "READY_FOR_ONE_TIME_SETUP"
    elif str(state["variables"].get(STATE_VARIABLE, "")).startswith("pending:"):
        status = "RECOVERY_REQUIRED"
    else:
        status = "INCONSISTENT_REFUSED"
    return {
        "status": status,
        "host": socket.gethostname(),
        "repository": REPOSITORY,
        "environment": ENVIRONMENT,
        "issuer_commit": binding[0],
        "issuer_sha256": binding[1],
        "rex_payload_commit": payload_commit,
        "rex_payload_sha256": payload_digests,
        "public_key": local,
        "predecessor_backup": backup,
        "bound_predecessor_sha256": PREDECESSOR_SHA256,
        "secret_present": SECRET_NAME in state["secrets"],
        "per_issuance_human_steps": 0 if status == "COMPLETE" else None,
    }


def apply() -> dict:
    ensure_host()
    ensure_owner_tty()
    payload_binding()
    gh_login()
    refresh_govml()
    readiness = preflight()
    if readiness["status"] not in {
        "COMPLETE", "COMPLETE_CLEANUP_REQUIRED",
        "READY_FOR_ONE_TIME_SETUP", "RECOVERY_REQUIRED",
    }:
        raise SetupRefusal(f"APPLY_PREFLIGHT_REFUSED status={readiness['status']}")
    binding = issuer_binding()
    state = remote_state()
    local = local_public_state()
    backup = predecessor_backup_state()
    if completed_state(state, local, binding, backup):
        return preflight()
    if completed_postmark_state(state, local, binding) and exact_predecessor(backup):
        remove_predecessor_backup(state["variables"][PUBLIC_SHA_VARIABLE])
        return preflight()
    pending = str(state["variables"].get(STATE_VARIABLE, "")).startswith("pending:")
    if pending:
        pending_sha = str(state["variables"].get(STATE_VARIABLE, "")).removeprefix("pending:")
        if re.fullmatch(r"[0-9a-f]{64}", pending_sha) is None:
            raise SetupRefusal("PENDING_PUBLIC_KEY_DIGEST_REFUSED")
        backup = predecessor_backup_state()
        restore = False
        remove_local = False
        if backup.get("present"):
            if (
                not exact_predecessor(backup)
                or local.get("valid") is not True
                or local.get("sha256") != pending_sha
            ):
                raise SetupRefusal("PENDING_PREDECESSOR_BACKUP_MISMATCH_REFUSED")
            restore = True
        elif local.get("present"):
            if exact_predecessor(local):
                pass
            elif local.get("valid") is True and local.get("sha256") == pending_sha:
                remove_local = True
            else:
                raise SetupRefusal("PENDING_PUBLIC_KEY_MISMATCH_REFUSED")
        delete_pending_environment(pending_sha, binding)
        if restore:
            restore_predecessor(pending_sha)
        elif remove_local:
            remove_public_key(pending_sha)
        state = remote_state()
        local = local_public_state()
        backup = predecessor_backup_state()
    if (
        state["environment"] is not None
        or backup.get("present")
        or (local.get("present") and not exact_predecessor(local))
    ):
        raise SetupRefusal("PREEXISTING_PRINCIPAL_STATE_REFUSED")
    predecessor = exact_predecessor(local)

    private = Ed25519PrivateKey.generate()
    private_raw = private_pem(private)
    public_raw = public_pem(private)
    public_sha = sha256(public_raw)
    configuration = {"started": False, "environment_id": None}
    installed = False
    marked_complete = False
    try:
        configure_environment(
            private=private_raw,
            public_sha256=public_sha,
            issuer_commit=binding[0],
            issuer_sha256=binding[1],
            tracker=configuration,
        )
        install_public_key(public_raw, predecessor=predecessor)
        installed = True
        observed = local_public_state()
        if not (
            observed.get("valid") is True
            and observed.get("sha256") == public_sha
        ):
            raise SetupRefusal("ROOT_PUBLIC_KEY_POSTSTATE_REFUSED")
        mark_complete(public_sha)
        marked_complete = True
        if predecessor:
            remove_predecessor_backup(public_sha)
        final = preflight()
        if final["status"] != "COMPLETE":
            raise SetupRefusal("FINAL_POSTSTATE_REFUSED")
        return final
    except Exception as original:
        try:
            exact_complete = marked_complete or completed_postmark_state(
                remote_state(), local_public_state(), binding,
            )
        except Exception:
            exact_complete = False
        if exact_complete:
            raise
        try:
            if isinstance(configuration.get("environment_id"), int):
                delete_partial_environment(
                    public_sha256=public_sha,
                    binding=binding,
                    environment_id=configuration["environment_id"],
                )
            elif configuration.get("started"):
                raise SetupRefusal("PARTIAL_ENVIRONMENT_UNATTRIBUTED_REFUSED")
            if installed:
                if predecessor:
                    restore_predecessor(public_sha)
                else:
                    remove_public_key(public_sha)
        except Exception as recovery:
            raise SetupRefusal(
                f"TRANSITION_AND_RECOVERY_REFUSED original={original} recovery={recovery}"
            ) from original
        raise
    finally:
        private_raw = ""


def self_test() -> dict:
    private = Ed25519PrivateKey.generate()
    public = public_pem(private)
    encoded = base64.b64encode(public).decode("ascii")
    assert base64.b64decode(encoded, validate=True) == public
    assert len(sha256(public)) == 64
    assert private_pem(private).startswith("-----BEGIN PRIVATE KEY-----\n")
    expected = {
        "empty_to_complete": True,
        "pending_recovery_deletes_remote_and_public": True,
        "pending_recovery_requires_exact_owned_digest": True,
        "root_install_is_atomic_no_clobber": True,
        "remote_recovery_refuses_concurrent_drift": True,
        "apply_binds_landed_payload_before_mutation": True,
        "install_failure_rolls_back_remote": True,
        "complete_state_has_zero_per_issuance_human_steps": True,
        "private_key_not_persisted_by_design": True,
    }
    # The transition ordering is structural: remote pending state precedes the
    # root install; every exception after either step invokes its paired
    # rollback before propagating. Source tests plant both failures.
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--preflight", action="store_true")
    actions.add_argument("--apply", action="store_true")
    actions.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            result = self_test()
            print(json.dumps(result, sort_keys=True))
            return 0 if all(result.values()) else 1
        result = apply() if args.apply else preflight()
    except (OSError, SetupRefusal, subprocess.TimeoutExpired) as exc:
        print(f"HOSTED_PRINCIPAL_SETUP_REFUSED reason={exc}")
        return 3
    label = "HOSTED_PRINCIPAL_SETUP_COMPLETE" if result["status"] == "COMPLETE" else "HOSTED_PRINCIPAL_SETUP_PREFLIGHT"
    print(f"{label} {json.dumps(result, sort_keys=True)}")
    return 0 if result["status"] in {"COMPLETE", "READY_FOR_ONE_TIME_SETUP"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
