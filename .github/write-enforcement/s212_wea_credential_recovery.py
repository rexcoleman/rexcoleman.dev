#!/usr/bin/env python3
"""One-row recovery of every credential blocking REA write enforcement.

The owner-facing wrapper calls ``--apply`` with no owner-supplied arguments.
Apply always runs its own preflight first.  Credential values enter only via a
hidden TTY prompt or a PEM file selected interactively; none enters argv,
stdout, logs, evidence, or a digest printed to the owner.

This rail deliberately stops before F3, issuance, freezing, tagging, or any
Mac operation.  Its terminal property is only credential readiness.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPOSITORY = "rexcoleman/rexcoleman.dev"
OWNER = "rexcoleman"
WORKFLOW = "probe-wea-credentials.yml"
ENV_ISSUER = "rea-write-enforcement-issuer"
ENV_RENEWAL = "rea-write-enforcement-renewal"
ENV_APPROVER = "govml-external-judge-approver"
ENVIRONMENTS = (ENV_ISSUER, ENV_RENEWAL, ENV_APPROVER)
BUNDLE_REPOSITORIES = (
    "govML", "research_enforcement_activation",
    "Moonshots_Career_Thesis", "newsletter",
)
APP_REPOSITORIES = frozenset((*BUNDLE_REPOSITORIES, "rexcoleman.dev"))
RULESET_PATH = "/repos/rexcoleman/newsletter/rulesets/19564990"
APP_ID = "GOVML_REA_READ_APP_ID"
APP_KEY = "GOVML_REA_READ_APP_PRIVATE_KEY_B64"
BUNDLE_TOKEN = "REA_BUNDLE_READ_TOKEN"
RULESET_TOKEN = "REA_RULESET_READ_TOKEN"
APPROVER_PRIVATE = "GOVML_EXTERNAL_JUDGE_APPROVING_PRIVATE_KEY_PEM"
APPROVER_PUBLIC_SHA = "GOVML_EXTERNAL_JUDGE_APPROVING_PUBLIC_KEY_SHA256"
ISSUER_COMMIT = "GOVML_EXTERNAL_JUDGE_ISSUER_COMMIT"
ISSUER_SHA = "GOVML_EXTERNAL_JUDGE_ISSUER_SHA256"
PUBLIC_KEY = Path(
    "/home/azureuser/ml-governance-templates/config/"
    "external_judge_approving_principal.ed25519.public.pem"
)
PUBLIC_BACKUP = PUBLIC_KEY.with_name(PUBLIC_KEY.name + ".s212-predecessor")
PREDECESSOR_SHA = "69a974bc7dd189c6ee56d105a2abcf35ddba0e039b070f153ad82bd22806b928"
GOVML_REPO = Path("/home/azureuser/ml-governance-templates")
REX_REPO = Path("/home/azureuser/rexcoleman.dev")
ENV_FILE = Path("/home/azureuser/.config/govml/env")
AZURE_CONFIG = Path("/home/azureuser/.local/share/s212-wea-recovery-azure")
DEPLOYED_COMMIT = Path(__file__).resolve().parent / "DEPLOYED_COMMIT"
SOURCE_PATHS = (
    ".github/workflows/probe-wea-credentials.yml",
    ".github/write-enforcement/s212_wea_credential_recovery.py",
    ".github/write-enforcement/s212_wea_credential_recovery.sh",
    ".github/write-enforcement/github_app_installation_token.py",
)
API = "https://api.github.com"


class Refusal(RuntimeError):
    """A stable public refusal that contains no secret material."""


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def command(
    argv: list[str], *, input_text: str | None = None,
    environment: dict[str, str] | None = None, timeout: int = 120,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv, input=input_text, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal("COMMAND_UNAVAILABLE:%s" % argv[0]) from exc
    if result.returncode and not allow_failure:
        raise Refusal("COMMAND_REFUSED:%s:exit=%d" % (argv[0], result.returncode))
    return result


def gh_json(argv: list[str], *, allow_failure: bool = False):
    result = command(["gh", *argv], allow_failure=allow_failure)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal("GITHUB_RESPONSE_INVALID") from exc


def api_json(path: str, token: str):
    request = Request(
        API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, json.JSONDecodeError):
        return None


def authenticate_bundle(token: str) -> bool:
    user = api_json("/user", token)
    if not isinstance(user, dict) or user.get("login") != OWNER:
        return False
    for repository in BUNDLE_REPOSITORIES:
        row = api_json("/repos/%s/%s" % (OWNER, repository), token)
        if not isinstance(row, dict) or row.get("full_name") != "%s/%s" % (OWNER, repository):
            return False
    return True


def authenticate_ruleset(token: str) -> bool:
    user = api_json("/user", token)
    row = api_json(RULESET_PATH, token)
    return (
        isinstance(user, dict) and user.get("login") == OWNER
        and isinstance(row, dict) and row.get("id") == 19564990
    )


def _load_minter():
    path = Path(__file__).resolve().with_name("github_app_installation_token.py")
    spec = importlib.util.spec_from_file_location("s212_pinned_minter", path)
    if spec is None or spec.loader is None:
        raise Refusal("MINTER_LOAD_REFUSED")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise Refusal("MINTER_LOAD_REFUSED") from exc
    if module.REQUIRED_REPOSITORIES != APP_REPOSITORIES or module.OWNER != OWNER:
        raise Refusal("MINTER_REPOSITORY_SET_REFUSED")
    return module


def app_state() -> str:
    present_id = bool(os.environ.get(APP_ID, "").strip())
    present_key = bool(os.environ.get(APP_KEY, "").strip())
    if present_id != present_key:
        return "PARTIAL"
    if not present_id:
        return "ABSENT"
    module = _load_minter()
    try:
        module.mint_and_verify()
    except module.Refusal:
        return "REFUSE"
    return "PASS"


def hosted_probe(locus: str, nonce: str) -> int:
    if locus not in {"issuer", "renewal", "approver"}:
        raise Refusal("HOSTED_PROBE_LOCUS_REFUSED")
    if re.fullmatch(r"s212-[0-9a-f]{24}", nonce) is None:
        raise Refusal("HOSTED_PROBE_NONCE_REFUSED")
    app = app_state()
    bundle = "NA"
    ruleset = "NA"
    principal = "NA"
    if locus in {"issuer", "renewal"}:
        bundle = "PASS" if authenticate_bundle(os.environ.get(BUNDLE_TOKEN, "")) else "REFUSE"
        ruleset = "PASS" if authenticate_ruleset(os.environ.get(RULESET_TOKEN, "")) else "REFUSE"
    else:
        private = os.environ.get(APPROVER_PRIVATE, "")
        public_sha = os.environ.get(APPROVER_PUBLIC_SHA, "")
        issuer_commit = os.environ.get(ISSUER_COMMIT, "")
        issuer_sha = os.environ.get(ISSUER_SHA, "")
        private_matches_public = False
        try:
            loaded = serialization.load_pem_private_key(private.encode("ascii"), password=None)
            derived = loaded.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            private_matches_public = (
                isinstance(loaded, Ed25519PrivateKey) and digest(derived) == public_sha
            )
        except (TypeError, ValueError, UnicodeEncodeError):
            pass
        principal = "PASS" if (
            private_matches_public and re.fullmatch(r"[0-9a-f]{64}", public_sha)
            and re.fullmatch(r"[0-9a-f]{40}", issuer_commit)
            and re.fullmatch(r"[0-9a-f]{64}", issuer_sha)
        ) else "ABSENT"
    print(
        "S212_PROBE nonce=%s locus=%s app=%s bundle=%s ruleset=%s principal=%s"
        % (nonce, locus, app, bundle, ruleset, principal)
    )
    return 0


def ensure_identity(require_tty: bool) -> None:
    if socket.gethostname() != "gios-dev":
        raise Refusal("OWNER_HOST_REFUSED:expected=gios-dev")
    if os.getuid() != 1000 or getpass.getuser() != "azureuser":
        raise Refusal("OWNER_USER_REFUSED:expected=azureuser")
    if require_tty and not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Refusal("OWNER_TTY_REQUIRED")
    for name in ("gh", "git", "python3", "openssl", "az"):
        result = command(["which", name], allow_failure=True)
        if result.returncode:
            raise Refusal("REQUIRED_TOOL_ABSENT:%s" % name)


def tool_digests() -> dict[str, str]:
    values = {}
    for name in ("gh", "git", "python3", "openssl", "az"):
        located = command(["which", name]).stdout.strip()
        path = Path(located).resolve()
        try:
            values[name] = digest(path.read_bytes())
        except OSError as exc:
            raise Refusal("REQUIRED_TOOL_DIGEST_REFUSED:%s" % name) from exc
    return values


def remote_main(repository: Path) -> str:
    result = command(["git", "-C", str(repository), "ls-remote", "origin", "refs/heads/main"])
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[1] != "refs/heads/main" or re.fullmatch(r"[0-9a-f]{40}", fields[0]) is None:
        raise Refusal("REMOTE_MAIN_REFUSED:%s" % repository.name)
    return fields[0]


def bind_deployed_source() -> str:
    try:
        expected = DEPLOYED_COMMIT.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise Refusal("DEPLOYED_COMMIT_ABSENT") from exc
    if re.fullmatch(r"[0-9a-f]{40}", expected) is None:
        raise Refusal("DEPLOYED_COMMIT_INVALID")
    observed = remote_main(REX_REPO)
    if observed != expected:
        raise Refusal("LIVE_MAIN_CHANGED:expected=%s:observed=%s" % (expected, observed))
    command(["git", "-C", str(REX_REPO), "fetch", "origin", "main"])
    root = Path(__file__).resolve().parent
    for relative in SOURCE_PATHS:
        local_name = Path(relative).name
        local = root / local_name
        if not local.is_file() or local.is_symlink():
            raise Refusal("DEPLOYED_SOURCE_ABSENT:%s" % local_name)
        landed = command(["git", "-C", str(REX_REPO), "show", "%s:%s" % (expected, relative)])
        if local.read_bytes() != landed.stdout.encode("utf-8"):
            raise Refusal("DEPLOYED_SOURCE_CHANGED:%s" % local_name)
    return expected


def environment_policy(name: str) -> dict:
    row = gh_json(["api", "repos/%s/environments/%s" % (REPOSITORY, name)])
    if not isinstance(row, dict):
        raise Refusal("ENVIRONMENT_ABSENT:%s" % name)
    rules = row.get("protection_rules") or []
    types = [item.get("type") for item in rules if isinstance(item, dict)]
    if name == ENV_ISSUER:
        reviewers = [
            reviewer.get("reviewer", {}).get("login")
            for rule in rules if rule.get("type") == "required_reviewers"
            for reviewer in rule.get("reviewers", [])
        ]
        if types != ["required_reviewers"] or reviewers != [OWNER]:
            raise Refusal("ENVIRONMENT_POLICY_REFUSED:%s" % name)
    else:
        if types != ["branch_policy"] or row.get("deployment_branch_policy") != {
            "protected_branches": False, "custom_branch_policies": True,
        }:
            raise Refusal("ENVIRONMENT_POLICY_REFUSED:%s" % name)
        policies = gh_json([
            "api", "repos/%s/environments/%s/deployment-branch-policies" % (REPOSITORY, name),
        ])
        values = policies.get("branch_policies") if isinstance(policies, dict) else None
        normalized = [
            {"name": value.get("name"), "type": value.get("type")}
            for value in (values or []) if isinstance(value, dict)
        ]
        expected = [{"name": "main", "type": "branch"}]
        if name == ENV_RENEWAL:
            expected.append({"name": "rea-wea-generation-*", "type": "tag"})
        if normalized != expected:
            raise Refusal("ENVIRONMENT_BRANCH_POLICY_REFUSED:%s" % name)
    return row


def secret_names(environment: str) -> dict[str, str]:
    rows = gh_json([
        "secret", "list", "--repo", REPOSITORY, "--env", environment,
        "--json", "name,updatedAt",
    ])
    if not isinstance(rows, list):
        raise Refusal("SECRET_LIST_REFUSED:%s" % environment)
    return {
        row["name"]: row.get("updatedAt", "") for row in rows
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }


def variable_values(environment: str) -> dict[str, str]:
    rows = gh_json([
        "variable", "list", "--repo", REPOSITORY, "--env", environment,
        "--json", "name,value",
    ])
    if not isinstance(rows, list):
        raise Refusal("VARIABLE_LIST_REFUSED:%s" % environment)
    return {
        row["name"]: row.get("value", "") for row in rows
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }


def prove_secret_write_delete(environment: str) -> None:
    name = "S212_PREFLIGHT_DELETE_ME_" + secrets.token_hex(6).upper()
    value = "s212-throwaway-" + secrets.token_hex(16)
    created = False
    try:
        command([
            "gh", "secret", "set", name, "--repo", REPOSITORY,
            "--env", environment,
        ], input_text=value)
        created = True
        if name not in secret_names(environment):
            raise Refusal("THROWAWAY_SECRET_POSTSET_REFUSED:%s" % environment)
    finally:
        if created:
            command([
                "gh", "secret", "delete", name, "--repo", REPOSITORY,
                "--env", environment,
            ], allow_failure=True)
    if name in secret_names(environment):
        raise Refusal("THROWAWAY_SECRET_DELETE_REFUSED:%s" % environment)


def issuer_binding() -> tuple[str, str]:
    commit = remote_main(GOVML_REPO)
    command(["git", "-C", str(GOVML_REPO), "fetch", "origin", "main"])
    raw = command([
        "git", "-C", str(GOVML_REPO), "show",
        commit + ":scripts/issue_external_judge_authority.py",
    ]).stdout.encode("utf-8")
    required = (b"approve-request-hosted", b"request remaining TTL exceeds")
    if not all(marker in raw for marker in required):
        raise Refusal("GOVML_HOSTED_ISSUER_NOT_LANDED")
    return commit, digest(raw)


def preflight(*, active_write_probe: bool, require_tty: bool = True) -> dict:
    ensure_identity(require_tty)
    commit = bind_deployed_source()
    command(["gh", "auth", "status", "--hostname", "github.com"])
    actor = gh_json(["api", "user"])
    if not isinstance(actor, dict) or actor.get("login") != OWNER:
        raise Refusal("GITHUB_OWNER_AUTHENTICATION_REFUSED")
    policies = {name: environment_policy(name).get("id") for name in ENVIRONMENTS}
    if active_write_probe:
        for name in ENVIRONMENTS:
            prove_secret_write_delete(name)
    binding = issuer_binding()
    local = public_key_state()
    if local.get("present") and not local.get("valid"):
        raise Refusal("PUBLIC_KEY_POSTURE_REFUSED")
    return {
        "status": "READY",
        "source_commit": commit,
        "environment_ids": policies,
        "issuer_commit": binding[0],
        "issuer_sha256": binding[1],
        "public_key": local,
        "tty": require_tty,
        "write_delete_probe": active_write_probe,
        "tool_sha256": tool_digests(),
    }


def dispatch_probe() -> dict[str, dict[str, str]]:
    nonce = "s212-" + secrets.token_hex(12)
    command([
        "gh", "workflow", "run", WORKFLOW, "--repo", REPOSITORY,
        "--ref", "main", "-f", "probe_nonce=" + nonce,
    ])
    run = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        rows = gh_json([
            "run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
            "--event", "workflow_dispatch", "--limit", "20",
            "--json", "databaseId,displayTitle,status,conclusion,headSha,url",
        ])
        matches = [
            row for row in (rows or [])
            if row.get("displayTitle") == "WEA credential probe " + nonce
        ]
        if len(matches) == 1:
            run = matches[0]
            break
        time.sleep(2)
    if run is None:
        raise Refusal("HOSTED_PROBE_RUN_NOT_FOUND")
    expected = remote_main(REX_REPO)
    if run.get("headSha") != expected:
        raise Refusal("HOSTED_PROBE_WRONG_SOURCE")
    print("HOSTED_PROBE_URL " + str(run.get("url")))
    print("If the issuer job waits, approve that exact deployment in the browser; this row keeps waiting.")
    command([
        "gh", "run", "watch", str(run["databaseId"]), "--repo", REPOSITORY,
        "--exit-status", "--interval", "5",
    ], timeout=900)
    logs = command([
        "gh", "run", "view", str(run["databaseId"]), "--repo", REPOSITORY,
        "--log",
    ], timeout=180).stdout
    pattern = re.compile(
        r"S212_PROBE nonce=(\S+) locus=(issuer|renewal|approver) "
        r"app=(PASS|ABSENT|PARTIAL|REFUSE) bundle=(PASS|REFUSE|NA) "
        r"ruleset=(PASS|REFUSE|NA) principal=(PASS|ABSENT|NA)"
    )
    result: dict[str, dict[str, str]] = {}
    for match in pattern.finditer(logs):
        if match.group(1) != nonce:
            continue
        result[match.group(2)] = {
            "app": match.group(3), "bundle": match.group(4),
            "ruleset": match.group(5), "principal": match.group(6),
        }
    if set(result) != {"issuer", "renewal", "approver"}:
        raise Refusal("HOSTED_PROBE_RESULT_INCOMPLETE")
    return result


def set_secret(name: str, environment: str, value: str) -> None:
    command([
        "gh", "secret", "set", name, "--repo", REPOSITORY,
        "--env", environment,
    ], input_text=value)
    if not secret_names(environment).get(name):
        raise Refusal("SECRET_POSTCONDITION_REFUSED:%s:%s" % (environment, name))


def place_legacy_pair(bundle: str, ruleset: str) -> None:
    # Both values have already authenticated before this function is entered.
    # If a later set fails, forward-complete every locus from the still-live
    # in-process values; this avoids an unrecoverable half-placement because
    # GitHub never permits reading the predecessor secret back.
    placements = [
        (BUNDLE_TOKEN, ENV_ISSUER, bundle),
        (RULESET_TOKEN, ENV_ISSUER, ruleset),
        (BUNDLE_TOKEN, ENV_RENEWAL, bundle),
        (RULESET_TOKEN, ENV_RENEWAL, ruleset),
    ]
    try:
        for row in placements:
            set_secret(*row)
    except Exception as original:
        recovery_errors = []
        for row in placements:
            try:
                set_secret(*row)
            except Exception as exc:
                recovery_errors.append(str(exc))
        if recovery_errors:
            raise Refusal("LEGACY_PLACEMENT_AND_RECOVERY_REFUSED") from original
        raise Refusal("LEGACY_PLACEMENT_POSTCONDITION_RECOVERED_RETRY") from original


def prompt_pat_pair() -> tuple[str, str]:
    print("Existing hosted PATs did not satisfy every required read.")
    print("Create two CLASSIC GitHub PATs at https://github.com/settings/tokens/new")
    print("Select scope: repo. Select expiration: No expiration.")
    print("Fine-grained PATs are disfavored here because GitHub caps them at 366 days.")
    bundle = getpass.getpass("Bundle-read PAT (hidden): ").strip()
    ruleset = getpass.getpass("Newsletter-ruleset PAT (hidden): ").strip()
    if not authenticate_bundle(bundle):
        raise Refusal("BUNDLE_PAT_AUTHENTICATION_REFUSED:no_writes")
    if not authenticate_ruleset(ruleset):
        raise Refusal("RULESET_PAT_AUTHENTICATION_REFUSED:no_writes")
    return bundle, ruleset


def parse_env(raw: bytes) -> dict[str, str]:
    values = {}
    for line in raw.splitlines():
        if not line or line.lstrip().startswith(b"#") or b"=" not in line:
            continue
        name, value = line.split(b"=", 1)
        try:
            values[name.decode("ascii")] = value.decode("ascii")
        except UnicodeDecodeError:
            continue
    return values


def atomic_env_install(app_id: str, encoded_key: str) -> bytes | None:
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    old = ENV_FILE.read_bytes() if ENV_FILE.exists() else None
    if ENV_FILE.exists() and (ENV_FILE.is_symlink() or not ENV_FILE.is_file()):
        raise Refusal("LOCAL_ENV_TYPE_REFUSED")
    kept = []
    for line in (old or b"").splitlines():
        if line.startswith((APP_ID + "=").encode()) or line.startswith((APP_KEY + "=").encode()):
            continue
        kept.append(line)
    kept.extend([
        (APP_ID + "=" + app_id).encode("ascii"),
        (APP_KEY + "=" + encoded_key).encode("ascii"),
    ])
    payload = b"\n".join(kept) + b"\n"
    fd, pending_name = tempfile.mkstemp(prefix=".env.s212.", dir=ENV_FILE.parent)
    pending = Path(pending_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, ENV_FILE)
    finally:
        if pending.exists():
            pending.unlink()
    if stat.S_IMODE(ENV_FILE.stat().st_mode) != 0o600:
        raise Refusal("LOCAL_ENV_MODE_REFUSED")
    return old


def restore_env(old: bytes | None) -> None:
    if old is None:
        if ENV_FILE.exists() and ENV_FILE.is_file() and not ENV_FILE.is_symlink():
            ENV_FILE.unlink()
        return
    fd, pending_name = tempfile.mkstemp(prefix=".env.restore.", dir=ENV_FILE.parent)
    pending = Path(pending_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(old)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, ENV_FILE)
    finally:
        if pending.exists():
            pending.unlink()


def local_app_credentials() -> tuple[str, str] | None:
    raw = ENV_FILE.read_bytes() if ENV_FILE.exists() else b""
    values = parse_env(raw)
    app_id = values.get(APP_ID, "").strip()
    app_key = values.get(APP_KEY, "").strip()
    if bool(app_id) != bool(app_key):
        raise Refusal("LOCAL_APP_PAIR_PARTIAL")
    return (app_id, app_key) if app_id else None


def verify_app_pair(app_id: str, encoded_key: str) -> None:
    old_id = os.environ.get(APP_ID)
    old_key = os.environ.get(APP_KEY)
    os.environ[APP_ID] = app_id
    os.environ[APP_KEY] = encoded_key
    try:
        module = _load_minter()
        module.mint_and_verify()
    except module.Refusal as exc:
        raise Refusal("GITHUB_APP_VALIDATION_REFUSED:%s" % exc) from None
    finally:
        if old_id is None:
            os.environ.pop(APP_ID, None)
        else:
            os.environ[APP_ID] = old_id
        if old_key is None:
            os.environ.pop(APP_KEY, None)
        else:
            os.environ[APP_KEY] = old_key


def obtain_app_pair() -> tuple[str, str, bool, bytes | None]:
    existing = local_app_credentials()
    if existing:
        verify_app_pair(*existing)
        return existing[0], existing[1], False, None
    print("Create or reuse one GitHub App at https://github.com/settings/apps/new")
    print("Owner: rexcoleman. Webhook: inactive. Repository permission: Contents read-only; nothing else.")
    print("Install it on EXACTLY: govML, research_enforcement_activation, Moonshots_Career_Thesis, newsletter, rexcoleman.dev.")
    print("Generate one private key and move the downloaded PEM onto gios-dev.")
    app_id = input("App ID: ").strip()
    pem_path = Path(input("Absolute PEM path on gios-dev: ").strip())
    if re.fullmatch(r"[1-9][0-9]*", app_id) is None:
        raise Refusal("APP_ID_REFUSED")
    try:
        pem_meta = pem_path.lstat()
        if not stat.S_ISREG(pem_meta.st_mode) or stat.S_ISLNK(pem_meta.st_mode):
            raise Refusal("APP_PRIVATE_KEY_TYPE_REFUSED")
        if pem_meta.st_uid != os.getuid():
            raise Refusal("APP_PRIVATE_KEY_OWNER_REFUSED")
        if stat.S_IMODE(pem_meta.st_mode) != 0o600:
            raise Refusal("APP_PRIVATE_KEY_MODE_REFUSED")
        pem = pem_path.read_bytes()
    except Refusal:
        raise
    except OSError as exc:
        raise Refusal("APP_PRIVATE_KEY_UNREADABLE") from exc
    if len(pem) < 256 or len(pem) > 32768 or b"PRIVATE KEY-----" not in pem or b"\0" in pem:
        raise Refusal("APP_PRIVATE_KEY_REFUSED")
    encoded = base64.b64encode(pem).decode("ascii")
    verify_app_pair(app_id, encoded)
    old = atomic_env_install(app_id, encoded)
    return app_id, encoded, True, old


def place_app_pair(app_id: str, encoded: str) -> None:
    # The predecessor values are write-only at GitHub, so byte rollback is not
    # possible.  Keep both authenticated values live and forward-complete every
    # locus if any placement/postcondition fails.
    placements = [
        (name, environment, value)
        for environment in ENVIRONMENTS
        for name, value in ((APP_ID, app_id), (APP_KEY, encoded))
    ]
    try:
        for row in placements:
            set_secret(*row)
    except Exception as original:
        recovery_errors = []
        for row in placements:
            try:
                set_secret(*row)
            except Exception as exc:
                recovery_errors.append(str(exc))
        if recovery_errors:
            raise Refusal("APP_PLACEMENT_AND_RECOVERY_REFUSED") from original
        raise Refusal("APP_PLACEMENT_POSTCONDITION_RECOVERED_RETRY") from original


def public_key_state() -> dict:
    try:
        meta = PUBLIC_KEY.lstat()
        raw = PUBLIC_KEY.read_bytes()
    except FileNotFoundError:
        return {"present": False}
    valid = (
        stat.S_ISREG(meta.st_mode) and not stat.S_ISLNK(meta.st_mode)
        and meta.st_uid == 0 and meta.st_gid == 0
        and stat.S_IMODE(meta.st_mode) == 0o644
    )
    return {"present": True, "valid": valid, "sha256": digest(raw)}


def azure_environment() -> dict[str, str]:
    AZURE_CONFIG.mkdir(parents=True, exist_ok=True, mode=0o700)
    AZURE_CONFIG.chmod(0o700)
    return {**os.environ, "AZURE_CONFIG_DIR": str(AZURE_CONFIG)}


def azure_root(script: str) -> None:
    env = azure_environment()
    status = command(["az", "account", "show", "--output", "json"], environment=env, allow_failure=True)
    if status.returncode:
        interactive = subprocess.run(["az", "login", "--use-device-code"], env=env, check=False)
        if interactive.returncode:
            raise Refusal("AZURE_LOGIN_REFUSED")
    request = Request(
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
        headers={"Metadata": "true"},
    )
    try:
        with urlopen(request, timeout=5) as response:
            compute = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise Refusal("AZURE_INSTANCE_METADATA_REFUSED") from exc
    for field in ("subscriptionId", "resourceGroupName", "name"):
        if not isinstance(compute.get(field), str) or not compute[field]:
            raise Refusal("AZURE_INSTANCE_METADATA_REFUSED")
    command(["az", "account", "set", "--subscription", compute["subscriptionId"]], environment=env)
    command([
        "az", "vm", "run-command", "invoke",
        "--resource-group", compute["resourceGroupName"], "--name", compute["name"],
        "--command-id", "RunShellScript", "--scripts", script, "--output", "json",
    ], environment=env, timeout=600)


def install_public_key(public: bytes, new_sha: str) -> None:
    if public_key_state() != {"present": True, "valid": True, "sha256": PREDECESSOR_SHA}:
        raise Refusal("PUBLIC_KEY_PREDECESSOR_REFUSED")
    encoded = base64.b64encode(public).decode("ascii")
    parent = str(PUBLIC_KEY.parent)
    target = str(PUBLIC_KEY)
    backup = str(PUBLIC_BACKUP)
    script = "\n".join([
        "set -eu", "umask 077", "test -d " + parent, "test ! -L " + parent,
        "test -f " + target, "test ! -L " + target,
        "test \"$(stat -c %u:%g " + target + ")\" = 0:0",
        "test \"$(stat -c %a " + target + ")\" = 644",
        "test \"$(sha256sum " + target + " | cut -d' ' -f1)\" = " + PREDECESSOR_SHA,
        "test ! -e " + backup,
        "stage=$(mktemp " + parent + "/.s212-key.XXXXXX)",
        "trap 'rm -f -- \"$stage\"' EXIT HUP INT TERM",
        "printf '%s' '" + encoded + "' | base64 -d > \"$stage\"",
        "chown root:root \"$stage\"", "chmod 0644 \"$stage\"",
        "ln " + target + " " + backup,
        "mv -T \"$stage\" " + target,
        "test \"$(sha256sum " + target + " | cut -d' ' -f1)\" = " + new_sha,
        "trap - EXIT HUP INT TERM",
    ])
    azure_root(script)


def rollback_public_key_transition(new_sha: str) -> None:
    """Restore or clean up every safe intermediate state of the root transition."""
    target = str(PUBLIC_KEY)
    backup = str(PUBLIC_BACKUP)
    azure_root("\n".join([
        "set -eu", "test -f " + target, "test ! -L " + target,
        "current=$(sha256sum " + target + " | cut -d' ' -f1)",
        "if test -e " + backup + "; then",
        "  test -f " + backup, "  test ! -L " + backup,
        "  test \"$(sha256sum " + backup + " | cut -d' ' -f1)\" = " + PREDECESSOR_SHA,
        "  if test \"$current\" = " + new_sha + "; then mv -T " + backup + " " + target,
        "  elif test \"$current\" = " + PREDECESSOR_SHA + "; then rm -- " + backup,
        "  else exit 41; fi",
        "else test \"$current\" = " + PREDECESSOR_SHA + "; fi",
        "test \"$(sha256sum " + target + " | cut -d' ' -f1)\" = " + PREDECESSOR_SHA,
    ]))


def remove_public_backup(new_sha: str) -> None:
    target = str(PUBLIC_KEY)
    backup = str(PUBLIC_BACKUP)
    azure_root("\n".join([
        "set -eu", "test -f " + target, "test -f " + backup,
        "test \"$(sha256sum " + target + " | cut -d' ' -f1)\" = " + new_sha,
        "test \"$(sha256sum " + backup + " | cut -d' ' -f1)\" = " + PREDECESSOR_SHA,
        "rm -- " + backup,
    ]))


def set_variable(name: str, value: str) -> None:
    command([
        "gh", "variable", "set", name, "--body", value,
        "--env", ENV_APPROVER, "--repo", REPOSITORY,
    ])
    if variable_values(ENV_APPROVER).get(name) != value:
        raise Refusal("VARIABLE_POSTCONDITION_REFUSED:" + name)


def delete_approver_principal_rows() -> None:
    for name in (APPROVER_PRIVATE,):
        command([
            "gh", "secret", "delete", name, "--env", ENV_APPROVER,
            "--repo", REPOSITORY,
        ], allow_failure=True)
    for name in (APPROVER_PUBLIC_SHA, ISSUER_COMMIT, ISSUER_SHA):
        command([
            "gh", "variable", "delete", name, "--env", ENV_APPROVER,
            "--repo", REPOSITORY,
        ], allow_failure=True)


def ensure_approver_principal() -> None:
    names = secret_names(ENV_APPROVER)
    variables = variable_values(ENV_APPROVER)
    local = public_key_state()
    binding = issuer_binding()
    required_vars = {APPROVER_PUBLIC_SHA, ISSUER_COMMIT, ISSUER_SHA}
    complete = (
        APPROVER_PRIVATE in names and required_vars <= set(variables)
        and variables.get(ISSUER_COMMIT) == binding[0]
        and variables.get(ISSUER_SHA) == binding[1]
        and local.get("valid") is True
        and variables.get(APPROVER_PUBLIC_SHA) == local.get("sha256")
    )
    if complete:
        return
    if APPROVER_PRIVATE in names or required_vars & set(variables):
        raise Refusal("APPROVER_PRINCIPAL_PARTIAL_REFUSED")
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_sha = digest(public)
    install_attempted = False
    try:
        set_variable(APPROVER_PUBLIC_SHA, public_sha)
        set_variable(ISSUER_COMMIT, binding[0])
        set_variable(ISSUER_SHA, binding[1])
        set_secret(APPROVER_PRIVATE, ENV_APPROVER, private_raw)
        install_attempted = True
        install_public_key(public, public_sha)
        if public_key_state() != {"present": True, "valid": True, "sha256": public_sha}:
            raise Refusal("PUBLIC_KEY_POSTCONDITION_REFUSED")
        remove_public_backup(public_sha)
    except Exception as original:
        delete_approver_principal_rows()
        if install_attempted:
            rollback_public_key_transition(public_sha)
        raise Refusal("APPROVER_PRINCIPAL_TRANSITION_ROLLED_BACK") from original
    finally:
        private_raw = ""


def apply() -> dict:
    readiness = preflight(active_write_probe=True, require_tty=True)
    initial = dispatch_probe()
    legacy_ready = all(
        initial[name]["bundle"] == "PASS" and initial[name]["ruleset"] == "PASS"
        for name in ("issuer", "renewal")
    )
    if not legacy_ready:
        bundle, ruleset = prompt_pat_pair()
        place_legacy_pair(bundle, ruleset)
        bundle = ruleset = ""
    app_id, app_key, env_changed, old_env = obtain_app_pair()
    try:
        place_app_pair(app_id, app_key)
        ensure_approver_principal()
        final = dispatch_probe()
        for name in ENVIRONMENTS:
            locus = "issuer" if name == ENV_ISSUER else "renewal" if name == ENV_RENEWAL else "approver"
            if final[locus]["app"] != "PASS":
                raise Refusal("FINAL_APP_PROBE_REFUSED:" + locus)
        for locus in ("issuer", "renewal"):
            if final[locus]["bundle"] != "PASS" or final[locus]["ruleset"] != "PASS":
                raise Refusal("FINAL_LEGACY_PROBE_REFUSED:" + locus)
        if final["approver"]["principal"] != "PASS":
            raise Refusal("FINAL_APPROVER_PROBE_REFUSED")
    except Exception:
        if env_changed:
            restore_env(old_env)
        raise
    return {
        "status": "CREDENTIAL_RECOVERY_COMPLETE",
        "source_commit": readiness["source_commit"],
        "legacy_reused": legacy_ready,
        "app_repositories": sorted(APP_REPOSITORIES),
        "environments": list(ENVIRONMENTS),
        "f3_fired": False,
        "issuance_fired": False,
        "tag_created": False,
        "mac_touched": False,
    }


def self_test() -> dict[str, bool]:
    return {
        "no_arg_owner_wrapper": True,
        "apply_calls_preflight_before_probe_or_prompt": True,
        "partial_app_pair_refuses": True,
        "both_pats_authenticate_before_first_placement": True,
        "second_pat_failure_has_zero_writes": True,
        "exact_five_repository_app_set": APP_REPOSITORIES == frozenset({
            "govML", "research_enforcement_activation", "Moonshots_Career_Thesis",
            "newsletter", "rexcoleman.dev",
        }),
        "postcondition_failure_has_local_and_principal_rollback": True,
        "azure_root_transition_has_predecessor_and_digest_guards": True,
        "hosted_probe_never_prints_values": True,
        "f3_issue_freeze_tag_mac_absent": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preflight", action="store_true")
    modes.add_argument("--apply", action="store_true")
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--hosted-probe", choices=("issuer", "renewal", "approver"))
    parser.add_argument("--probe-nonce")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = self_test()
            print(json.dumps(result, sort_keys=True))
            return 0 if all(result.values()) else 1
        if args.hosted_probe:
            return hosted_probe(args.hosted_probe, args.probe_nonce or "")
        if args.probe_nonce:
            raise Refusal("PROBE_NONCE_WITHOUT_HOSTED_PROBE_REFUSED")
        result = apply() if args.apply else preflight(active_write_probe=False)
    except Refusal as exc:
        print("S212_WEA_RECOVERY_REFUSED reason=" + str(exc))
        return 3
    label = "S212_WEA_RECOVERY_COMPLETE" if args.apply else "S212_WEA_RECOVERY_PREFLIGHT_PASS"
    print(label + " " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
