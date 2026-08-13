#!/usr/bin/env python3
"""Close one registered sealed bundle-secret transition.

This local transition is deliberately bound to the cycle10 enforcement target.
It dispatches and approves the protected issuer's sealed transfer, authenticates
the resulting packet, installs only its ciphertext with the local GitHub
session, and dispatches the bound capability-change issuance.  The plaintext
bundle token never leaves the protected issuer environment.

The target secret must be absent.  That makes the mutation reversible: every
failure after creation deletes the newly-created secret and verifies absence.
An existing secret is never overwritten because its old value is write-only
and therefore cannot be rolled back.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REFUSAL_EXIT = 3
HOST = "gios-dev"
ISSUER_REPOSITORY = "rexcoleman/rexcoleman.dev"
TARGET_REPOSITORY = "rexcoleman/cycle_10_autonomous_cycle_apparatus_build"
WORKFLOW = "issue-write-enforcement-attestation.yml"
ENVIRONMENT = "rea-write-enforcement-issuer"
SECRET_NAME = "REA_BUNDLE_READ_TOKEN"
TRANSFER_TOOL = Path(__file__).with_name("provision_downstream_bundle_secret.py")

SPEC = importlib.util.spec_from_file_location("sealed_bundle_core", TRANSFER_TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("SEALED_CORE_IMPORT_REFUSED")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)


class Refusal(RuntimeError):
    pass


def lower_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(char in "0123456789abcdef" for char in value))


def command(argv, stdin_value=None):
    completed = subprocess.run(
        argv, input=stdin_value, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False,
    )
    if completed.returncode:
        raise Refusal("COMMAND_REFUSED exit=%s subject=%s" % (
            completed.returncode, " ".join(argv[:4]),
        ))
    return completed.stdout


def api(path, method="GET", body=None, allow_not_found=False):
    argv = ["gh", "api", path]
    if method != "GET":
        argv.extend(["--method", method])
    if body is not None:
        argv.extend(["--input", "-"])
    completed = subprocess.run(
        argv,
        input=json.dumps(body, sort_keys=True, separators=(",", ":"))
        if body is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if allow_not_found and completed.returncode and "HTTP 404" in completed.stderr:
        return None
    if completed.returncode:
        raise Refusal("API_REFUSED exit=%s path=%s" % (completed.returncode, path))
    if not completed.stdout.strip():
        return None
    try:
        return json.loads(completed.stdout)
    except ValueError:
        raise Refusal("API_MALFORMED path=%s" % path) from None


def runtime_ready():
    if socket.gethostname().split(".", 1)[0] != HOST or os.geteuid() == 0:
        raise Refusal("COACH_RUNTIME_REFUSED")
    command(["gh", "auth", "status", "--hostname", "github.com"])


def public_key():
    value = api("repos/%s/actions/secrets/public-key" % TARGET_REPOSITORY)
    try:
        raw = base64.b64decode(value["key"].encode("ascii"), validate=True)
        key_id = value["key_id"]
    except (AttributeError, KeyError, TypeError, ValueError):
        raise Refusal("DOWNSTREAM_PUBLIC_KEY_REFUSED") from None
    if len(raw) != 32 or not isinstance(key_id, str) or not key_id.isdigit():
        raise Refusal("DOWNSTREAM_PUBLIC_KEY_REFUSED")
    return {
        "key_id": key_id,
        "key_b64": value["key"],
        "key_sha256": hashlib.sha256(raw).hexdigest(),
    }


def secret_metadata():
    return api(
        "repos/%s/actions/secrets/%s" % (TARGET_REPOSITORY, SECRET_NAME),
        allow_not_found=True,
    )


def assert_secret_absent():
    if secret_metadata() is not None:
        raise Refusal("DOWNSTREAM_SECRET_PREEXISTING_REFUSED")


def run_state(run_id):
    value = json.loads(command([
        "gh", "run", "view", str(run_id), "--repo", ISSUER_REPOSITORY,
        "--json", "databaseId,event,headBranch,headSha,status,conclusion,url",
    ]))
    if value.get("databaseId") != run_id or value.get("event") != "workflow_dispatch":
        raise Refusal("RUN_IDENTITY_REFUSED run=%s" % run_id)
    return value


def pending_environment(run_id):
    rows = api("repos/%s/actions/runs/%s/pending_deployments" % (
        ISSUER_REPOSITORY, run_id,
    ))
    matches = [
        row for row in rows if isinstance(row, dict)
        and row.get("environment", {}).get("name") == ENVIRONMENT
        and isinstance(row.get("environment", {}).get("id"), int)
        and row.get("current_user_can_approve") is True
    ] if isinstance(rows, list) else []
    return matches[0]["environment"]["id"] if len(matches) == 1 else None


def approve(run_id, purpose):
    environment_id = pending_environment(run_id)
    if environment_id is None:
        raise Refusal("ISSUER_APPROVAL_BOUNDARY_REFUSED run=%s" % run_id)
    result = api(
        "repos/%s/actions/runs/%s/pending_deployments" % (
            ISSUER_REPOSITORY, run_id,
        ),
        method="POST",
        body={
            "environment_ids": [environment_id],
            "state": "approved",
            "comment": "s153 registered cycle10 sealed transition: %s" % purpose,
        },
    )
    if not isinstance(result, list):
        raise Refusal("ISSUER_APPROVAL_REFUSED run=%s" % run_id)


def wait_pending(run_id, expected_ref, expected_sha):
    for _attempt in range(120):
        state = run_state(run_id)
        if state.get("headBranch") != expected_ref or state.get("headSha") != expected_sha:
            raise Refusal("ISSUER_RUN_SUBJECT_REFUSED run=%s" % run_id)
        if pending_environment(run_id) is not None:
            return
        if state.get("status") == "completed":
            raise Refusal("ISSUER_FAILED_BEFORE_APPROVAL run=%s" % run_id)
        time.sleep(5)
    raise Refusal("ISSUER_APPROVAL_TIMEOUT run=%s" % run_id)


def wait_success(run_id, expected_ref, expected_sha):
    for _attempt in range(240):
        state = run_state(run_id)
        if state.get("headBranch") != expected_ref or state.get("headSha") != expected_sha:
            raise Refusal("ISSUER_RUN_SUBJECT_REFUSED run=%s" % run_id)
        if state.get("status") == "completed":
            if state.get("conclusion") != "success":
                raise Refusal("ISSUER_RUN_FAILED run=%s" % run_id)
            return state
        time.sleep(5)
    raise Refusal("ISSUER_RUN_TIMEOUT run=%s" % run_id)


def dispatch(args, mode, fields):
    rows = json.loads(command([
        "gh", "run", "list", "--repo", ISSUER_REPOSITORY,
        "--workflow", WORKFLOW, "--limit", "1", "--json", "databaseId",
    ]))
    baseline = rows[0]["databaseId"] if rows else 0
    argv = [
        "gh", "workflow", "run", WORKFLOW, "--repo", ISSUER_REPOSITORY,
        "--ref", args.issuer_ref, "-f", "mode=%s" % mode,
        "-f", "predecessor_run_id=%s" % args.predecessor_run_id,
        "-f", "predecessor_wea_sha256=%s" % args.predecessor_wea_sha256,
    ]
    for key, value in sorted(fields.items()):
        argv.extend(["-f", "%s=%s" % (key, value)])
    command(argv)
    for _attempt in range(60):
        candidates = json.loads(command([
            "gh", "run", "list", "--repo", ISSUER_REPOSITORY,
            "--workflow", WORKFLOW, "--event", "workflow_dispatch",
            "--limit", "5", "--json",
            "databaseId,event,headBranch,headSha,status,conclusion,url",
        ]))
        matches = [row for row in candidates
                   if row.get("databaseId", 0) > baseline
                   and row.get("headBranch") == args.issuer_ref
                   and row.get("headSha") == args.issuer_sha]
        if len(matches) == 1:
            return matches[0]["databaseId"]
        if len(matches) > 1:
            raise Refusal("ISSUER_DISCOVERY_AMBIGUOUS")
        time.sleep(5)
    raise Refusal("ISSUER_DISCOVERY_TIMEOUT")


def sealed_packet(args, run_id, key, temporary):
    artifacts = api("repos/%s/actions/runs/%s/artifacts" % (
        ISSUER_REPOSITORY, run_id,
    ))
    expected = "rea-downstream-sealed-secret-%s" % run_id
    matches = [row for row in artifacts.get("artifacts", [])
               if isinstance(row, dict) and row.get("name") == expected
               and row.get("expired") is False
               and row.get("workflow_run", {}).get("id") == run_id
               and row.get("workflow_run", {}).get("head_branch") == args.issuer_ref
               and row.get("workflow_run", {}).get("head_sha") == args.issuer_sha] \
        if isinstance(artifacts, dict) else []
    if len(matches) != 1:
        raise Refusal("SEALED_ARTIFACT_REFUSED run=%s" % run_id)
    command([
        "gh", "run", "download", str(run_id), "--repo", ISSUER_REPOSITORY,
        "--name", expected, "--dir", str(temporary),
    ])
    packet_path = temporary / "sealed-transfer.json"
    value = CORE.load_packet(packet_path)
    verify_args = argparse.Namespace(
        packet=packet_path,
        manifest=args.manifest,
        target_repository=TARGET_REPOSITORY,
        key_id=key["key_id"],
        public_key_sha256=key["key_sha256"],
        ciphertext_sha256=value.get("ciphertext_sha256"),
        run_id=run_id,
        workflow_ref="refs/tags/%s" % args.issuer_ref,
        workflow_sha=args.issuer_sha,
    )
    CORE.verify(verify_args)
    return value


def rollback_secret(reason):
    path = "repos/%s/actions/secrets/%s" % (TARGET_REPOSITORY, SECRET_NAME)
    try:
        api(path, method="DELETE")
        if secret_metadata() is not None:
            raise Refusal("ROLLBACK_POSTCHECK_REFUSED")
    except Exception as exc:
        raise Refusal("ROLLBACK_FAILED original=%s rollback=%s" % (
            reason, type(exc).__name__,
        )) from None
    raise Refusal("ROLLED_BACK_AFTER_FAILURE original=%s" % reason)


def install_ciphertext(packet, key):
    if public_key() != key:
        raise Refusal("DOWNSTREAM_PUBLIC_KEY_DRIFT")
    assert_secret_absent()
    before = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    path = "repos/%s/actions/secrets/%s" % (TARGET_REPOSITORY, SECRET_NAME)
    try:
        response = api(path, method="PUT", body={
            "encrypted_value": packet["ciphertext_b64"],
            "key_id": key["key_id"],
        })
        if response not in (None, {}):
            raise Refusal("DOWNSTREAM_SECRET_WRITE_RESPONSE_REFUSED")
        observed = secret_metadata()
        updated = dt.datetime.fromisoformat(
            observed["updated_at"].replace("Z", "+00:00")
        ).astimezone(dt.timezone.utc)
        if observed.get("name") != SECRET_NAME or updated < before:
            raise Refusal("DOWNSTREAM_SECRET_POSTCHECK_REFUSED")
        if public_key() != key:
            raise Refusal("DOWNSTREAM_PUBLIC_KEY_DRIFT")
    except Exception as exc:
        # A failed PUT can still have reached GitHub.  Probe before deciding
        # whether rollback is required; never leave a possibly partial write.
        if secret_metadata() is not None:
            rollback_secret(type(exc).__name__)
        raise


def verify_issued_artifact(run_id, args):
    value = api("repos/%s/actions/runs/%s/artifacts" % (
        ISSUER_REPOSITORY, run_id,
    ))
    expected = "rea-write-enforcement-attestation-%s" % run_id
    matches = [row for row in value.get("artifacts", [])
               if isinstance(row, dict) and row.get("name") == expected
               and row.get("expired") is False
               and row.get("workflow_run", {}).get("id") == run_id
               and row.get("workflow_run", {}).get("head_branch") == args.issuer_ref
               and row.get("workflow_run", {}).get("head_sha") == args.issuer_sha] \
        if isinstance(value, dict) else []
    if len(matches) != 1:
        raise Refusal("ISSUANCE_ARTIFACT_REFUSED run=%s" % run_id)


def validate_args(args):
    if (not re.fullmatch(r"rea-wea-generation-5-[0-9a-f]{12}", args.issuer_ref)
            or not lower_hex(args.issuer_sha, 40)
            or not re.fullmatch(r"[1-9][0-9]*", args.predecessor_run_id)
            or not lower_hex(args.predecessor_wea_sha256, 64)):
        raise Refusal("TRANSITION_SUBJECT_REFUSED")
    _raw, _digest, _commits = CORE.load_manifest(args.manifest)


def run_transition(args):
    runtime_ready()
    validate_args(args)
    key = public_key()
    assert_secret_absent()
    if args.dry_run:
        print("REGISTERED_DOWNSTREAM_SECRET_PREFLIGHT_PASS target=%s "
              "secret_absent=true key_id=%s mutation=false" % (
                  TARGET_REPOSITORY, key["key_id"],
              ))
        return 0
    secret_created = False
    try:
        seal_run = dispatch(args, "seal_downstream", {
            "downstream_key_id": key["key_id"],
            "downstream_repository": TARGET_REPOSITORY,
            "downstream_public_key_b64": key["key_b64"],
            "downstream_public_key_sha256": key["key_sha256"],
        })
        wait_pending(seal_run, args.issuer_ref, args.issuer_sha)
        approve(seal_run, "sealed cycle10 bundle transfer")
        wait_success(seal_run, args.issuer_ref, args.issuer_sha)
        with tempfile.TemporaryDirectory(prefix="rea-s153-cycle10-sealed-") as name:
            packet = sealed_packet(args, seal_run, key, Path(name))
        install_ciphertext(packet, key)
        secret_created = True
        issue_run = dispatch(args, "capability_change", {
            "downstream_key_id": key["key_id"],
            "downstream_repository": TARGET_REPOSITORY,
            "downstream_public_key_sha256": key["key_sha256"],
            "sealed_ciphertext_sha256": packet["ciphertext_sha256"],
            "sealed_transfer_run_id": str(seal_run),
        })
        wait_pending(issue_run, args.issuer_ref, args.issuer_sha)
        approve(issue_run, "cycle10 capability-change issuance")
        wait_success(issue_run, args.issuer_ref, args.issuer_sha)
        verify_issued_artifact(issue_run, args)
        if secret_metadata() is None or public_key() != key:
            raise Refusal("FINAL_POSTSTATE_REFUSED")
    except Exception as exc:
        if secret_created and secret_metadata() is not None:
            rollback_secret(type(exc).__name__)
        raise
    print("REGISTERED_DOWNSTREAM_SECRET_PASS target=%s seal_run=%s "
          "issue_run=%s rollback_available=absent-only plaintext_exposed=false" % (
              TARGET_REPOSITORY, seal_run, issue_run,
          ))
    return 0


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--manifest", type=Path, required=True)
    value.add_argument("--issuer-ref", required=True)
    value.add_argument("--issuer-sha", required=True)
    value.add_argument("--predecessor-run-id", required=True)
    value.add_argument("--predecessor-wea-sha256", required=True)
    value.add_argument("--dry-run", action="store_true")
    return value


def main(argv=None):
    try:
        return run_transition(parser().parse_args(argv))
    except (Refusal, CORE.Refusal) as exc:
        print("REFUSE(REGISTERED_DOWNSTREAM_SECRET): %s" % exc, file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT
    except Exception as exc:
        print("REFUSE(REGISTERED_DOWNSTREAM_SECRET): UNEXPECTED_%s" % (
            type(exc).__name__,
        ), file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
