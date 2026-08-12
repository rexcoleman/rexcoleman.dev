#!/usr/bin/env python3
"""Checked approval-only completion of the s152 public-packet successor."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


HOST = "gios-dev"
MARKER = "rea-s152-public-successor-approval-v1"
REPOSITORY = "rexcoleman/rexcoleman.dev"
ENVIRONMENT = "rea-write-enforcement-issuer"
WORKFLOW = "issue-write-enforcement-attestation.yml"
REVIEW_RUN_ID = 31558727743
REVIEW_WORKFLOW_SHA = "4865392bf4837cb8b5eefb9aaf84e2a429479116"
MANIFEST_PR = 72
MANIFEST_HEAD = "bbb565d6349c36c3cb6db3018e04003f864711a8"
MANIFEST_PATH = ".github/write-enforcement/frozen_bundle_manifest.generation-5.json"
MANIFEST_FILE_SHA256 = "821a0fb63b568383727858bd617922df14ff8f01e8e5b20c11befa844b80493a"
MANIFEST_DIGEST = "9881c3dbab40d1c7f01e4ed609a5765d836883875a20cda970339364468f6d3c"
ISSUER_TAG = "rea-wea-generation-5-bbb565d6349c"
PREDECESSOR_RUN_ID = 31537532308
INSTALLED = Path("/home/azureuser/.local/state/rea_enforcement/remote_wea")


class Refusal(RuntimeError):
    pass


def command(argv, stdin_value=None):
    completed = subprocess.run(
        argv, input=stdin_value, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False,
    )
    if completed.returncode:
        raise Refusal("COMMAND_REFUSED exit=%s subject=%s" % (
            completed.returncode, " ".join(argv[:4])
        ))
    return completed.stdout


def api(path, method="GET", body=None, allow_not_found=False):
    argv = ["gh", "api", path]
    if method != "GET":
        argv.extend(["--method", method, "--input", "-"])
    completed = subprocess.run(
        argv,
        input=json.dumps(body, separators=(",", ":")) if body is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if allow_not_found and completed.returncode and "HTTP 404" in completed.stderr:
        return None
    if completed.returncode:
        raise Refusal("API_REFUSED exit=%s path=%s" % (completed.returncode, path))
    try:
        return json.loads(completed.stdout)
    except ValueError:
        raise Refusal("API_MALFORMED path=%s" % path) from None


def runtime_ready():
    if os.environ.get("REA_S152_CHECKED_WRAPPER") != MARKER:
        raise Refusal("CHECKED_WRAPPER_REQUIRED")
    if socket.gethostname().split(".", 1)[0] != HOST:
        raise Refusal("HOST_REFUSED")
    if os.geteuid() == 0 or not (
        sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty()
    ):
        raise Refusal("OWNER_RUNTIME_REFUSED")
    command(["gh", "auth", "status", "--hostname", "github.com"])


def run_state(run_id):
    value = json.loads(command([
        "gh", "run", "view", str(run_id), "--repo", REPOSITORY,
        "--json", "databaseId,event,headBranch,headSha,status,conclusion,url",
    ]))
    if value.get("databaseId") != run_id or value.get("event") != "workflow_dispatch":
        raise Refusal("RUN_IDENTITY_REFUSED run=%s" % run_id)
    return value


def pending_environment(run_id):
    rows = api("repos/%s/actions/runs/%s/pending_deployments" % (
        REPOSITORY, run_id
    ))
    matches = [
        row for row in rows if isinstance(row, dict)
        and row.get("environment", {}).get("name") == ENVIRONMENT
        and isinstance(row.get("environment", {}).get("id"), int)
        and row.get("current_user_can_approve") is True
    ] if isinstance(rows, list) else []
    if len(matches) != 1:
        return None
    return matches[0]["environment"]["id"]


def approve(run_id, purpose):
    environment_id = pending_environment(run_id)
    if environment_id is None:
        raise Refusal("OWNER_GATE_NOT_PENDING run=%s" % run_id)
    value = api(
        "repos/%s/actions/runs/%s/pending_deployments" % (REPOSITORY, run_id),
        method="POST",
        body={
            "environment_ids": [environment_id],
            "state": "approved",
            "comment": "s152 checked approval-only arc: %s" % purpose,
        },
    )
    if not isinstance(value, list):
        raise Refusal("OWNER_GATE_APPROVAL_REFUSED run=%s" % run_id)


def wait_success(run_id, expected_head, attempts, purpose):
    for _attempt in range(attempts):
        value = run_state(run_id)
        if value.get("status") == "completed":
            if value.get("conclusion") != "success" or value.get("headSha") != expected_head:
                raise Refusal("%s_FAILED run=%s" % (purpose, run_id))
            return value
        time.sleep(5)
    raise Refusal("%s_TIMEOUT run=%s" % (purpose, run_id))


def verify_manifest_pr(require_open=True):
    value = api("repos/%s/pulls/%s" % (REPOSITORY, MANIFEST_PR))
    expected_state = "open" if require_open else "closed"
    if (
        value.get("state") != expected_state
        or value.get("draft") is not False
        or value.get("head", {}).get("sha") != MANIFEST_HEAD
        or value.get("base", {}).get("ref") != "main"
        or (not require_open and value.get("merged") is not True)
    ):
        raise Refusal("MANIFEST_PR_IDENTITY_REFUSED")
    files = api("repos/%s/pulls/%s/files?per_page=100" % (REPOSITORY, MANIFEST_PR))
    if (
        not isinstance(files, list) or len(files) != 1
        or files[0].get("filename") != MANIFEST_PATH
        or files[0].get("status") != "modified"
    ):
        raise Refusal("MANIFEST_PR_FILE_SET_REFUSED")
    content = api("repos/%s/contents/%s?ref=%s" % (
        REPOSITORY, MANIFEST_PATH, MANIFEST_HEAD
    ))
    try:
        raw = base64.b64decode(
            content["content"].encode("ascii").replace(b"\n", b""), validate=True
        )
        manifest = json.loads(raw.decode("utf-8"))
    except (AttributeError, KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise Refusal("MANIFEST_BYTES_REFUSED") from None
    ids = [row.get("member_id") for row in manifest.get("members", [])
           if isinstance(row, dict)]
    if (
        hashlib.sha256(raw).hexdigest() != MANIFEST_FILE_SHA256
        or manifest.get("authority_generation") != 5
        or manifest.get("manifest_digest") != MANIFEST_DIGEST
        or len(ids) != 247 or len(set(ids)) != 247
        or ids.count("ci-enforcement-materializer") != 1
        or ids.count("protected-downstream-bundle-secret-transition") != 1
        or ids.count("public-attestation-publisher") != 1
    ):
        raise Refusal("MANIFEST_CONTRACT_REFUSED")


def merge_manifest_pr():
    command([
        "gh", "pr", "merge", str(MANIFEST_PR), "--repo", REPOSITORY,
        "--merge", "--delete-branch=false",
    ])
    verify_manifest_pr(require_open=False)


def peel_tag(value):
    obj = value.get("object", {}) if isinstance(value, dict) else {}
    if obj.get("type") != "tag" or not isinstance(obj.get("sha"), str):
        raise Refusal("GENERATION_TAG_OBJECT_REFUSED")
    tag = api("repos/%s/git/tags/%s" % (REPOSITORY, obj["sha"]))
    if tag.get("object", {}).get("type") != "commit":
        raise Refusal("GENERATION_TAG_PEEL_REFUSED")
    return tag["object"].get("sha")


def create_tag():
    path = "repos/%s/git/ref/tags/%s" % (REPOSITORY, ISSUER_TAG)
    existing = api(path, allow_not_found=True)
    if existing is not None:
        if peel_tag(existing) != MANIFEST_HEAD:
            raise Refusal("GENERATION_TAG_RETARGETED")
        return
    tag = api(
        "repos/%s/git/tags" % REPOSITORY, method="POST",
        body={"tag": ISSUER_TAG,
              "message": "REA generation 5 public packet authority",
              "object": MANIFEST_HEAD, "type": "commit"},
    )
    tag_sha = tag.get("sha") if isinstance(tag, dict) else None
    if not isinstance(tag_sha, str):
        raise Refusal("GENERATION_TAG_CREATE_REFUSED")
    api("repos/%s/git/refs" % REPOSITORY, method="POST",
        body={"ref": "refs/tags/%s" % ISSUER_TAG, "sha": tag_sha})
    if peel_tag(api(path)) != MANIFEST_HEAD:
        raise Refusal("GENERATION_TAG_POSTCHECK_REFUSED")


def predecessor_digest():
    wea = INSTALLED / "write_enforcement_attestation.json"
    receipt = INSTALLED / "issuance_receipt.json"
    if not wea.is_file() or wea.is_symlink() or not receipt.is_file() or receipt.is_symlink():
        raise Refusal("PREDECESSOR_FILES_REFUSED")
    raw = wea.read_bytes()
    try:
        value = json.loads(receipt.read_bytes())
    except (OSError, ValueError):
        raise Refusal("PREDECESSOR_RECEIPT_REFUSED") from None
    digest = hashlib.sha256(raw).hexdigest()
    if value.get("workflow_run_id") != PREDECESSOR_RUN_ID or value.get("wea_sha256") != digest:
        raise Refusal("PREDECESSOR_IDENTITY_REFUSED")
    return digest


def dispatch_issuer(digest):
    rows = json.loads(command([
        "gh", "run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
        "--limit", "1", "--json", "databaseId",
    ]))
    baseline = rows[0]["databaseId"] if rows else 0
    command([
        "gh", "workflow", "run", WORKFLOW, "--repo", REPOSITORY,
        "--ref", ISSUER_TAG, "-f", "mode=capability_change",
        "-f", "predecessor_run_id=%s" % PREDECESSOR_RUN_ID,
        "-f", "predecessor_wea_sha256=%s" % digest,
    ])
    for _attempt in range(60):
        candidates = json.loads(command([
            "gh", "run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
            "--event", "workflow_dispatch", "--limit", "5", "--json",
            "databaseId,event,headBranch,headSha,status,conclusion,url",
        ]))
        matches = [row for row in candidates
                   if row.get("databaseId", 0) > baseline
                   and row.get("headBranch") == ISSUER_TAG
                   and row.get("headSha") == MANIFEST_HEAD]
        if len(matches) == 1:
            return matches[0]["databaseId"]
        if len(matches) > 1:
            raise Refusal("ISSUER_DISCOVERY_AMBIGUOUS")
        time.sleep(5)
    raise Refusal("ISSUER_DISCOVERY_TIMEOUT")


def wait_owner_gate(run_id):
    for _attempt in range(120):
        if pending_environment(run_id) is not None:
            return
        value = run_state(run_id)
        if value.get("status") == "completed":
            raise Refusal("ISSUER_FAILED_BEFORE_OWNER_GATE run=%s" % run_id)
        time.sleep(5)
    raise Refusal("ISSUER_OWNER_GATE_TIMEOUT run=%s" % run_id)


def verify_artifact(run_id):
    value = api("repos/%s/actions/runs/%s/artifacts" % (REPOSITORY, run_id))
    expected = "rea-write-enforcement-attestation-%s" % run_id
    matches = [row for row in value.get("artifacts", [])
               if isinstance(row, dict) and row.get("name") == expected
               and row.get("expired") is False]
    if len(matches) != 1:
        raise Refusal("ISSUER_ARTIFACT_REFUSED run=%s" % run_id)


def preflight():
    runtime_ready()
    verify_manifest_pr()
    if pending_environment(REVIEW_RUN_ID) is None:
        raise Refusal("REVIEW_OWNER_GATE_NOT_PENDING")
    print("PREFLIGHT_PASS host=gios-dev review_run=%s manifest_pr=%s "
          "manifest_digest=%s owner_credential_handling=false mutation=false" % (
              REVIEW_RUN_ID, MANIFEST_PR, MANIFEST_DIGEST
          ))
    print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
    return 0


def run():
    runtime_ready()
    verify_manifest_pr()
    approve(REVIEW_RUN_ID, "exact public-packet successor review")
    review = wait_success(REVIEW_RUN_ID, REVIEW_WORKFLOW_SHA, 120, "REVIEW")
    if review.get("headBranch") != "main":
        raise Refusal("REVIEW_WORKFLOW_REF_REFUSED")
    verify_manifest_pr()
    merge_manifest_pr()
    create_tag()
    issuer_run = dispatch_issuer(predecessor_digest())
    wait_owner_gate(issuer_run)
    approve(issuer_run, "public-packet successor issuance")
    issued = wait_success(issuer_run, MANIFEST_HEAD, 240, "ISSUER")
    if issued.get("headBranch") != ISSUER_TAG:
        raise Refusal("ISSUER_TAG_REFUSED")
    verify_artifact(issuer_run)
    print("S152_SUCCESSOR_APPROVAL_PASS review_run=%s manifest_pr=%s tag=%s "
          "issuer_run=%s artifact=verified owner_credential_handling=false" % (
              REVIEW_RUN_ID, MANIFEST_PR, ISSUER_TAG, issuer_run
          ))
    print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)
    try:
        return preflight() if args.preflight else run()
    except Refusal as exc:
        print("REFUSE(S152_SUCCESSOR_APPROVAL): %s" % exc, file=sys.stderr)
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false", file=sys.stderr)
        return 2
    except Exception as exc:
        print("REFUSE(S152_SUCCESSOR_APPROVAL): UNEXPECTED_%s" % type(exc).__name__,
              file=sys.stderr)
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
