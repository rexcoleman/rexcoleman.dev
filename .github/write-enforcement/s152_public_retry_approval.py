#!/usr/bin/env python3
"""One checked owner arc for the sealed-free s152 successor publication retry."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path


HOST = "gios-dev"
MARKER = "rea-s152-public-retry-approval-v5"
REPOSITORY = "rexcoleman/rexcoleman.dev"
TARGET_REPOSITORY = "rexcoleman/research_enforcement_activation"
ENVIRONMENT = "rea-write-enforcement-issuer"
WORKFLOW = "issue-write-enforcement-attestation.yml"
REVIEW_RUN_ID = 31604361900
REVIEW_JOB_ID = 94139404692
REVIEW_WORKFLOW_SHA = "87e6f1f95b6d67fd4491d652bfbab97d611d6536"
MANIFEST_PR = 88
MANIFEST_HEAD = "fb97ae2f01a6a13b20209747923be41a057502c6"
MANIFEST_PATH = ".github/write-enforcement/frozen_bundle_manifest.generation-5.json"
MANIFEST_FILE_SHA256 = "a45405e8a8ce555624a7bbbd77aff036232ea19d9167568bedd693a2c10c4d43"
MANIFEST_DIGEST = "3240b02963c5fef93c7c268a6ffce7323fb7468b0f6d13a42e177b8bee8e4893"
ISSUER_TAG = "rea-wea-generation-5-fb97ae2f01a6"
SECRET_NAME = "REA_BUNDLE_READ_TOKEN"
INSTALLED = Path("/home/azureuser/.local/state/rea_enforcement/remote_wea")
SIGNED_ROOTS = Path("/home/azureuser/.local/state/rea_enforcement/signed_member_roots")
GENERATION4_TAG_PREFIX = "refs/tags/rea-wea-generation-4-"
GENERATION4_MEMBER_COUNT = 244
MANIFEST_SCHEMA = "rea.write.enforcement-bundle-manifest.v1"
RECEIPT_SCHEMA = "rea.write.remote-issuance-receipt.v1"
ISSUER_URL = (
    "https://github.com/rexcoleman/rexcoleman.dev/actions/workflows/"
    "issue-write-enforcement-attestation.yml"
)
PUBLIC_ROOT = "rea-write-enforcement-packets"
PUBLIC_POINTER = PUBLIC_ROOT + "/latest.json"
PUBLIC_SCHEMA = "rea.write.public-attestation-pointer.v1"
PUBLIC_FILES = frozenset({
    "SHA256SUMS", "claim_policy.json", "claim_registry.json",
    "enforcement_bundle_manifest.json", "hybrid_capability_authority.json",
    "hybrid_capability_provider", "issuance_receipt.json",
    "predecessor_write_enforcement_attestation.json", "runtime_mount.py",
    "trusted_wea_public.pem", "write_enforcement_attestation.json",
})


class Refusal(RuntimeError):
    pass


def command(argv, env=None):
    completed = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, env=env,
    )
    if completed.returncode:
        raise Refusal("COMMAND_REFUSED exit=%s subject=%s" % (
            completed.returncode, " ".join(argv[:4]),
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
    if not completed.stdout.strip():
        return None
    try:
        return json.loads(completed.stdout)
    except ValueError:
        raise Refusal("API_MALFORMED path=%s" % path) from None


def runtime_ready():
    if os.environ.get("REA_S152_CHECKED_WRAPPER") != MARKER:
        raise Refusal("CHECKED_WRAPPER_REQUIRED")
    if socket.gethostname().split(".", 1)[0] != HOST:
        raise Refusal("HOST_REFUSED")
    if os.geteuid() == 0 or not all(
        stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)
    ):
        raise Refusal("OWNER_RUNTIME_REFUSED")
    command(["gh", "auth", "status", "--hostname", "github.com"])


def lower_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(char in "0123456789abcdef" for char in value))


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
        REPOSITORY, run_id,
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
        method="POST", body={
            "environment_ids": [environment_id], "state": "approved",
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


def content_bytes(path, ref):
    value = api("repos/%s/contents/%s?ref=%s" % (REPOSITORY, path, ref))
    try:
        if value.get("type") != "file" or value.get("path") != path:
            raise ValueError("identity")
        compact = b"".join(value["content"].encode("ascii").split())
        return base64.b64decode(compact, validate=True)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise Refusal("CONTENT_BYTES_REFUSED path=%s" % path) from None


def verify_manifest_pr(require_open=True):
    value = api("repos/%s/pulls/%s" % (REPOSITORY, MANIFEST_PR))
    expected_state = "open" if require_open else "closed"
    if (value.get("state") != expected_state or value.get("draft") is not False
            or value.get("head", {}).get("sha") != MANIFEST_HEAD
            or value.get("base", {}).get("ref") != "main"
            or (not require_open and value.get("merged") is not True)):
        raise Refusal("MANIFEST_PR_IDENTITY_REFUSED")
    files = api("repos/%s/pulls/%s/files?per_page=100" % (REPOSITORY, MANIFEST_PR))
    if (not isinstance(files, list) or len(files) != 1
            or files[0].get("filename") != MANIFEST_PATH
            or files[0].get("status") != "modified"):
        raise Refusal("MANIFEST_PR_FILE_SET_REFUSED")
    raw = content_bytes(MANIFEST_PATH, MANIFEST_HEAD)
    try:
        manifest = json.loads(raw)
    except ValueError:
        raise Refusal("MANIFEST_BYTES_REFUSED") from None
    ids = [row.get("member_id") for row in manifest.get("members", [])
           if isinstance(row, dict)]
    if (hashlib.sha256(raw).hexdigest() != MANIFEST_FILE_SHA256
            or manifest.get("authority_generation") != 5
            or manifest.get("manifest_digest") != MANIFEST_DIGEST
            or len(ids) != 247 or len(set(ids)) != 247
            or ids.count("public-attestation-publisher") != 1):
        raise Refusal("MANIFEST_CONTRACT_REFUSED")


def merge_manifest_pr():
    command(["gh", "pr", "merge", str(MANIFEST_PR), "--repo", REPOSITORY,
             "--merge", "--delete-branch=false"])
    verify_manifest_pr(require_open=False)


def peel_tag(value):
    obj = value.get("object", {}) if isinstance(value, dict) else {}
    if obj.get("type") != "tag" or not lower_hex(obj.get("sha"), 40):
        raise Refusal("TAG_OBJECT_REFUSED")
    tag = api("repos/%s/git/tags/%s" % (REPOSITORY, obj["sha"]))
    if tag.get("object", {}).get("type") != "commit":
        raise Refusal("TAG_PEEL_REFUSED")
    return tag["object"].get("sha")


def create_tag():
    path = "repos/%s/git/ref/tags/%s" % (REPOSITORY, ISSUER_TAG)
    existing = api(path, allow_not_found=True)
    if existing is not None:
        if peel_tag(existing) != MANIFEST_HEAD:
            raise Refusal("GENERATION_TAG_RETARGETED")
        return
    tag = api("repos/%s/git/tags" % REPOSITORY, method="POST", body={
        "tag": ISSUER_TAG, "message": "REA generation 5 public retry authority",
        "object": MANIFEST_HEAD, "type": "commit",
    })
    tag_sha = tag.get("sha") if isinstance(tag, dict) else None
    if not lower_hex(tag_sha, 40):
        raise Refusal("GENERATION_TAG_CREATE_REFUSED")
    api("repos/%s/git/refs" % REPOSITORY, method="POST",
        body={"ref": "refs/tags/%s" % ISSUER_TAG, "sha": tag_sha})
    if peel_tag(api(path)) != MANIFEST_HEAD:
        raise Refusal("GENERATION_TAG_POSTCHECK_REFUSED")


def regular_bytes(path):
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise Refusal("PREDECESSOR_NONREGULAR path=%s" % path.name)
        raw = path.read_bytes()
        after = path.lstat()
    except OSError:
        raise Refusal("PREDECESSOR_READ_REFUSED path=%s" % path.name) from None
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise Refusal("PREDECESSOR_FILE_DRIFT path=%s" % path.name)
    return raw


def verify_generation4_tag(receipt):
    workflow_ref = receipt.get("workflow_ref")
    if not isinstance(workflow_ref, str) or not workflow_ref.startswith(GENERATION4_TAG_PREFIX):
        raise Refusal("PREDECESSOR_TAG_REFUSED")
    ref = api("repos/%s/git/ref/tags/%s" % (REPOSITORY, workflow_ref[10:]))
    if peel_tag(ref) != receipt.get("workflow_sha"):
        raise Refusal("PREDECESSOR_TAG_REFUSED")


def predecessor_snapshot():
    paths = {
        "wea": INSTALLED / "write_enforcement_attestation.json",
        "receipt": INSTALLED / "issuance_receipt.json",
        "manifest": INSTALLED / "enforcement_bundle_manifest.json",
        "predecessor": INSTALLED / "predecessor_write_enforcement_attestation.json",
    }
    initial = {name: regular_bytes(path) for name, path in paths.items()}
    try:
        wea = json.loads(initial["wea"])
        receipt = json.loads(initial["receipt"])
        manifest = json.loads(initial["manifest"])
        json.loads(initial["predecessor"])
    except ValueError:
        raise Refusal("PREDECESSOR_JSON_REFUSED") from None
    members = manifest.get("members")
    ids = [row.get("member_id") for row in members if isinstance(row, dict)] \
        if isinstance(members, list) else []
    digest = manifest.get("manifest_digest")
    rows = [row for row in members if isinstance(row, dict)
            and row.get("member_id") == "verify-only-resolver"] \
        if isinstance(members, list) else []
    if (manifest.get("schema_version") != MANIFEST_SCHEMA
            or manifest.get("authority_generation") != 4
            or not lower_hex(digest, 64) or len(ids) != GENERATION4_MEMBER_COUNT
            or len(set(ids)) != GENERATION4_MEMBER_COUNT or len(rows) != 1):
        raise Refusal("PREDECESSOR_MANIFEST_REFUSED")
    unsigned = dict(manifest)
    unsigned.pop("manifest_digest", None)
    calculated = hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    if calculated != digest:
        raise Refusal("PREDECESSOR_MANIFEST_DIGEST_REFUSED")
    row = rows[0]
    verifier = SIGNED_ROOTS / digest / row["repository"] / row["path"]
    verifier_raw = regular_bytes(verifier)
    if (len(verifier_raw) != row.get("byte_length")
            or hashlib.sha256(verifier_raw).hexdigest() != row.get("sha256")):
        raise Refusal("PREDECESSOR_VERIFIER_DIGEST_REFUSED")
    env = os.environ.copy()
    env["REA_REMOTE_WEA_ROOT"] = str(INSTALLED)
    try:
        status = json.loads(command(
            ["/usr/bin/python3", str(verifier), "attestation-status"], env=env,
        ))
    except ValueError:
        raise Refusal("PREDECESSOR_VERIFIER_OUTPUT_REFUSED") from None
    wea_digest = hashlib.sha256(initial["wea"]).hexdigest()
    run_id = receipt.get("workflow_run_id")
    epoch = status.get("authority_epoch")
    if (status.get("verdict") != "PASS" or status.get("state") != "ENFORCING"
            or status.get("authority_generation") != 4
            or status.get("predecessor_verified") is not True
            or status.get("state_digest") != wea_digest
            or status.get("enforcement_bundle_manifest_digest") != digest
            or status.get("workflow_run_id") != run_id
            or not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0
            or receipt.get("schema_version") != RECEIPT_SCHEMA
            or receipt.get("event") != "workflow_dispatch"
            or receipt.get("issuer") != ISSUER_URL
            or receipt.get("workflow_repository") != REPOSITORY
            or receipt.get("workflow_run_attempt") != 1
            or receipt.get("wea_sha256") != wea_digest
            or receipt.get("manifest_sha256") != digest
            or not lower_hex(receipt.get("workflow_sha"), 40)):
        raise Refusal("PREDECESSOR_STATUS_RECEIPT_REFUSED")
    remote = run_state(run_id)
    if (remote.get("status") != "completed" or remote.get("conclusion") != "success"
            or remote.get("headSha") != receipt["workflow_sha"]
            or remote.get("headBranch") != receipt["workflow_ref"][10:]):
        raise Refusal("PREDECESSOR_RUN_REFUSED")
    verify_generation4_tag(receipt)
    if initial != {name: regular_bytes(path) for name, path in paths.items()}:
        raise Refusal("PREDECESSOR_FILES_DRIFT")
    return {"run_id": run_id, "wea_sha256": wea_digest, "epoch": epoch,
            "manifest_digest": digest}


def secret_metadata():
    value = api("repos/%s/actions/secrets/%s" % (TARGET_REPOSITORY, SECRET_NAME))
    if (not isinstance(value, dict) or value.get("name") != SECRET_NAME
            or not isinstance(value.get("created_at"), str)
            or not isinstance(value.get("updated_at"), str)):
        raise Refusal("DOWNSTREAM_SECRET_METADATA_REFUSED")
    return {"name": value["name"], "created_at": value["created_at"],
            "updated_at": value["updated_at"]}


def dispatch_public_retry(snapshot):
    before = json.loads(command([
        "gh", "run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
        "--limit", "1", "--json", "databaseId",
    ]))
    baseline = before[0]["databaseId"] if before else 0
    command([
        "gh", "workflow", "run", WORKFLOW, "--repo", REPOSITORY,
        "--ref", ISSUER_TAG,
        "-f", "mode=public_retry",
        "-f", "predecessor_run_id=%s" % snapshot["run_id"],
        "-f", "predecessor_wea_sha256=%s" % snapshot["wea_sha256"],
    ])
    for _attempt in range(60):
        rows = json.loads(command([
            "gh", "run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
            "--event", "workflow_dispatch", "--limit", "5", "--json",
            "databaseId,headBranch,headSha,status,conclusion,url",
        ]))
        matches = [row for row in rows if row.get("databaseId", 0) > baseline
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
        if run_state(run_id).get("status") == "completed":
            raise Refusal("ISSUER_FAILED_BEFORE_OWNER_GATE run=%s" % run_id)
        time.sleep(5)
    raise Refusal("ISSUER_OWNER_GATE_TIMEOUT run=%s" % run_id)


def verify_public_retry_jobs(run_id):
    value = api("repos/%s/actions/runs/%s/jobs?per_page=100" % (REPOSITORY, run_id))
    jobs = {row.get("name"): row for row in value.get("jobs", [])
            if isinstance(row, dict)} if isinstance(value, dict) else {}
    expected = {"preflight-predecessor", "preflight-sealed-transfer", "issue-wea",
                "seal-downstream", "renew-preflight", "renew-wea"}
    if set(jobs) != expected:
        raise Refusal("PUBLIC_RETRY_JOB_SET_REFUSED")
    for name in ("preflight-predecessor", "preflight-sealed-transfer", "issue-wea"):
        if jobs[name].get("conclusion") != "success":
            raise Refusal("PUBLIC_RETRY_JOB_RESULT_REFUSED job=%s" % name)
    for name in ("seal-downstream", "renew-preflight", "renew-wea"):
        if jobs[name].get("conclusion") != "skipped":
            raise Refusal("PUBLIC_RETRY_UNEXPECTED_PHASE job=%s" % name)


def verify_artifact(run_id):
    value = api("repos/%s/actions/runs/%s/artifacts?per_page=100" % (REPOSITORY, run_id))
    expected = "rea-write-enforcement-attestation-%s" % run_id
    matches = [row for row in value.get("artifacts", []) if isinstance(row, dict)
               and row.get("name") == expected and row.get("expired") is False
               and row.get("workflow_run", {}).get("id") == run_id
               and row.get("workflow_run", {}).get("head_branch") == ISSUER_TAG
               and row.get("workflow_run", {}).get("head_sha") == MANIFEST_HEAD] \
        if isinstance(value, dict) else []
    if len(matches) != 1:
        raise Refusal("ISSUER_ARTIFACT_REFUSED run=%s" % run_id)


def verify_public_packet(run_id):
    packet_tag = "rea-wea-generation-packet-%s" % run_id
    ref = api("repos/%s/git/ref/tags/%s" % (REPOSITORY, packet_tag))
    commit = peel_tag(ref)
    try:
        pointer = json.loads(content_bytes(PUBLIC_POINTER, commit))
    except ValueError:
        raise Refusal("PUBLIC_POINTER_REFUSED") from None
    files = pointer.get("files") if isinstance(pointer, dict) else None
    if (pointer.get("schema_version") != PUBLIC_SCHEMA
            or pointer.get("repository") != REPOSITORY
            or pointer.get("workflow_run_id") != run_id
            or pointer.get("packet_tag") != packet_tag
            or pointer.get("workflow_ref") != "refs/tags/%s" % ISSUER_TAG
            or pointer.get("workflow_sha") != MANIFEST_HEAD
            or pointer.get("packet_path") != "%s/packets/%s" % (PUBLIC_ROOT, run_id)
            or not isinstance(files, dict) or set(files) != PUBLIC_FILES
            or any(not lower_hex(value, 64) for value in files.values())):
        raise Refusal("PUBLIC_POINTER_IDENTITY_REFUSED")
    for name, expected in files.items():
        path = "%s/packets/%s/%s" % (PUBLIC_ROOT, run_id, name)
        if hashlib.sha256(content_bytes(path, commit)).hexdigest() != expected:
            raise Refusal("PUBLIC_PACKET_FILE_REFUSED path=%s" % name)
    receipt = json.loads(content_bytes(
        "%s/packets/%s/issuance_receipt.json" % (PUBLIC_ROOT, run_id), commit,
    ))
    if (receipt.get("workflow_run_id") != run_id
            or receipt.get("workflow_ref") != "refs/tags/%s" % ISSUER_TAG
            or receipt.get("workflow_sha") != MANIFEST_HEAD):
        raise Refusal("PUBLIC_PACKET_RECEIPT_REFUSED")


def review_boundary():
    value = run_state(REVIEW_RUN_ID)
    environment_id = pending_environment(REVIEW_RUN_ID)
    jobs = api("repos/%s/actions/runs/%s/jobs?per_page=100" % (
        REPOSITORY, REVIEW_RUN_ID,
    ))
    matches = [row for row in jobs.get("jobs", []) if isinstance(row, dict)
               and row.get("id") == REVIEW_JOB_ID and row.get("run_id") == REVIEW_RUN_ID
               and row.get("name") == "option-a-post-hoc-detection"
               and row.get("head_sha") == REVIEW_WORKFLOW_SHA
               and row.get("head_branch") == "main"] if isinstance(jobs, dict) else []
    if (value.get("status") != "waiting" or value.get("conclusion") not in ("", None)
            or value.get("headSha") != REVIEW_WORKFLOW_SHA
            or value.get("headBranch") != "main"
            or environment_id != 18598689835 or len(matches) != 1
            or matches[0].get("status") != "waiting"):
        raise Refusal("REVIEW_OWNER_GATE_REFUSED")


def preflight():
    runtime_ready()
    verify_manifest_pr(require_open=True)
    review_boundary()
    predecessor = predecessor_snapshot()
    secret_metadata()
    print("S152_PUBLIC_RETRY_PREFLIGHT_PASS review_run=%s manifest_pr=%s "
          "manifest_digest=%s predecessor_run=%s predecessor_epoch=%s "
          "mode=public_retry seal_phase=false secret_mutation=false" % (
              REVIEW_RUN_ID, MANIFEST_PR, MANIFEST_DIGEST,
              predecessor["run_id"], predecessor["epoch"],
          ))
    print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
    return 0


def run():
    runtime_ready()
    verify_manifest_pr(require_open=True)
    predecessor_snapshot()
    review_boundary()
    approve(REVIEW_RUN_ID, "exact renewal-safe public retry successor review")
    review = wait_success(REVIEW_RUN_ID, REVIEW_WORKFLOW_SHA, 120, "REVIEW")
    if review.get("headBranch") != "main":
        raise Refusal("REVIEW_WORKFLOW_REF_REFUSED")
    verify_manifest_pr(require_open=True)
    merge_manifest_pr()
    create_tag()
    # Bind the installed predecessor only after the review, merge, and tag.
    # A renewal between preflight and this point is accepted and used exactly.
    predecessor = predecessor_snapshot()
    secret_before = secret_metadata()
    issuer_run = dispatch_public_retry(predecessor)
    wait_owner_gate(issuer_run)
    if predecessor_snapshot() != predecessor:
        raise Refusal("PREDECESSOR_DRIFT_BEFORE_ISSUER_APPROVAL")
    approve(issuer_run, "sealed-free public retry successor issuance")
    issued = wait_success(issuer_run, MANIFEST_HEAD, 240, "ISSUER")
    if issued.get("headBranch") != ISSUER_TAG:
        raise Refusal("ISSUER_TAG_REFUSED")
    verify_public_retry_jobs(issuer_run)
    verify_artifact(issuer_run)
    verify_public_packet(issuer_run)
    if secret_metadata() != secret_before:
        raise Refusal("DOWNSTREAM_SECRET_MUTATION_REFUSED")
    print("S152_PUBLIC_RETRY_PASS review_run=%s manifest_pr=%s tag=%s "
          "issuer_run=%s artifact=verified public_packet=verified "
          "seal_phase=false secret_mutation=false" % (
              REVIEW_RUN_ID, MANIFEST_PR, ISSUER_TAG, issuer_run,
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
        print("REFUSE(S152_PUBLIC_RETRY_APPROVAL): %s" % exc, file=sys.stderr)
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false", file=sys.stderr)
        return 2
    except Exception as exc:
        print("REFUSE(S152_PUBLIC_RETRY_APPROVAL): UNEXPECTED_%s" % type(exc).__name__,
              file=sys.stderr)
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
