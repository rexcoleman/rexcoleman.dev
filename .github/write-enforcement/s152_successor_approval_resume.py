#!/usr/bin/env python3
"""Checked approval-only completion of the s152 public-packet successor."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HOST = "gios-dev"
MARKER = "rea-s152-sealed-successor-approval-v3"
REPOSITORY = "rexcoleman/rexcoleman.dev"
ENVIRONMENT = "rea-write-enforcement-issuer"
WORKFLOW = "issue-write-enforcement-attestation.yml"
REVIEW_RUN_ID = 31597379743
REVIEW_WORKFLOW_SHA = "8ef44d4314ca621ae340591727a3cd62b24bd2ef"
MANIFEST_PR = 76
MANIFEST_HEAD = "d97fd5520ec3f38a7cd13f1b9899a76ff83c14d8"
MANIFEST_PATH = ".github/write-enforcement/frozen_bundle_manifest.generation-5.json"
MANIFEST_FILE = Path("/data/tmp/rexdev_s152_successor_review") / MANIFEST_PATH
MANIFEST_FILE_SHA256 = "185263455c5f88687df3b057b3e1d6d3ca02a3a445c78c8629e648257bc835cf"
MANIFEST_DIGEST = "61b14636f83daaf080cc8db1cda412b2aa762fb3b5ba0b9f8f4b96e3ce9ae612"
ISSUER_TAG = "rea-wea-generation-5-d97fd5520ec3"
TARGET_REPOSITORY = "rexcoleman/research_enforcement_activation"
SECRET_NAME = "REA_BUNDLE_READ_TOKEN"
TRANSFER_TOOL = Path(__file__).with_name("provision_downstream_bundle_secret.py")
INSTALLED = Path("/home/azureuser/.local/state/rea_enforcement/remote_wea")
SIGNED_ROOTS = Path(
    "/home/azureuser/.local/state/rea_enforcement/signed_member_roots"
)
GENERATION4_TAG_PREFIX = "refs/tags/rea-wea-generation-4-"
GENERATION4_MEMBER_COUNT = 244
MANIFEST_SCHEMA = "rea.write.enforcement-bundle-manifest.v1"
RECEIPT_SCHEMA = "rea.write.remote-issuance-receipt.v1"
ISSUER_URL = (
    "https://github.com/rexcoleman/rexcoleman.dev/actions/workflows/"
    "issue-write-enforcement-attestation.yml"
)


class Refusal(RuntimeError):
    pass


def command(argv, stdin_value=None, env=None):
    completed = subprocess.run(
        argv, input=stdin_value, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, env=env,
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


def verify_issuer_tag():
    path = "repos/%s/git/ref/tags/%s" % (REPOSITORY, ISSUER_TAG)
    existing = api(path, allow_not_found=True)
    if existing is None or peel_tag(existing) != MANIFEST_HEAD:
        raise Refusal("GENERATION_TAG_IDENTITY_REFUSED")


def regular_bytes(path):
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise Refusal("PREDECESSOR_NONREGULAR path=%s" % path.name)
        raw = path.read_bytes()
        after = path.lstat()
    except (OSError, ValueError):
        raise Refusal("PREDECESSOR_READ_REFUSED path=%s" % path.name) from None
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise Refusal("PREDECESSOR_FILE_DRIFT path=%s" % path.name)
    return raw


def json_bytes(path):
    raw = regular_bytes(path)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("PREDECESSOR_JSON_REFUSED path=%s" % path.name) from None
    if not isinstance(value, dict):
        raise Refusal("PREDECESSOR_JSON_REFUSED path=%s" % path.name)
    return raw, value


def verify_generation4_tag(receipt):
    workflow_ref = receipt.get("workflow_ref")
    if not isinstance(workflow_ref, str) or not workflow_ref.startswith(
        GENERATION4_TAG_PREFIX
    ):
        raise Refusal("PREDECESSOR_TAG_REFUSED")
    tag_name = workflow_ref[len("refs/tags/"):]
    ref = api("repos/%s/git/ref/tags/%s" % (REPOSITORY, tag_name))
    if peel_tag(ref) != receipt.get("workflow_sha"):
        raise Refusal("PREDECESSOR_TAG_REFUSED")


def lower_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(char in "0123456789abcdef" for char in value))


def validate_status_receipt(status, receipt, wea_digest, manifest_digest):
    run_id = receipt.get("workflow_run_id")
    epoch = status.get("authority_epoch")
    if (
        status.get("verdict") != "PASS" or status.get("state") != "ENFORCING"
        or status.get("authority_generation") != 4
        or status.get("predecessor_verified") is not True
        or status.get("remote_issued") is not True
        or status.get("state_digest") != wea_digest
        or status.get("enforcement_bundle_manifest_digest") != manifest_digest
        or not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0
        or status.get("workflow_run_id") != run_id
        or not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0
    ):
        raise Refusal("PREDECESSOR_VERIFIER_STATUS_REFUSED")
    if (
        receipt.get("schema_version") != RECEIPT_SCHEMA
        or receipt.get("event") != "workflow_dispatch"
        or receipt.get("issuer") != ISSUER_URL
        or receipt.get("workflow_repository") != REPOSITORY
        or receipt.get("workflow_run_attempt") != 1
        or receipt.get("wea_sha256") != wea_digest
        or receipt.get("manifest_sha256") != manifest_digest
        or receipt.get("issued_at") != status.get("issued_at")
        or not lower_hex(receipt.get("workflow_sha"), 40)
        or not lower_hex(receipt.get("workflow_blob_sha256"), 64)
    ):
        raise Refusal("PREDECESSOR_RECEIPT_REFUSED")
    return run_id, epoch


def predecessor_snapshot():
    paths = {
        "wea": INSTALLED / "write_enforcement_attestation.json",
        "receipt": INSTALLED / "issuance_receipt.json",
        "manifest": INSTALLED / "enforcement_bundle_manifest.json",
        "predecessor": INSTALLED / "predecessor_write_enforcement_attestation.json",
    }
    initial = {name: regular_bytes(path) for name, path in paths.items()}
    try:
        wea = json.loads(initial["wea"].decode("utf-8"))
        receipt = json.loads(initial["receipt"].decode("utf-8"))
        manifest = json.loads(initial["manifest"].decode("utf-8"))
        json.loads(initial["predecessor"].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("PREDECESSOR_JSON_REFUSED") from None
    if not all(isinstance(row, dict) for row in (wea, receipt, manifest)):
        raise Refusal("PREDECESSOR_JSON_REFUSED")
    members = manifest.get("members")
    ids = [row.get("member_id") for row in members if isinstance(row, dict)] \
        if isinstance(members, list) else []
    digest = manifest.get("manifest_digest")
    verifier_rows = [row for row in members if isinstance(row, dict)
                     and row.get("member_id") == "verify-only-resolver"] \
        if isinstance(members, list) else []
    if (
        manifest.get("schema_version") != MANIFEST_SCHEMA
        or manifest.get("authority_generation") != 4
        or not isinstance(digest, str) or len(digest) != 64
        or len(ids) != GENERATION4_MEMBER_COUNT
        or len(set(ids)) != GENERATION4_MEMBER_COUNT
        or len(verifier_rows) != 1
    ):
        raise Refusal("PREDECESSOR_MANIFEST_REFUSED")
    canonical = dict(manifest)
    canonical.pop("manifest_digest", None)
    calculated = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if calculated != digest:
        raise Refusal("PREDECESSOR_MANIFEST_DIGEST_REFUSED")
    verifier_row = verifier_rows[0]
    if (
        verifier_row.get("repository") != "research_enforcement_activation"
        or verifier_row.get("path") != "write_integrity/attestation/wea_verifier.py"
    ):
        raise Refusal("PREDECESSOR_VERIFIER_ROW_REFUSED")
    verifier = SIGNED_ROOTS / digest / verifier_row["repository"] / verifier_row["path"]
    verifier_raw = regular_bytes(verifier)
    if (len(verifier_raw) != verifier_row.get("byte_length")
            or hashlib.sha256(verifier_raw).hexdigest() != verifier_row.get("sha256")):
        raise Refusal("PREDECESSOR_VERIFIER_DIGEST_REFUSED")
    verifier_env = os.environ.copy()
    verifier_env["REA_REMOTE_WEA_ROOT"] = str(INSTALLED)
    try:
        status = json.loads(command(
            ["/usr/bin/python3", str(verifier), "attestation-status"],
            env=verifier_env,
        ))
    except ValueError:
        raise Refusal("PREDECESSOR_VERIFIER_OUTPUT_REFUSED") from None
    wea_digest = hashlib.sha256(initial["wea"]).hexdigest()
    run_id, epoch = validate_status_receipt(status, receipt, wea_digest, digest)
    remote = run_state(run_id)
    if (
        remote.get("status") != "completed" or remote.get("conclusion") != "success"
        or remote.get("headSha") != receipt["workflow_sha"]
        or remote.get("headBranch") != receipt["workflow_ref"][len("refs/tags/"):]
    ):
        raise Refusal("PREDECESSOR_RUN_REFUSED")
    verify_generation4_tag(receipt)
    final = {name: regular_bytes(path) for name, path in paths.items()}
    if initial != final:
        raise Refusal("PREDECESSOR_FILES_DRIFT")
    return {
        "run_id": run_id,
        "wea_sha256": wea_digest,
        "epoch": epoch,
        "manifest_digest": digest,
        "workflow_ref": receipt["workflow_ref"],
        "workflow_sha": receipt["workflow_sha"],
        "issued_at": receipt["issued_at"],
        "file_hashes": {name: hashlib.sha256(raw).hexdigest()
                        for name, raw in initial.items()},
    }


def dispatch_workflow(snapshot, mode, fields):
    rows = json.loads(command([
        "gh", "run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
        "--limit", "1", "--json", "databaseId",
    ]))
    baseline = rows[0]["databaseId"] if rows else 0
    argv = [
        "gh", "workflow", "run", WORKFLOW, "--repo", REPOSITORY,
        "--ref", ISSUER_TAG, "-f", "mode=%s" % mode,
        "-f", "predecessor_run_id=%s" % snapshot["run_id"],
        "-f", "predecessor_wea_sha256=%s" % snapshot["wea_sha256"],
    ]
    for key, value in sorted(fields.items()):
        argv.extend(["-f", "%s=%s" % (key, value)])
    command(argv)
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


def downstream_public_key():
    value = api("repos/%s/actions/secrets/public-key" % TARGET_REPOSITORY)
    try:
        raw = base64.b64decode(value["key"].encode("ascii"), validate=True)
        key_id = value["key_id"]
    except (AttributeError, KeyError, TypeError, ValueError):
        raise Refusal("DOWNSTREAM_PUBLIC_KEY_REFUSED") from None
    if len(raw) != 32 or not isinstance(key_id, str) or not key_id.isdigit():
        raise Refusal("DOWNSTREAM_PUBLIC_KEY_REFUSED")
    return {
        "key_id": key_id, "key_b64": value["key"],
        "key_sha256": hashlib.sha256(raw).hexdigest(),
    }


def sealed_packet(run_id, key):
    artifacts = api("repos/%s/actions/runs/%s/artifacts" % (REPOSITORY, run_id))
    expected = "rea-downstream-sealed-secret-%s" % run_id
    matches = [row for row in artifacts.get("artifacts", [])
               if isinstance(row, dict) and row.get("name") == expected
               and row.get("expired") is False
               and row.get("workflow_run", {}).get("id") == run_id]
    if len(matches) != 1:
        raise Refusal("SEALED_ARTIFACT_REFUSED")
    with tempfile.TemporaryDirectory(prefix="rea-s152-sealed-") as temporary:
        root = Path(temporary)
        command([
            "gh", "run", "download", str(run_id), "--repo", REPOSITORY,
            "--name", expected, "--dir", str(root),
        ])
        path = root / "sealed-transfer.json"
        try:
            value = json.loads(path.read_bytes())
        except (OSError, ValueError):
            raise Refusal("SEALED_PACKET_REFUSED") from None
        ciphertext_sha = value.get("ciphertext_sha256")
        if not lower_hex(ciphertext_sha, 64):
            raise Refusal("SEALED_PACKET_REFUSED")
        command([
            "/usr/bin/python3", str(TRANSFER_TOOL), "verify",
            "--packet", str(path), "--manifest", str(MANIFEST_FILE),
            "--key-id", key["key_id"],
            "--public-key-sha256", key["key_sha256"],
            "--ciphertext-sha256", ciphertext_sha,
            "--run-id", str(run_id), "--workflow-ref", "refs/tags/%s" % ISSUER_TAG,
            "--workflow-sha", MANIFEST_HEAD,
        ])
        return value


def submit_ciphertext(packet, key):
    if downstream_public_key() != key:
        raise Refusal("DOWNSTREAM_PUBLIC_KEY_DRIFT")
    before = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    value = api(
        "repos/%s/actions/secrets/%s" % (TARGET_REPOSITORY, SECRET_NAME),
        method="PUT", body={
            "encrypted_value": packet["ciphertext_b64"], "key_id": key["key_id"],
        },
    )
    if value is not None:
        raise Refusal("DOWNSTREAM_SECRET_WRITE_RESPONSE_REFUSED")
    observed = api("repos/%s/actions/secrets/%s" % (
        TARGET_REPOSITORY, SECRET_NAME,
    ))
    try:
        updated = dt.datetime.fromisoformat(
            observed["updated_at"].replace("Z", "+00:00")
        ).astimezone(dt.timezone.utc)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise Refusal("DOWNSTREAM_SECRET_POSTCHECK_REFUSED") from None
    if observed.get("name") != SECRET_NAME or updated < before:
        raise Refusal("DOWNSTREAM_SECRET_POSTCHECK_REFUSED")
    if downstream_public_key() != key:
        raise Refusal("DOWNSTREAM_PUBLIC_KEY_DRIFT")


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
    predecessor = predecessor_snapshot()
    verify_manifest_pr(require_open=True)
    review = run_state(REVIEW_RUN_ID)
    if (review.get("status") == "completed"
            or review.get("headSha") != REVIEW_WORKFLOW_SHA
            or review.get("headBranch") != "main"
            or pending_environment(REVIEW_RUN_ID) is None):
        raise Refusal("REVIEW_STATE_REFUSED")
    key = downstream_public_key()
    print("PREFLIGHT_PASS host=gios-dev review_run=%s manifest_pr=%s "
          "manifest_digest=%s predecessor_run=%s predecessor_epoch=%s "
          "downstream_key_id=%s owner_credential_handling=false mutation=false" % (
              REVIEW_RUN_ID, MANIFEST_PR, MANIFEST_DIGEST,
              predecessor["run_id"], predecessor["epoch"], key["key_id"]
          ))
    print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
    return 0


def run():
    runtime_ready()
    predecessor = predecessor_snapshot()
    review = run_state(REVIEW_RUN_ID)
    if review.get("status") == "completed":
        if (review.get("conclusion") != "success"
                or review.get("headSha") != REVIEW_WORKFLOW_SHA
                or review.get("headBranch") != "main"):
            raise Refusal("REVIEW_STATE_REFUSED")
    else:
        approve(REVIEW_RUN_ID, "exact public-packet successor review")
        review = wait_success(REVIEW_RUN_ID, REVIEW_WORKFLOW_SHA, 120, "REVIEW")
        if review.get("headBranch") != "main":
            raise Refusal("REVIEW_WORKFLOW_REF_REFUSED")
    verify_manifest_pr(require_open=True)
    merge_manifest_pr()
    create_tag()
    current = predecessor_snapshot()
    if current != predecessor:
        raise Refusal("PREDECESSOR_DRIFT_REFUSED")
    key = downstream_public_key()
    seal_run = dispatch_workflow(current, "seal_downstream", {
        "downstream_key_id": key["key_id"],
        "downstream_public_key_b64": key["key_b64"],
        "downstream_public_key_sha256": key["key_sha256"],
    })
    wait_owner_gate(seal_run)
    approve(seal_run, "sealed downstream bundle transfer")
    sealed = wait_success(seal_run, MANIFEST_HEAD, 240, "SEALED_TRANSFER")
    if sealed.get("headBranch") != ISSUER_TAG:
        raise Refusal("SEALED_TRANSFER_TAG_REFUSED")
    packet = sealed_packet(seal_run, key)
    submit_ciphertext(packet, key)
    current = predecessor_snapshot()
    issuer_run = dispatch_workflow(current, "capability_change", {
        "downstream_key_id": key["key_id"],
        "downstream_public_key_sha256": key["key_sha256"],
        "sealed_transfer_run_id": seal_run,
        "sealed_ciphertext_sha256": packet["ciphertext_sha256"],
    })
    wait_owner_gate(issuer_run)
    approve(issuer_run, "sealed public-packet successor issuance")
    issued = wait_success(issuer_run, MANIFEST_HEAD, 240, "ISSUER")
    if issued.get("headBranch") != ISSUER_TAG:
        raise Refusal("ISSUER_TAG_REFUSED")
    verify_artifact(issuer_run)
    print("S152_SEALED_SUCCESSOR_PASS review_run=%s manifest_pr=%s tag=%s "
          "seal_run=%s issuer_run=%s artifact=verified plaintext_exposed=false" % (
              REVIEW_RUN_ID, MANIFEST_PR, ISSUER_TAG, seal_run, issuer_run
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
