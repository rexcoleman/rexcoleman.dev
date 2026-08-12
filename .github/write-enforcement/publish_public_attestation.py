#!/usr/bin/env python3
"""Publish one verified WEA packet to an append-only Contents/Git surface.

The issuer's Actions artifact remains an operational copy.  This transition
adds a second, public transport whose readers need Contents:Read only.  Each
run receives a unique packet path and an annotated
``rea-wea-generation-packet-<run-id>`` tag protected from deletion and
retargeting by the existing generation-tag ruleset. ``latest.json`` inside
that immutable commit binds the exact issuer tag, workflow commit, packet path,
and every file digest. After genesis, the new packet's predecessor WEA must
byte-match the greatest previously published run.

This program carries no private key or repository-read credential.  It runs
after issuance verification with the job-scoped GitHub token and publishes
only the already-audited 11-file public packet.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


REPOSITORY = "rexcoleman/rexcoleman.dev"
TAG_PREFIX = "rea-wea-generation-packet-"
PUBLIC_ROOT = "rea-write-enforcement-packets"
POINTER = PUBLIC_ROOT + "/latest.json"
SCHEMA = "rea.write.public-attestation-pointer.v1"
EXPECTED_FILES = frozenset({
    "SHA256SUMS",
    "claim_policy.json",
    "claim_registry.json",
    "enforcement_bundle_manifest.json",
    "hybrid_capability_authority.json",
    "hybrid_capability_provider",
    "issuance_receipt.json",
    "predecessor_write_enforcement_attestation.json",
    "runtime_mount.py",
    "trusted_wea_public.pem",
    "write_enforcement_attestation.json",
})
EXECUTABLE_FILES = frozenset({"hybrid_capability_provider", "runtime_mount.py"})
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$")
REFUSAL_EXIT = 3


class Refusal(RuntimeError):
    pass


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def gh_api(path, *, method="GET", body=None, allow_not_found=False):
    argv = ["gh", "api", path]
    if method != "GET":
        argv.extend(["--method", method, "--input", "-"])
    completed = subprocess.run(
        argv,
        input=(json.dumps(body, separators=(",", ":")) if body is not None else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if allow_not_found and completed.returncode and (
        "HTTP 404" in completed.stderr or '"status":"404"' in completed.stderr
    ):
        return None
    if completed.returncode:
        raise Refusal("GIT_API_REFUSED exit=%s" % completed.returncode)
    try:
        return json.loads(completed.stdout)
    except ValueError:
        raise Refusal("GIT_API_MALFORMED") from None


def content_bytes(path: str, commit: str) -> bytes:
    value = gh_api("repos/%s/contents/%s?ref=%s" % (REPOSITORY, path, commit))
    try:
        if value.get("type") != "file" or value.get("path") != path:
            raise ValueError("identity")
        return base64.b64decode(value["content"].encode("ascii"), validate=True)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise Refusal("PUBLIC_CONTENT_MALFORMED path=%s" % path) from None


def validate_packet(root: Path, run_id: int, workflow_ref: str, workflow_sha: str,
                    genesis_predecessor_sha: str) -> tuple[dict, dict[str, str]]:
    paths = list(root.iterdir()) if root.is_dir() else []
    names = {path.name for path in paths if path.is_file() and not path.is_symlink()}
    if names != EXPECTED_FILES or len(paths) != len(EXPECTED_FILES):
        raise Refusal("PUBLIC_PACKET_FILE_SET_REFUSED")
    files = {name: sha((root / name).read_bytes()) for name in EXPECTED_FILES}
    try:
        lines = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError):
        raise Refusal("PUBLIC_PACKET_CHECKSUMS_REFUSED") from None
    claims = {}
    for line in lines:
        match = CHECKSUM.fullmatch(line)
        if match is None or match.group(2) in claims:
            raise Refusal("PUBLIC_PACKET_CHECKSUMS_REFUSED")
        claims[match.group(2)] = match.group(1)
    if set(claims) != EXPECTED_FILES - {"SHA256SUMS"}:
        raise Refusal("PUBLIC_PACKET_CHECKSUM_SET_REFUSED")
    if any(files[name] != digest for name, digest in claims.items()):
        raise Refusal("PUBLIC_PACKET_CHECKSUM_MISMATCH")
    try:
        receipt = json.loads((root / "issuance_receipt.json").read_bytes())
        manifest = json.loads((root / "enforcement_bundle_manifest.json").read_bytes())
    except (OSError, ValueError):
        raise Refusal("PUBLIC_PACKET_JSON_REFUSED") from None
    if (
        receipt.get("workflow_run_id") != run_id
        or receipt.get("workflow_repository") != REPOSITORY
        or receipt.get("event") != "workflow_dispatch"
        or receipt.get("workflow_ref") != workflow_ref
        or receipt.get("workflow_sha") != workflow_sha
        or receipt.get("wea_sha256") != files["write_enforcement_attestation.json"]
        or manifest.get("authority_generation") != 5
        or files["predecessor_write_enforcement_attestation.json"]
        != genesis_predecessor_sha
    ):
        raise Refusal("PUBLIC_PACKET_RECEIPT_BINDING_REFUSED")
    return receipt, files


def read_prior(head: str):
    try:
        value = json.loads(content_bytes(POINTER, head).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("PUBLIC_POINTER_MALFORMED") from None
    files = value.get("files") if isinstance(value, dict) else None
    if (
        value.get("schema_version") != SCHEMA
        or value.get("repository") != REPOSITORY
        or not isinstance(value.get("workflow_run_id"), int)
        or not isinstance(value.get("packet_path"), str)
        or not isinstance(files, dict)
        or set(files) != EXPECTED_FILES
        or any(not isinstance(item, str) or HEX64.fullmatch(item) is None
               for item in files.values())
    ):
        raise Refusal("PUBLIC_POINTER_IDENTITY_REFUSED")
    return value


def packet_tags():
    values = gh_api(
        "repos/%s/git/matching-refs/tags/%s" % (REPOSITORY, TAG_PREFIX)
    )
    rows = []
    for value in values if isinstance(values, list) else []:
        name = value.get("ref") if isinstance(value, dict) else None
        expected = "refs/tags/" + TAG_PREFIX
        suffix = name[len(expected):] if isinstance(name, str) and name.startswith(expected) else ""
        object_value = value.get("object", {}) if isinstance(value, dict) else {}
        if suffix.isdigit() and int(suffix) > 0 and object_value.get("type") == "tag":
            tag = gh_api("repos/%s/git/tags/%s" % (REPOSITORY, object_value.get("sha")))
            commit = tag.get("object", {}).get("sha") if isinstance(tag, dict) else None
            if tag.get("object", {}).get("type") != "commit" or not isinstance(commit, str) \
                    or HEX40.fullmatch(commit) is None:
                raise Refusal("PUBLIC_TAG_IDENTITY_REFUSED")
            rows.append((int(suffix), commit))
    return rows


def blob(raw: bytes) -> str:
    value = gh_api(
        "repos/%s/git/blobs" % REPOSITORY,
        method="POST",
        body={"content": base64.b64encode(raw).decode("ascii"), "encoding": "base64"},
    )
    digest = value.get("sha") if isinstance(value, dict) else None
    if not isinstance(digest, str) or HEX40.fullmatch(digest) is None:
        raise Refusal("PUBLIC_BLOB_IDENTITY_REFUSED")
    return digest


def publish(args) -> str:
    root = Path(args.issuance)
    _receipt, files = validate_packet(
        root, args.run_id, args.workflow_ref, args.workflow_sha,
        args.genesis_predecessor_wea_sha256,
    )
    rows = packet_tags()
    if any(run_id == args.run_id for run_id, _commit in rows):
        raise Refusal("PUBLIC_RUN_ALREADY_PUBLISHED")
    if rows:
        prior_run, prior_commit = max(rows, key=lambda row: row[0])
        prior = read_prior(prior_commit)
        if args.run_id <= prior["workflow_run_id"]:
            raise Refusal("PUBLIC_RUN_NOT_MONOTONIC")
        if files["predecessor_write_enforcement_attestation.json"] \
                != prior["files"]["write_enforcement_attestation.json"]:
            raise Refusal("PUBLIC_PREDECESSOR_CHAIN_REFUSED")
    commit = gh_api("repos/%s/git/commits/%s" % (REPOSITORY, args.workflow_sha))
    base_tree = commit.get("tree", {}).get("sha")
    if not isinstance(base_tree, str) or HEX40.fullmatch(base_tree) is None:
        raise Refusal("PUBLIC_BASE_TREE_REFUSED")
    packet_tag = TAG_PREFIX + str(args.run_id)
    packet_path = "%s/packets/%s" % (PUBLIC_ROOT, args.run_id)
    pointer = {
        "schema_version": SCHEMA,
        "repository": REPOSITORY,
        "workflow_run_id": args.run_id,
        "packet_tag": packet_tag,
        "workflow_ref": args.workflow_ref,
        "workflow_sha": args.workflow_sha,
        "packet_path": packet_path,
        "files": dict(sorted(files.items())),
    }
    entries = []
    for name in sorted(EXPECTED_FILES):
        entries.append({
            "path": "%s/%s" % (packet_path, name),
            "mode": "100755" if name in EXECUTABLE_FILES else "100644",
            "type": "blob",
            "sha": blob((root / name).read_bytes()),
        })
    entries.append({
        "path": POINTER, "mode": "100644", "type": "blob",
        "sha": blob((json.dumps(pointer, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")),
    })
    tree_body = {"tree": entries, "base_tree": base_tree}
    tree = gh_api("repos/%s/git/trees" % REPOSITORY, method="POST", body=tree_body)
    tree_sha = tree.get("sha") if isinstance(tree, dict) else None
    if not isinstance(tree_sha, str) or HEX40.fullmatch(tree_sha) is None:
        raise Refusal("PUBLIC_TREE_IDENTITY_REFUSED")
    commit = gh_api(
        "repos/%s/git/commits" % REPOSITORY,
        method="POST",
        body={
            "message": "publish WEA packet for issuer run %s" % args.run_id,
            "tree": tree_sha,
            "parents": [args.workflow_sha],
        },
    )
    new_head = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(new_head, str) or HEX40.fullmatch(new_head) is None:
        raise Refusal("PUBLIC_COMMIT_IDENTITY_REFUSED")
    tag_object = gh_api(
        "repos/%s/git/tags" % REPOSITORY,
        method="POST",
        body={
            "tag": packet_tag,
            "message": "Immutable public WEA packet for issuer run %s" % args.run_id,
            "object": new_head,
            "type": "commit",
        },
    )
    tag_sha = tag_object.get("sha") if isinstance(tag_object, dict) else None
    if not isinstance(tag_sha, str) or HEX40.fullmatch(tag_sha) is None:
        raise Refusal("PUBLIC_TAG_CREATE_REFUSED")
    gh_api(
        "repos/%s/git/refs" % REPOSITORY,
        method="POST",
        body={"ref": "refs/tags/%s" % packet_tag, "sha": tag_sha},
    )
    observed = gh_api("repos/%s/git/ref/tags/%s" % (REPOSITORY, packet_tag))
    if observed.get("object", {}).get("sha") != tag_sha:
        raise Refusal("PUBLIC_TAG_POSTCHECK_REFUSED")
    if json.loads(content_bytes(POINTER, new_head).decode("utf-8")) != pointer:
        raise Refusal("PUBLIC_POINTER_POSTCHECK_REFUSED")
    return new_head


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--issuance", required=True)
    value.add_argument("--run-id", required=True, type=int)
    value.add_argument("--workflow-ref", required=True)
    value.add_argument("--workflow-sha", required=True)
    value.add_argument("--genesis-predecessor-wea-sha256", required=True)
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    if (
        args.run_id <= 0
        or not args.workflow_ref.startswith("refs/tags/rea-wea-generation-")
        or HEX40.fullmatch(args.workflow_sha) is None
        or HEX64.fullmatch(args.genesis_predecessor_wea_sha256) is None
        or not os.environ.get("GH_TOKEN", "").strip()
    ):
        print("REFUSED PUBLIC_PUBLISH_INPUT_REFUSED", file=sys.stderr)
        return REFUSAL_EXIT
    try:
        head = publish(args)
    except Refusal as exc:
        print("REFUSED %s" % exc, file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT
    except Exception as exc:
        print("REFUSED UNEXPECTED_%s" % type(exc).__name__, file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT
    print(
        "PUBLIC_ATTESTATION_PUBLISHED tag=%s run_id=%s commit=%s "
        "files=11 immutable=true secret_bytes_printed=false"
        % (TAG_PREFIX + str(args.run_id), args.run_id, head)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
