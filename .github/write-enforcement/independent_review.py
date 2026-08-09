#!/usr/bin/env python3
"""Read-only Option A audit bound to an exact PR head and file digest."""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
ALLOWED_REPOSITORIES = {
    "rexcoleman/research_enforcement_activation": "master",
    "rexcoleman/rexcoleman.dev": "main",
}
SITE_RULESET_ID = 19768000
SITE_MANIFEST = ".github/write-enforcement/frozen_bundle_manifest.generation-4.json"
POLICY = "rea-option-a-posthoc-exact-head-v2"
MEMBER_CONTRACT = Path(__file__).with_name("member_contract.py")
GENERATION_MEMBER_COUNT = 235
REQUIRED_MEMBER_CLASSES = {
    "boundary_gate",
    "resolver",
    "readiness_consumer",
    "live_emitter_binding",
    "master_runner_binding",
    "project_runner_binding",
    "scaffold_installer",
    "invocation_receipt",
    "close_readiness_gate",
    "remote_workflow",
    "remote_ruleset",
    "claim_policy",
    "profile_registry",
    "trusted_public_key",
}


class Refusal(RuntimeError):
    """A fail-closed policy refusal."""


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def api(token: str, path: str, method: str = "GET", body: object | None = None):
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": POLICY,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise Refusal(f"GitHub API {method} {path} returned {exc.code}: {detail}") from exc
    if not payload:
        return None
    return json.loads(payload)


def installation_repositories(token: str) -> list[str]:
    response = api(token, "/installation/repositories?per_page=100")
    if response["total_count"] > 100:
        raise Refusal("installation repository population exceeds one audited page")
    return sorted(item["full_name"] for item in response["repositories"])


def pull_files(token: str, repo: str, number: int) -> list[dict]:
    values: list[dict] = []
    page = 1
    while True:
        response = api(token, f"/repos/{repo}/pulls/{number}/files?per_page=100&page={page}")
        values.extend(response)
        if len(response) < 100:
            break
        page += 1
        if page > 30:
            raise Refusal("pull-request file population exceeded 3,000")
    return [
        {
            "filename": item["filename"],
            "status": item["status"],
            "sha": item["sha"],
            "additions": item["additions"],
            "deletions": item["deletions"],
        }
        for item in values
    ]


def content_bytes(token: str, repo: str, path: str, ref: str) -> bytes:
    response = api(token, f"/repos/{repo}/contents/{path}?ref={ref}")
    if response.get("encoding") != "base64" or response.get("type") != "file":
        raise Refusal(f"content response for {path} is not an inline base64 file")
    return base64.b64decode(response["content"])


def expected_members() -> dict[str, tuple[str, str]]:
    source = MEMBER_CONTRACT.read_text()
    value: dict[str, tuple[str, str]] = {}
    for node in ast.parse(source).body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "EXPECTED_MEMBERS"
        ):
            value = ast.literal_eval(node.value)
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "EXPECTED_MEMBERS"
            and node.value.func.attr == "update"
            and len(node.value.args) == 1
            and not node.value.keywords
        ):
            value.update(ast.literal_eval(node.value.args[0]))
    if not isinstance(value, dict) or len(value) != GENERATION_MEMBER_COUNT:
        raise Refusal(
            "trusted member contract does not contain exactly "
            f"{GENERATION_MEMBER_COUNT} members"
        )
    return value


def manifest_contract(raw: bytes) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"generation-4 manifest is not JSON: {type(exc).__name__}") from exc
    expected_keys = {
        "schema_version",
        "authority_generation",
        "ruleset_id",
        "normalized_ruleset_sha256",
        "required_member_classes",
        "members",
        "manifest_digest",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise Refusal("generation-4 manifest has a non-canonical top-level shape")
    unsigned = dict(value)
    claimed = unsigned.pop("manifest_digest")
    if claimed != canonical_digest(unsigned):
        raise Refusal("generation-4 manifest self-digest differs")
    if (
        value["schema_version"] != "rea.write.enforcement-bundle-manifest.v1"
        or value["authority_generation"] != 4
        or value["ruleset_id"] != 19564990
        or set(value["required_member_classes"]) != REQUIRED_MEMBER_CLASSES
        or re.fullmatch(r"[0-9a-f]{64}", value["normalized_ruleset_sha256"])
        is None
        or not isinstance(value["members"], list)
        or len(value["members"]) != GENERATION_MEMBER_COUNT
    ):
        raise Refusal("generation-4 manifest contract differs")
    observed: dict[str, tuple[str, str]] = {}
    for row in value["members"]:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "member_id",
                "repository",
                "commit",
                "path",
                "sha256",
                "byte_length",
            }
            or not isinstance(row["member_id"], str)
            or row["member_id"] in observed
            or re.fullmatch(r"[0-9a-f]{40}", row["commit"]) is None
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
            or not isinstance(row["byte_length"], int)
            or row["byte_length"] <= 0
        ):
            raise Refusal("generation-4 manifest member shape differs")
        observed[row["member_id"]] = (row["repository"], row["path"])
    if observed != expected_members():
        raise Refusal("generation-4 manifest member contract differs")
    return {
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "manifest_digest": claimed,
        "member_count": GENERATION_MEMBER_COUNT,
        "member_contract": "EXACT",
    }


def ruleset_state(token: str, repo: str) -> dict:
    rulesets = api(token, f"/repos/{repo}/rulesets?includes_parents=false")
    if repo == "rexcoleman/rexcoleman.dev":
        candidates = [item for item in rulesets if item["id"] == SITE_RULESET_ID]
        if len(candidates) != 1:
            raise Refusal("site ruleset 19768000 is absent or duplicated")
        detail = api(token, f"/repos/{repo}/rulesets/{SITE_RULESET_ID}")
    else:
        candidates = [
            item
            for item in rulesets
            if item["name"] == "rea-master-second-principal"
        ]
        detail = None if not candidates else api(
            token, f"/repos/{repo}/rulesets/{candidates[0]['id']}"
        )
    if detail is None:
        return {"status": "NOT_YET_INSTALLED"}
    if detail["enforcement"] != "active":
        raise Refusal("branch ruleset is not active")
    if detail.get("bypass_actors") not in ([], None):
        raise Refusal("branch ruleset contains bypass actors")
    expected_ref = (
        "refs/heads/main"
        if repo == "rexcoleman/rexcoleman.dev"
        else "refs/heads/master"
    )
    ref_name = detail.get("conditions", {}).get("ref_name", {})
    if ref_name != {"exclude": [], "include": [expected_ref]}:
        raise Refusal("branch ruleset target differs")
    rule_types = sorted(rule.get("type") for rule in detail.get("rules", []))
    if rule_types != ["deletion", "non_fast_forward", "pull_request"]:
        raise Refusal("branch ruleset rule population differs")
    pull_rules = [rule for rule in detail["rules"] if rule["type"] == "pull_request"]
    if len(pull_rules) != 1:
        raise Refusal("ruleset does not contain exactly one pull-request rule")
    params = pull_rules[0]["parameters"]
    if params["required_approving_review_count"] != 0:
        raise Refusal("ruleset does not require exactly zero approving reviews")
    if not params["dismiss_stale_reviews_on_push"]:
        raise Refusal("ruleset does not dismiss stale reviews")
    if not params["required_review_thread_resolution"]:
        raise Refusal("ruleset does not require conversation resolution")
    return {
        "status": "ACTIVE",
        "id": detail["id"],
        "name": detail["name"],
        "bypass_actors": detail.get("bypass_actors"),
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": True,
        "required_review_thread_resolution": True,
        "target": expected_ref,
        "rule_types": rule_types,
    }


def read_state(token: str, args: argparse.Namespace) -> dict:
    pr = api(token, f"/repos/{args.repository}/pulls/{args.pull_request}")
    files = pull_files(token, args.repository, args.pull_request)
    reviews = api(
        token,
        f"/repos/{args.repository}/pulls/{args.pull_request}/reviews?per_page=100",
    )
    state = {
        "installation_repositories": installation_repositories(token),
        "pull_request": {
            "state": pr["state"],
            "draft": pr["draft"],
            "author": pr["user"]["login"],
            "base": pr["base"]["ref"],
            "head_ref": pr["head"]["ref"],
            "head_sha": pr["head"]["sha"],
        },
        "files": files,
        "files_sha256": canonical_digest(files),
        "ruleset": ruleset_state(token, args.repository),
        "reviews": sorted([
            {
                "actor": item["user"]["login"],
                "state": item["state"],
                "commit_id": item.get("commit_id"),
            }
            for item in reviews
        ], key=lambda item: (item["actor"], item["state"], item["commit_id"] or "")),
    }
    if args.repository == "rexcoleman/rexcoleman.dev":
        state["manifest"] = manifest_contract(
            content_bytes(
                token, args.repository, SITE_MANIFEST, args.expected_head
            )
        )
    return state


def assert_policy(state: dict, args: argparse.Namespace) -> None:
    if state["installation_repositories"] != sorted(ALLOWED_REPOSITORIES):
        raise Refusal(
            "App installation scope must be exactly research_enforcement_activation "
            "and rexcoleman.dev"
        )
    pr = state["pull_request"]
    expected_base = ALLOWED_REPOSITORIES[args.repository]
    if pr["state"] != "open" or pr["draft"]:
        raise Refusal("target pull request is not open and non-draft")
    if pr["author"] != "rexcoleman":
        raise Refusal("target pull request author is not rexcoleman")
    if pr["base"] != expected_base:
        raise Refusal(f"target base is not {expected_base}")
    if pr["head_sha"] != args.expected_head:
        raise Refusal("target head moved from the exact expected SHA")
    if state["files_sha256"] != args.expected_files_sha256:
        raise Refusal("pull-request file-set digest does not match predeclared digest")
    if args.repository == "rexcoleman/rexcoleman.dev":
        if [item["filename"] for item in state["files"]] != [SITE_MANIFEST]:
            raise Refusal("site review is not a one-file generation-4 manifest change")
        if not args.expected_manifest_sha256:
            raise Refusal("site review requires expected manifest SHA-256")
        if state["manifest"]["manifest_sha256"] != args.expected_manifest_sha256:
            raise Refusal("generation-4 manifest bytes do not match predeclared digest")
        if state["ruleset"]["status"] != "ACTIVE":
            raise Refusal("site review ruleset is not active")
        if state["ruleset"].get("bypass_actors") not in ([], None):
            raise Refusal("site ruleset re-admits a bypass actor")
        if state["ruleset"].get("required_approving_review_count") != 0:
            raise Refusal("site ruleset does not require zero approvals")
        if state["ruleset"].get("dismiss_stale_reviews_on_push") is not True:
            raise Refusal("site ruleset does not dismiss stale reviews")
        if state["ruleset"].get("required_review_thread_resolution") is not True:
            raise Refusal("site ruleset does not require conversation resolution")
        if state["ruleset"].get("target") != "refs/heads/main":
            raise Refusal("site ruleset targets the wrong branch")
        if state["ruleset"].get("rule_types") != [
            "deletion",
            "non_fast_forward",
            "pull_request",
        ]:
            raise Refusal("site ruleset rule population differs")


def run(args: argparse.Namespace) -> int:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise Refusal("GH_TOKEN is absent")
    if args.repository not in ALLOWED_REPOSITORIES:
        raise Refusal("repository is outside the two-repository policy")
    if len(args.expected_head) != 40 or any(
        char not in "0123456789abcdef" for char in args.expected_head
    ):
        raise Refusal("expected head is not a lowercase 40-hex SHA")
    for name, value in (
        ("expected files digest", args.expected_files_sha256),
        ("expected manifest digest", args.expected_manifest_sha256),
    ):
        if value and (
            len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise Refusal(f"{name} is not a lowercase SHA-256")

    before = read_state(token, args)
    assert_policy(before, args)
    second = read_state(token, args)
    assert_policy(second, args)
    if canonical_digest(before) != canonical_digest(second):
        raise Refusal("remote state changed during the read-only double read")

    evidence = {
        "policy": POLICY,
        "mode": args.mode,
        "repository": args.repository,
        "pull_request": args.pull_request,
        "head_sha": args.expected_head,
        "files_sha256": args.expected_files_sha256,
        "manifest_sha256": args.expected_manifest_sha256 or None,
        "state_sha256": canonical_digest(before),
        "mutation_count": 0,
    }
    print(
        "OPTION_A_POSTHOC_PREFLIGHT_PASS "
        + json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    )
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--mode", choices=("preflight",), required=True)
    value.add_argument("--repository", required=True)
    value.add_argument("--pull-request", required=True, type=int)
    value.add_argument("--expected-head", required=True)
    value.add_argument("--expected-files-sha256", required=True)
    value.add_argument("--expected-manifest-sha256", default="")
    return value


if __name__ == "__main__":
    try:
        sys.exit(run(parser().parse_args()))
    except (AssertionError, KeyError, Refusal, TypeError, ValueError) as exc:
        print(f"OPTION_A_POSTHOC_REFUSE: {exc}", file=sys.stderr)
        sys.exit(3)
