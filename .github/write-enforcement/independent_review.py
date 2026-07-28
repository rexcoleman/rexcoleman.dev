#!/usr/bin/env python3
"""Fail-closed GitHub App review bound to an exact PR head and file digest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

API = "https://api.github.com"
ALLOWED_REPOSITORIES = {
    "rexcoleman/research_enforcement_activation": "master",
    "rexcoleman/rexcoleman.dev": "main",
}
SITE_RULESET_ID = 19768000
SITE_MANIFEST = ".github/write-enforcement/frozen_bundle_manifest.generation-4.json"
POLICY = "rea-in-platform-second-principal-v1"
CHECK_NAME = "rea-independent-review/exact-head-v1"


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


def content_sha256(token: str, repo: str, path: str, ref: str) -> str:
    response = api(token, f"/repos/{repo}/contents/{path}?ref={ref}")
    if response.get("encoding") != "base64" or response.get("type") != "file":
        raise Refusal(f"content response for {path} is not an inline base64 file")
    return hashlib.sha256(base64.b64decode(response["content"])).hexdigest()


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
    pull_rules = [rule for rule in detail["rules"] if rule["type"] == "pull_request"]
    if len(pull_rules) != 1:
        raise Refusal("ruleset does not contain exactly one pull-request rule")
    params = pull_rules[0]["parameters"]
    if params["required_approving_review_count"] != 1:
        raise Refusal("ruleset does not require exactly one approving review")
    if not params["dismiss_stale_reviews_on_push"]:
        raise Refusal("ruleset does not dismiss stale reviews")
    return {
        "status": "ACTIVE",
        "id": detail["id"],
        "name": detail["name"],
        "bypass_actors": detail.get("bypass_actors"),
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": True,
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
        state["manifest_sha256"] = content_sha256(
            token, args.repository, SITE_MANIFEST, args.expected_head
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
        if state["manifest_sha256"] != args.expected_manifest_sha256:
            raise Refusal("generation-4 manifest bytes do not match predeclared digest")
        if state["ruleset"]["status"] != "ACTIVE":
            raise Refusal("site review ruleset is not active")
        if state["ruleset"].get("bypass_actors") not in ([], None):
            raise Refusal("site ruleset re-admits a bypass actor")
        if state["ruleset"].get("required_approving_review_count") != 1:
            raise Refusal("site ruleset does not require one approval")
        if state["ruleset"].get("dismiss_stale_reviews_on_push") is not True:
            raise Refusal("site ruleset does not dismiss stale reviews")
    elif args.mode == "approve" and state["ruleset"]["status"] != "ACTIVE":
        raise Refusal("REA approval is disabled until its branch ruleset is active")


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
    if args.mode == "preflight":
        print(
            "SECOND_PRINCIPAL_PREFLIGHT_PASS "
            + json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        )
        return 0

    if any(
        review["state"] == "APPROVED"
        and review["commit_id"] == args.expected_head
        for review in before["reviews"]
    ):
        raise Refusal("an approval already exists for this exact head")

    invocation = str(uuid.uuid4())
    check = api(
        token,
        f"/repos/{args.repository}/check-runs",
        "POST",
        {
            "name": CHECK_NAME,
            "head_sha": args.expected_head,
            "status": "completed",
            "conclusion": "success",
            "output": {
                "title": "Independent exact-head policy passed",
                "summary": (
                    f"policy={POLICY}\nhead={args.expected_head}\n"
                    f"state_sha256={evidence['state_sha256']}\n"
                    f"invocation={invocation}"
                ),
            },
        },
    )
    review = api(
        token,
        f"/repos/{args.repository}/pulls/{args.pull_request}/reviews",
        "POST",
        {
            "commit_id": args.expected_head,
            "event": "APPROVE",
            "body": (
                f"Independent in-platform review passed.\npolicy={POLICY}\n"
                f"head={args.expected_head}\nstate_sha256={evidence['state_sha256']}\n"
                f"invocation={invocation}\ncheck_run_id={check['id']}"
            ),
        },
    )
    print(
        "SECOND_PRINCIPAL_APPROVAL_PASS "
        f"head={args.expected_head} check_run_id={check['id']} "
        f"review_id={review['id']} state_sha256={evidence['state_sha256']}"
    )
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--mode", choices=("preflight", "approve"), required=True)
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
        print(f"SECOND_PRINCIPAL_REFUSE: {exc}", file=sys.stderr)
        sys.exit(3)
