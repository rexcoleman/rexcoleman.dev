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
SITE_MANIFEST = ".github/write-enforcement/frozen_bundle_manifest.generation-5.json"
POLICY = "rea-option-a-posthoc-exact-head-v2"
MEMBER_CONTRACT = Path(__file__).with_name("member_contract.py")
CONVERGENCE_INDEX = Path(__file__).with_name("signed_release_convergence_index.json")
ADAPTER_DIRECTORY = Path(__file__).with_name("adapters")
AUTHORITY_GENERATION = 5
REA_POPULATION_ADAPTER = re.compile(
    r"research-enforcement-activation-generation-5-population-([1-9][0-9]*)-v1"
)
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


def _member_map(value: object, subject: str) -> dict[str, tuple[str, str]]:
    if not isinstance(value, dict) or not value:
        raise Refusal(f"trusted member contract {subject} is not a nonempty map")
    result: dict[str, tuple[str, str]] = {}
    for member_id, row in value.items():
        if (
            not isinstance(member_id, str)
            or not member_id
            or not isinstance(row, tuple)
            or len(row) != 2
            or not all(isinstance(item, str) and item for item in row)
            or Path(row[1]).is_absolute()
            or ".." in Path(row[1]).parts
        ):
            raise Refusal(f"trusted member contract {subject} row differs")
        result[member_id] = row
    return result


def _json_file(path: Path, subject: str) -> object:
    try:
        if (
            path.is_symlink()
            or not path.is_file()
            or path.resolve().parent != path.parent.resolve()
        ):
            raise Refusal(f"{subject} path differs")
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"{subject} is unavailable: {type(exc).__name__}") from exc


def _registered_adapter_path() -> tuple[Path, int]:
    value = _json_file(CONVERGENCE_INDEX, "signed release convergence index")
    expected_keys = {
        "adapters",
        "documentation",
        "engine",
        "focused_tests",
        "index_guide",
        "cross_generation_inventory",
        "schema_version",
        "workflow",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value["schema_version"] != "rea.signed-release-convergence-index.v1"
        or value["documentation"] != "SIGNED_RELEASE_CONVERGENCE.md"
        or value["engine"] != "signed_release_convergence.py"
        or value["focused_tests"] != "tests/test_signed_release_convergence.py"
        or value["index_guide"] != "SIGNED_RELEASE_CONVERGENCE_INDEX.md"
        or value["cross_generation_inventory"]
        != "signed_release_convergence_inventory.json"
        or value["workflow"] != "../workflows/signed-release-convergence.yml"
        or not isinstance(value["adapters"], list)
        or not value["adapters"]
    ):
        raise Refusal("signed release convergence index contract differs")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    registered_populations: set[int] = set()
    populations: dict[int, str] = {}
    for row in value["adapters"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"adapter_id", "path", "status"}
            or not isinstance(row["adapter_id"], str)
            or not isinstance(row["path"], str)
            or row["status"] not in {"active", "retired"}
            or row["adapter_id"] in seen_ids
            or row["path"] in seen_paths
        ):
            raise Refusal("signed release convergence index adapter row differs")
        seen_ids.add(row["adapter_id"])
        seen_paths.add(row["path"])
        match = REA_POPULATION_ADAPTER.fullmatch(row["adapter_id"])
        if match is None:
            continue
        population = int(match.group(1))
        expected_path = (
            f"adapters/research_enforcement_activation.population-{population}-v1.json"
        )
        if row["path"] != expected_path or population in registered_populations:
            raise Refusal("registered REA population adapter identity is ambiguous")
        registered_populations.add(population)
        if row["status"] == "active":
            populations[population] = row["path"]
    if not populations:
        raise Refusal("registered REA population adapter is absent")
    selected_population = max(populations)
    relative = Path(populations[selected_population])
    selected = CONVERGENCE_INDEX.parent / relative
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or selected.parent.resolve() != ADAPTER_DIRECTORY.resolve()
    ):
        raise Refusal("registered REA population adapter path differs")
    return selected, selected_population


def _registered_adapter() -> dict:
    selected, selected_population = _registered_adapter_path()
    value = _json_file(selected, "registered population adapter")
    required = {
        "adapter_id",
        "authority_generation",
        "expected_member_count",
        "manifest_builder",
        "manifest_builder_flag",
        "manifest_path",
        "schema_version",
    }
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or value["schema_version"] != "rea.signed-release-convergence-adapter.v1"
        or value["adapter_id"]
        != (
            "research-enforcement-activation-generation-5-population-"
            f"{selected_population}-v1"
        )
        or value["authority_generation"] != AUTHORITY_GENERATION
        or not isinstance(value["expected_member_count"], int)
        or isinstance(value["expected_member_count"], bool)
        or value["expected_member_count"] != selected_population
        or value["manifest_builder"]
        != ".github/write-enforcement/build_frozen_manifest.py"
        or not isinstance(value["manifest_builder_flag"], str)
        or re.fullmatch(
            r"--[a-z0-9]+(?:-[a-z0-9]+)*-successor",
            value["manifest_builder_flag"],
        )
        is None
        or value["manifest_path"] != SITE_MANIFEST
    ):
        raise Refusal("registered population adapter contract differs")
    selector = value["manifest_builder_flag"][2:].replace("-", "_") + "_members"
    if selector != _terminal_successor_selector():
        raise Refusal("registered population adapter is not the terminal successor")
    if len(structural_members(selector)) != selected_population:
        raise Refusal("registered population differs from structural member contract")
    return value


def _selector_layers(tree: ast.Module, selector: str) -> list[str]:
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    resolving: set[str] = set()

    def resolve(name: str) -> list[str]:
        if name in resolving or name not in functions:
            raise Refusal(f"trusted member selector is absent or recursive: {name}")
        resolving.add(name)
        function = functions[name]
        for call in (
            item for item in ast.walk(function) if isinstance(item, ast.Call)
        ):
            if (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "value"
                and call.func.attr
                in {"clear", "pop", "popitem", "setdefault", "__delitem__", "__setitem__"}
            ):
                raise Refusal(f"trusted member selector mutation differs: {name}")
        layers: list[str] | None = None
        extensions: list[str] = []
        returned = False
        for node in function.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "value"
                and isinstance(node.value, ast.Call)
                and not node.value.keywords
            ):
                called = node.value.func
                if (
                    isinstance(called, ast.Name)
                    and called.id == "dict"
                    and len(node.value.args) == 1
                    and isinstance(node.value.args[0], ast.Name)
                    and node.value.args[0].id == "EXPECTED_MEMBERS"
                ):
                    layers = ["EXPECTED_MEMBERS"]
                elif (
                    isinstance(called, ast.Name)
                    and not node.value.args
                    and called.id.endswith("_members")
                ):
                    layers = resolve(called.id)
                else:
                    raise Refusal(f"trusted member selector base differs: {name}")
            elif (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and isinstance(node.value.func.value, ast.Name)
                and node.value.func.value.id == "value"
                and node.value.func.attr == "update"
                and len(node.value.args) == 1
                and not node.value.keywords
                and isinstance(node.value.args[0], ast.Name)
            ):
                extensions.append(node.value.args[0].id)
            elif (
                isinstance(node, ast.For)
                and isinstance(node.target, ast.Name)
                and isinstance(node.iter, (ast.Tuple, ast.List))
                and all(isinstance(item, ast.Name) for item in node.iter.elts)
            ):
                update_calls = [
                    item
                    for item in node.body
                    if isinstance(item, ast.Expr)
                    and isinstance(item.value, ast.Call)
                    and isinstance(item.value.func, ast.Attribute)
                    and isinstance(item.value.func.value, ast.Name)
                    and item.value.func.value.id == "value"
                    and item.value.func.attr == "update"
                    and len(item.value.args) == 1
                    and isinstance(item.value.args[0], ast.Name)
                    and item.value.args[0].id == node.target.id
                ]
                if len(update_calls) != 1:
                    raise Refusal(f"trusted member selector loop differs: {name}")
                extensions.extend(item.id for item in node.iter.elts)
            elif (
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Name)
                and node.value.id == "value"
            ):
                returned = True
        resolving.remove(name)
        if layers is None or not returned or not extensions:
            raise Refusal(f"trusted member selector shape differs: {name}")
        return layers + extensions

    return resolve(selector)


def _terminal_successor_selector() -> str:
    try:
        tree = ast.parse(MEMBER_CONTRACT.read_text())
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        raise Refusal(
            f"trusted member contract is unavailable: {type(exc).__name__}"
        ) from exc
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and (node.name == "successor_members" or node.name.endswith("_successor_members"))
    }
    if not functions:
        raise Refusal("trusted successor selector graph is absent")
    populations: dict[str, int] = {}
    for name in functions:
        _selector_layers(tree, name)
        populations[name] = len(structural_members(name))
    largest = max(populations.values())
    terminals = {
        name for name, population in populations.items() if population == largest
    }
    if len(terminals) != 1:
        raise Refusal("trusted successor selector terminal is ambiguous")
    return next(iter(terminals))


def structural_members(selector: str) -> dict[str, tuple[str, str]]:
    try:
        tree = ast.parse(MEMBER_CONTRACT.read_text())
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        raise Refusal(
            f"trusted member contract is unavailable: {type(exc).__name__}"
        ) from exc
    maps: dict[str, dict[str, tuple[str, str]]] = {}
    base_updates: list[dict[str, tuple[str, str]]] = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and (
                node.targets[0].id == "EXPECTED_MEMBERS"
                or node.targets[0].id.endswith("_ADDITIONAL_MEMBERS")
            )
        ):
            name = node.targets[0].id
            try:
                maps[name] = _member_map(ast.literal_eval(node.value), name)
            except (ValueError, SyntaxError) as exc:
                raise Refusal(f"trusted member contract literal differs: {name}") from exc
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
            try:
                base_updates.append(
                    _member_map(ast.literal_eval(node.value.args[0]), "EXPECTED_MEMBERS.update")
                )
            except (ValueError, SyntaxError) as exc:
                raise Refusal("trusted member contract base update differs") from exc
    if "EXPECTED_MEMBERS" not in maps:
        raise Refusal("trusted member contract base is absent")
    for update in base_updates:
        if set(maps["EXPECTED_MEMBERS"]) & set(update):
            raise Refusal("trusted member contract base update collides")
        maps["EXPECTED_MEMBERS"].update(update)
    layers = _selector_layers(tree, selector)
    if len(layers) != len(set(layers)) or any(layer not in maps for layer in layers):
        raise Refusal("trusted member selector layer set differs")
    value: dict[str, tuple[str, str]] = {}
    for layer in layers:
        extension = maps[layer]
        if set(value) & set(extension):
            raise Refusal(f"trusted member selector layer collides: {layer}")
        value.update(extension)
    if len(set(value.values())) != len(value):
        raise Refusal("trusted member selector subject collision")
    return value


def expected_members() -> dict[str, tuple[str, str]]:
    adapter = _registered_adapter()
    selector = adapter["manifest_builder_flag"][2:].replace("-", "_") + "_members"
    value = structural_members(selector)
    if len(value) != adapter["expected_member_count"]:
        raise Refusal("trusted member contract differs from registered adapter count")
    return value


def manifest_contract(raw: bytes) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"generation-5 manifest is not JSON: {type(exc).__name__}") from exc
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
        raise Refusal("generation-5 manifest has a non-canonical top-level shape")
    unsigned = dict(value)
    claimed = unsigned.pop("manifest_digest")
    if claimed != canonical_digest(unsigned):
        raise Refusal("generation-5 manifest self-digest differs")
    expected = expected_members()
    if (
        value["schema_version"] != "rea.write.enforcement-bundle-manifest.v1"
        or value["authority_generation"] != AUTHORITY_GENERATION
        or value["ruleset_id"] != 19564990
        or set(value["required_member_classes"]) != REQUIRED_MEMBER_CLASSES
        or re.fullmatch(r"[0-9a-f]{64}", value["normalized_ruleset_sha256"])
        is None
        or not isinstance(value["members"], list)
        or len(value["members"]) != len(expected)
    ):
        raise Refusal("generation-5 manifest contract differs")
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
            raise Refusal("generation-5 manifest member shape differs")
        observed[row["member_id"]] = (row["repository"], row["path"])
    if observed != expected:
        raise Refusal("generation-5 manifest member contract differs")
    return {
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "manifest_digest": claimed,
        "member_count": len(expected),
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
            raise Refusal("site review is not a one-file generation-5 manifest change")
        if not args.expected_manifest_sha256:
            raise Refusal("site review requires expected manifest SHA-256")
        if state["manifest"]["manifest_sha256"] != args.expected_manifest_sha256:
            raise Refusal("generation-5 manifest bytes do not match predeclared digest")
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
