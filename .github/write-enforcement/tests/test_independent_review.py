import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = Path(__file__).parents[1] / "independent_review.py"
SPEC = importlib.util.spec_from_file_location("review_pull_request", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def args(repo="rexcoleman/rexcoleman.dev", mode="preflight"):
    files = [
        {
            "filename": MODULE.SITE_MANIFEST,
            "status": "modified",
            "sha": "a" * 40,
            "additions": 1,
            "deletions": 1,
        }
    ]
    return SimpleNamespace(
        repository=repo,
        pull_request=2,
        expected_head="b" * 40,
        expected_files_sha256=digest(files),
        expected_manifest_sha256="c" * 64 if repo.endswith(".dev") else "",
        mode=mode,
    )


def state(repo="rexcoleman/rexcoleman.dev"):
    value = args(repo)
    files = [
        {
            "filename": MODULE.SITE_MANIFEST,
            "status": "modified",
            "sha": "a" * 40,
            "additions": 1,
            "deletions": 1,
        }
    ]
    return {
        "installation_repositories": sorted(MODULE.ALLOWED_REPOSITORIES),
        "pull_request": {
            "state": "open",
            "draft": False,
            "author": "rexcoleman",
            "base": MODULE.ALLOWED_REPOSITORIES[repo],
            "head_ref": "candidate",
            "head_sha": value.expected_head,
        },
        "files": files,
        "files_sha256": digest(files),
        "manifest": {
            "manifest_sha256": value.expected_manifest_sha256,
            "manifest_digest": "d" * 64,
            "member_count": MODULE.GENERATION_MEMBER_COUNT,
            "member_contract": "EXACT",
        },
        "ruleset": {
            "status": "ACTIVE",
            "id": 19768000,
            "name": "rexcoleman-dev-main-integrity",
            "bypass_actors": [],
            "required_approving_review_count": 0,
            "dismiss_stale_reviews_on_push": True,
            "required_review_thread_resolution": True,
            "target": "refs/heads/main",
            "rule_types": ["deletion", "non_fast_forward", "pull_request"],
        },
        "reviews": [],
    }


def test_site_policy_accepts_exact_predeclared_state():
    MODULE.assert_policy(state(), args())


@pytest.mark.parametrize(
    "mutation,expected",
    [
        (lambda value: value["installation_repositories"].pop(), "installation scope"),
        (lambda value: value["pull_request"].update(head_sha="d" * 40), "head moved"),
        (lambda value: value.update(files_sha256="d" * 64), "file-set digest"),
        (
            lambda value: value["manifest"].update(manifest_sha256="d" * 64),
            "manifest bytes",
        ),
        (
            lambda value: value["ruleset"].update(required_approving_review_count=1),
            "zero approvals",
        ),
        (
            lambda value: value["ruleset"].update(target="refs/heads/wrong"),
            "wrong branch",
        ),
        (
            lambda value: value["ruleset"].update(
                rule_types=["pull_request"]
            ),
            "rule population",
        ),
        (
            lambda value: value["ruleset"].update(
                required_review_thread_resolution=False
            ),
            "conversation resolution",
        ),
    ],
)
def test_site_policy_refuses_cheapest_strict_subsets(mutation, expected):
    value = state()
    mutation(value)
    with pytest.raises(MODULE.Refusal):
        MODULE.assert_policy(value, args())


def test_rea_preflight_allows_ruleset_not_yet_installed():
    value = state("rexcoleman/research_enforcement_activation")
    value["ruleset"] = {"status": "NOT_YET_INSTALLED"}
    MODULE.assert_policy(
        value,
        args("rexcoleman/research_enforcement_activation", mode="preflight"),
    )


def test_preconvergence_frozen_manifest_is_refused_after_contract_expansion():
    raw = (
        Path(__file__).parents[1]
        / "frozen_bundle_manifest.generation-4.json"
    ).read_bytes()
    assert len(json.loads(raw)["members"]) < MODULE.GENERATION_MEMBER_COUNT
    with pytest.raises(MODULE.Refusal, match="manifest contract differs"):
        MODULE.manifest_contract(raw)


def test_manifest_contract_refuses_self_consistent_wrong_member():
    value = {
        "schema_version": "rea.write.enforcement-bundle-manifest.v1",
        "authority_generation": 4,
        "ruleset_id": 19564990,
        "normalized_ruleset_sha256": "c" * 64,
        "required_member_classes": sorted(MODULE.REQUIRED_MEMBER_CLASSES),
        "members": [
            {
                "member_id": member_id, "repository": repository,
                "commit": "a" * 40, "path": path,
                "sha256": "b" * 64, "byte_length": 1,
            }
            for member_id, (repository, path) in MODULE.expected_members().items()
        ],
    }
    value["members"][0]["path"] = "wrong/path.py"
    value["manifest_digest"] = MODULE.canonical_digest(value)
    with pytest.raises(MODULE.Refusal, match="member contract"):
        MODULE.manifest_contract(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )


def test_preflight_mode_has_no_mutating_api_path(monkeypatch, capsys):
    value = state()
    monkeypatch.setenv("GH_TOKEN", "test-token-not-a-credential")
    monkeypatch.setattr(MODULE, "read_state", lambda _token, _args: value)

    def refuse_api(*_args, **_kwargs):
        raise AssertionError("preflight attempted an API mutation")

    monkeypatch.setattr(MODULE, "api", refuse_api)
    assert MODULE.run(args()) == 0
    assert capsys.readouterr().out.startswith("OPTION_A_POSTHOC_PREFLIGHT_PASS ")


def test_parser_exposes_no_approval_mode():
    with pytest.raises(SystemExit):
        MODULE.parser().parse_args(
            [
                "--mode",
                "approve",
                "--repository",
                "rexcoleman/rexcoleman.dev",
                "--pull-request",
                "2",
                "--expected-head",
                "b" * 40,
                "--expected-files-sha256",
                "c" * 64,
            ]
        )


def test_workflow_exposes_credential_only_after_environment_review():
    text = (
        Path(__file__).parents[2]
        / "workflows/independent-second-principal-review.yml"
    ).read_text()
    assert "\n  workflow_dispatch:\n" in text
    assert "\n  pull_request:" not in text
    assert "\n  pull_request_target:" not in text
    assert "environment: rea-write-enforcement-issuer" in text
    assert text.count("secrets.REA_SECOND_PRINCIPAL_PRIVATE_KEY") == 1
    assert "persist-credentials: false" in text
    assert "permissions:\n  contents: read" in text
