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


FROZEN_MANIFEST = (
    Path(__file__).parents[1] / "frozen_bundle_manifest.generation-4.json"
)


def reseal(value):
    """Recompute manifest_digest so the self-digest check cannot be the refusal.

    Without this, a mutated manifest is refused at the "self-digest differs"
    check and the member-count contract is never reached -- the test would pass
    while guarding nothing.
    """
    unsigned = {key: item for key, item in value.items() if key != "manifest_digest"}
    sealed = dict(unsigned)
    sealed["manifest_digest"] = MODULE.canonical_digest(unsigned)
    return json.dumps(sealed, sort_keys=True, separators=(",", ":")).encode()


def next_contract_manifest():
    value = {
        "schema_version": "rea.write.enforcement-bundle-manifest.v1",
        "authority_generation": MODULE.AUTHORITY_GENERATION,
        "ruleset_id": 19564990,
        "normalized_ruleset_sha256": "c" * 64,
        "required_member_classes": sorted(MODULE.REQUIRED_MEMBER_CLASSES),
        "members": [
            {"member_id": member_id, "repository": repository, "commit": "a" * 40,
             "path": path, "sha256": "b" * 64, "byte_length": 1}
            for member_id, (repository, path) in MODULE.expected_members().items()
        ],
    }
    return json.loads(reseal(value))


def test_current_freeze_remains_exact_after_logical_policy_key_repair():
    """Logical policy keys do not mutate immutable member subjects.

    The boundary-engine subject migration was already present in this freeze.
    This repair changes only the logical digest key in member_contract, while
    EXPECTED_MEMBERS continues to bind the same govML repository/path subject.
    The successor freeze must repin the changed member-contract bytes, but the
    current manifest's member identity contract remains exact.
    """
    value=json.loads(FROZEN_MANIFEST.read_bytes())
    assert value["authority_generation"] == 4
    assert len(value["members"]) == 244
    assert "ci-enforcement-materializer" not in {
        row["member_id"] for row in value["members"]
    }


def test_next_contract_manifest_is_an_exact_positive_control():
    report=MODULE.manifest_contract(reseal(next_contract_manifest()))
    assert report["member_count"] == MODULE.GENERATION_MEMBER_COUNT
    assert report["member_contract"] == "EXACT"


def test_preconvergence_frozen_manifest_is_refused_after_contract_expansion():
    """A manifest built before an expansion carries one member fewer.

    Expressed as a derivation from the current freeze rather than as a stored
    file, because the freeze process overwrites any stored generation-4
    manifest: an assertion against those bytes goes vacuous the moment the
    contract and the freeze converge, which is exactly how this test died.
    """
    value = next_contract_manifest()
    dropped = value["members"].pop()
    assert dropped["member_id"] in MODULE.expected_members()
    assert len(value["members"]) == MODULE.GENERATION_MEMBER_COUNT - 1
    raw = reseal(value)
    parsed = json.loads(raw)
    assert parsed["manifest_digest"] == MODULE.canonical_digest(
        {key: item for key, item in parsed.items() if key != "manifest_digest"}
    )
    with pytest.raises(
        MODULE.Refusal, match=r"^generation-5 manifest contract differs$"
    ):
        MODULE.manifest_contract(raw)


def test_manifest_carrying_a_member_beyond_the_contract_is_refused():
    """The other side of the count contract: an unregistered extra member."""
    value = next_contract_manifest()
    extra = dict(value["members"][0])
    extra["member_id"] = "unregistered-extra-member"
    value["members"].append(extra)
    assert len(value["members"]) == MODULE.GENERATION_MEMBER_COUNT + 1
    with pytest.raises(
        MODULE.Refusal, match=r"^generation-5 manifest contract differs$"
    ):
        MODULE.manifest_contract(reseal(value))


def test_manifest_contract_refuses_self_consistent_wrong_member():
    value = {
        "schema_version": "rea.write.enforcement-bundle-manifest.v1",
        "authority_generation": MODULE.AUTHORITY_GENERATION,
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
