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
CURRENT_MANIFEST = Path(__file__).parents[1] / "frozen_bundle_manifest.generation-5.json"


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
            "member_count": len(MODULE.expected_members()),
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
    assert report["member_count"] == len(MODULE.expected_members()) == 291
    assert report["member_contract"] == "EXACT"


def test_current_registered_population_291_manifest_is_the_real_positive():
    report = MODULE.manifest_contract(CURRENT_MANIFEST.read_bytes())
    assert report == {
        "manifest_sha256": "2f5d5c1f1a4da940675f0b7b2ab4b0a50b128b1a7ae0011a212e514e493089cf",
        "manifest_digest": "5844071f348ce00e6768009b88bc7a32cfc2868961c751be25fb38871e17e6aa",
        "member_count": 291,
        "member_contract": "EXACT",
    }


def test_registered_adapter_selects_structurally_derived_final_runtime_contract():
    path, population = MODULE._registered_adapter_path()
    adapter = MODULE._registered_adapter()
    selector = adapter["manifest_builder_flag"][2:].replace("-", "_") + "_members"
    current = MODULE.structural_members(selector)
    old = MODULE.structural_members("successor_members")
    assert path.name == (
        f"research_enforcement_activation.population-{population}-v1.json"
    )
    assert set(old) < set(current)
    assert len(current) == adapter["expected_member_count"] == population == 291
    assert "final-runtime-rollout" in current


def registered_fixture(tmp_path, monkeypatch):
    selected, _ = MODULE._registered_adapter_path()
    root = tmp_path / "write-enforcement"
    adapters = root / "adapters"
    adapters.mkdir(parents=True)
    paths = {
        "index": root / "signed_release_convergence_index.json",
        "adapter": adapters / selected.name,
        "contract": root / "member_contract.py",
    }
    index = json.loads(MODULE.CONVERGENCE_INDEX.read_bytes())
    adapter = json.loads(selected.read_bytes())
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    for row in index["adapters"]:
        if MODULE.REA_POPULATION_ADAPTER.fullmatch(row["adapter_id"]):
            source = MODULE.CONVERGENCE_INDEX.parent / row["path"]
            destination = root / row["path"]
            destination.write_bytes(source.read_bytes())
    paths["contract"].write_bytes(MODULE.MEMBER_CONTRACT.read_bytes())
    monkeypatch.setattr(MODULE, "CONVERGENCE_INDEX", paths["index"])
    monkeypatch.setattr(MODULE, "ADAPTER_DIRECTORY", adapters)
    monkeypatch.setattr(MODULE, "MEMBER_CONTRACT", paths["contract"])
    return index, adapter, paths


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(expected_member_count=290),
        lambda value: value.update(manifest_builder_flag="--successor"),
        lambda value: value.update(manifest_path="wrong.json"),
    ],
)
def test_registered_adapter_identity_is_load_bearing(tmp_path, monkeypatch, mutation):
    _index, adapter, paths = registered_fixture(tmp_path, monkeypatch)
    mutation(adapter)
    paths["adapter"].write_text(json.dumps(adapter), encoding="utf-8")
    with pytest.raises(MODULE.Refusal):
        MODULE.expected_members()


def test_unique_higher_registered_population_becomes_selected(tmp_path, monkeypatch):
    index, adapter, paths = registered_fixture(tmp_path, monkeypatch)
    population = adapter["expected_member_count"] + 1
    adapter_name = f"research_enforcement_activation.population-{population}-v1.json"
    index["adapters"].append(
        {
            "adapter_id": (
                "research-enforcement-activation-generation-5-population-"
                f"{population}-v1"
            ),
            "path": f"adapters/{adapter_name}",
            "status": "active",
        }
    )
    adapter.update(
        adapter_id=index["adapters"][-1]["adapter_id"],
        expected_member_count=population,
        manifest_builder_flag="--reviewer-successor",
    )
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    (paths["adapter"].parent / adapter_name).write_text(
        json.dumps(adapter), encoding="utf-8"
    )
    contract = paths["contract"].read_text()
    contract += """
REVIEWER_ADDITIONAL_MEMBERS = {
    "future-reviewer-fixture": ("rexcoleman.dev", "future/reviewer.py"),
}
def reviewer_successor_members():
    value = final_runtime_rollout_successor_members()
    value.update(REVIEWER_ADDITIONAL_MEMBERS)
    return value
"""
    paths["contract"].write_text(contract, encoding="utf-8")
    selected, selected_population = MODULE._registered_adapter_path()
    expected = MODULE.expected_members()
    assert selected.name == adapter_name
    assert selected_population == len(expected) == population
    assert expected["future-reviewer-fixture"] == (
        "rexcoleman.dev",
        "future/reviewer.py",
    )


def test_lower_only_registered_population_refuses_as_a_downgrade(
    tmp_path, monkeypatch
):
    index, _adapter, paths = registered_fixture(tmp_path, monkeypatch)
    index["adapters"] = [
        row
        for row in index["adapters"]
        if row["adapter_id"]
        != "research-enforcement-activation-generation-5-population-291-v1"
    ]
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(MODULE.Refusal, match="terminal successor"):
        MODULE._registered_adapter()


def test_retired_historical_population_does_not_block_active_terminal(
    tmp_path, monkeypatch
):
    index, _adapter, paths = registered_fixture(tmp_path, monkeypatch)
    historical = next(
        row
        for row in index["adapters"]
        if row["adapter_id"]
        == "research-enforcement-activation-generation-5-population-290-v1"
    )
    historical["status"] = "retired"
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    selected, population = MODULE._registered_adapter_path()
    assert population == 291
    assert selected.name == (
        "research_enforcement_activation.population-291-v1.json"
    )
    assert len(MODULE.expected_members()) == 291


def test_retired_terminal_with_only_lower_active_population_refuses(
    tmp_path, monkeypatch
):
    index, _adapter, paths = registered_fixture(tmp_path, monkeypatch)
    terminal = next(
        row
        for row in index["adapters"]
        if row["adapter_id"]
        == "research-enforcement-activation-generation-5-population-291-v1"
    )
    terminal["status"] = "retired"
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    selected, population = MODULE._registered_adapter_path()
    assert population == 290
    assert selected.name == (
        "research_enforcement_activation.population-290-v1.json"
    )
    with pytest.raises(MODULE.Refusal, match="terminal successor"):
        MODULE._registered_adapter()


@pytest.mark.parametrize("plant", ["missing", "duplicate", "schema", "path"])
def test_registered_population_index_refuses_missing_ambiguous_or_tampered_rows(
    tmp_path, monkeypatch, plant
):
    index, _adapter, paths = registered_fixture(tmp_path, monkeypatch)
    matching = [
        row
        for row in index["adapters"]
        if MODULE.REA_POPULATION_ADAPTER.fullmatch(row["adapter_id"])
    ]
    if plant == "missing":
        index["adapters"] = [
            row
            for row in index["adapters"]
            if not MODULE.REA_POPULATION_ADAPTER.fullmatch(row["adapter_id"])
        ]
    elif plant == "duplicate":
        duplicate = dict(matching[-1])
        duplicate["path"] = "adapters/ambiguous.json"
        index["adapters"].append(duplicate)
    elif plant == "schema":
        index["schema_version"] = "rea.signed-release-convergence-index.tampered"
    else:
        matching[-1]["path"] = "../escaping-population-291.json"
    paths["index"].write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(MODULE.Refusal):
        MODULE._registered_adapter_path()


def test_structural_member_derivation_does_not_execute_source(tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    planted = tmp_path / "member_contract.py"
    planted.write_text(
        MODULE.MEMBER_CONTRACT.read_text()
        + "\nopen(%r, 'w').write('executed')\n" % str(marker),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "MEMBER_CONTRACT", planted)
    assert len(MODULE.expected_members()) == 291
    assert not marker.exists()


def test_old_population_contract_is_refused_by_current_registered_route():
    value = next_contract_manifest()
    old = MODULE.structural_members("successor_members")
    value["members"] = [
        row for row in value["members"] if row["member_id"] in old
    ]
    assert {row["member_id"] for row in value["members"]} == set(old)
    with pytest.raises(MODULE.Refusal, match="generation-5 manifest contract differs"):
        MODULE.manifest_contract(reseal(value))


def test_mixed_old_current_population_with_same_count_is_refused():
    value = next_contract_manifest()
    final = next(
        index
        for index, row in enumerate(value["members"])
        if row["member_id"] == "final-runtime-rollout"
    )
    value["members"][final] = {
        "member_id": "legacy-mixed-member",
        "repository": "research_enforcement_activation",
        "commit": "a" * 40,
        "path": "scripts/s231_final_runtime_rollout.py",
        "sha256": "b" * 64,
        "byte_length": 1,
    }
    assert len(value["members"]) == len(MODULE.expected_members())
    with pytest.raises(MODULE.Refusal, match="member contract"):
        MODULE.manifest_contract(reseal(value))


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
    assert len(value["members"]) == len(MODULE.expected_members()) - 1
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
    assert len(value["members"]) == len(MODULE.expected_members()) + 1
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


def test_population_291_policy_keeps_manifest_sha_and_file_set_load_bearing():
    expected = args()
    for field, replacement in (
        ("expected_manifest_sha256", "d" * 64),
        ("expected_files_sha256", "e" * 64),
    ):
        planted = SimpleNamespace(**vars(expected))
        setattr(planted, field, replacement)
        with pytest.raises(MODULE.Refusal):
            MODULE.assert_policy(state(), planted)


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
