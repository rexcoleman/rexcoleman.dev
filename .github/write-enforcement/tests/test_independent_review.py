import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = Path(__file__).parents[1] / "independent_review.py"
SPEC = importlib.util.spec_from_file_location("review_pull_request", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)
CURRENT_MANIFEST = Path(__file__).parents[1] / "frozen_bundle_manifest.generation-5.json"
HEAD_SHA = "b" * 40
BASE_SHA = "e" * 40


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def boundary_receipt(**updates):
    value = {
        "assertion": "COMMIT_PREFLIGHT_PASS",
        "caller": "git-pre-commit",
        "changed_paths": [MODULE.SITE_MANIFEST],
        "changed_paths_count": 1,
        "changed_paths_sha256": MODULE.stable_paths_digest([MODULE.SITE_MANIFEST]),
        "mode": "commit-preflight",
        "parent_head": BASE_SHA,
        "run_id": "pre-commit-" + "1" * 24,
        "schema_version": MODULE.PRE_COMMIT_RECEIPT_SCHEMA,
        "utc_asserted_at": "2026-09-13T12:00:00Z",
    }
    value.update(updates)
    return value


def boundary_receipt_bytes(**updates):
    return (
        json.dumps(boundary_receipt(**updates), indent=2, sort_keys=True) + "\n"
    ).encode()


def site_files():
    receipt_raw = boundary_receipt_bytes()
    return [
        {
            "filename": MODULE.SITE_MANIFEST,
            "status": "modified",
            "sha": "a" * 40,
            "additions": 1,
            "deletions": 1,
        },
        {
            "filename": MODULE.PRE_COMMIT_RECEIPT,
            "status": "modified",
            "sha": MODULE.git_blob_sha(receipt_raw),
            "additions": 1,
            "deletions": 1,
        },
    ]


def args(repo="rexcoleman/rexcoleman.dev", mode="preflight"):
    files = site_files()
    return SimpleNamespace(
        repository=repo,
        pull_request=2,
        expected_head=HEAD_SHA,
        expected_files_sha256=digest(files),
        expected_manifest_sha256="c" * 64 if repo.endswith(".dev") else "",
        mode=mode,
    )


def state(repo="rexcoleman/rexcoleman.dev"):
    value = args(repo)
    files = site_files()
    return {
        "installation_repositories": sorted(MODULE.ALLOWED_REPOSITORIES),
        "pull_request": {
            "state": "open",
            "draft": False,
            "author": "rexcoleman",
            "base": MODULE.ALLOWED_REPOSITORIES[repo],
            "base_sha": BASE_SHA,
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
        "receipt": MODULE.receipt_contract(
            boundary_receipt_bytes(), HEAD_SHA, BASE_SHA
        ),
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


def test_live_shaped_two_file_state_fetches_receipt_at_exact_head(
    monkeypatch,
):
    expected = args()
    manifest_raw = CURRENT_MANIFEST.read_bytes()
    receipt_raw = boundary_receipt_bytes()
    files = site_files()
    fetched = []

    def fake_api(_token, path, *_args, **_kwargs):
        if path.endswith("/pulls/2"):
            return {
                "state": "open",
                "draft": False,
                "user": {"login": "rexcoleman"},
                "base": {"ref": "main", "sha": BASE_SHA},
                "head": {"ref": "candidate", "sha": HEAD_SHA},
            }
        if path.endswith("/pulls/2/reviews?per_page=100"):
            return []
        raise AssertionError(path)

    def fake_content(_token, repo, path, ref):
        assert repo == "rexcoleman/rexcoleman.dev"
        assert ref == HEAD_SHA
        fetched.append((path, ref))
        return manifest_raw if path == MODULE.SITE_MANIFEST else receipt_raw

    monkeypatch.setattr(MODULE, "api", fake_api)
    monkeypatch.setattr(MODULE, "pull_files", lambda *_args: files)
    monkeypatch.setattr(
        MODULE,
        "installation_repositories",
        lambda _token: sorted(MODULE.ALLOWED_REPOSITORIES),
    )
    monkeypatch.setattr(MODULE, "ruleset_state", lambda *_args: state()["ruleset"])
    monkeypatch.setattr(MODULE, "content_bytes", fake_content)
    observed = MODULE.read_state("fixture-token", expected)
    expected.expected_manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    expected.expected_files_sha256 = digest(files)
    MODULE.assert_policy(observed, expected)
    assert fetched == [
        (MODULE.SITE_MANIFEST, HEAD_SHA),
        (MODULE.PRE_COMMIT_RECEIPT, HEAD_SHA),
    ]
    assert observed["receipt"]["receipt_sha256"] == hashlib.sha256(
        receipt_raw
    ).hexdigest()


def test_system_python_38_imports_reviewer_and_computes_git_blob_identity():
    program = "\n".join(
        [
            "import importlib.util",
            f"path = {str(MODULE_PATH)!r}",
            "spec = importlib.util.spec_from_file_location('review', path)",
            "module = importlib.util.module_from_spec(spec)",
            "spec.loader.exec_module(module)",
            "print(module.git_blob_sha(b'fixture'))",
        ]
    )
    completed = subprocess.run(
        ["/usr/bin/python3", "-I", "-B", "-c", program],
        check=True,
        text=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent/independent-review-py38",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
        },
    )
    assert completed.stderr == ""
    assert completed.stdout == "001f1993905d81b471eeaa840432cf35aedaea61\n"


@pytest.mark.parametrize(
    "files",
    [
        site_files()[:1],
        site_files()[1:],
        site_files() + [{
            "filename": "planted-extra",
            "status": "added",
            "sha": "f" * 40,
            "additions": 1,
            "deletions": 0,
        }],
        site_files() + [dict(site_files()[1])],
        list(reversed(site_files())),
        [site_files()[0], dict(site_files()[1], status="added")],
    ],
)
def test_site_policy_refuses_nonexact_two_file_shapes_after_digest_binding(files):
    observed = state()
    observed["files"] = files
    observed["files_sha256"] = digest(files)
    expected = args()
    expected.expected_files_sha256 = digest(files)
    with pytest.raises(MODULE.Refusal, match="exact manifest and boundary-receipt"):
        MODULE.assert_policy(observed, expected)


def test_receipt_contract_accepts_exact_normal_hook_bytes():
    raw = boundary_receipt_bytes()
    observed = MODULE.receipt_contract(raw, HEAD_SHA, BASE_SHA)
    assert observed["content_ref"] == HEAD_SHA
    assert observed["parent_head"] == BASE_SHA
    assert observed["changed_paths"] == [MODULE.SITE_MANIFEST]
    assert observed["changed_paths_count"] == 1
    assert observed["changed_paths_sha256"] == MODULE.stable_paths_digest(
        [MODULE.SITE_MANIFEST]
    )
    assert observed["receipt_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("caller"),
        lambda value: value.update(extra="planted"),
        lambda value: value.update(assertion="REFUSED"),
        lambda value: value.update(caller="planted"),
        lambda value: value.update(mode="planted"),
        lambda value: value.update(parent_head="f" * 40),
        lambda value: value.update(changed_paths=[]),
        lambda value: value.update(changed_paths=[MODULE.PRE_COMMIT_RECEIPT]),
        lambda value: value.update(changed_paths_count=0),
        lambda value: value.update(changed_paths_count=True),
        lambda value: value.update(changed_paths_sha256="0" * 64),
        lambda value: value.update(run_id="pre-commit-wrong"),
        lambda value: value.update(utc_asserted_at="2026-02-30T12:00:00Z"),
    ],
)
def test_receipt_contract_refuses_strict_subsets_and_nonpass_fields(mutation):
    value = boundary_receipt()
    mutation(value)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with pytest.raises(MODULE.Refusal):
        MODULE.receipt_contract(raw, HEAD_SHA, BASE_SHA)


def test_receipt_contract_refuses_altered_or_ambiguous_bytes():
    raw = boundary_receipt_bytes()
    with pytest.raises(MODULE.Refusal, match="not canonical"):
        MODULE.receipt_contract(raw.replace(b"{\n", b"{ \n", 1), HEAD_SHA, BASE_SHA)
    duplicate = raw.replace(
        b'{\n  "assertion":', b'{\n  "assertion": "COMMIT_PREFLIGHT_PASS",\n  "assertion":', 1,
    )
    with pytest.raises(MODULE.Refusal, match="duplicate key"):
        MODULE.receipt_contract(duplicate, HEAD_SHA, BASE_SHA)


def test_receipt_state_binds_expected_head_and_pr_base():
    expected = args()
    for mutation in (
        lambda value: value["receipt"].update(content_ref="f" * 40),
        lambda value: value["receipt"].update(parent_head="f" * 40),
        lambda value: value["pull_request"].update(base_sha="f" * 40),
    ):
        observed = state()
        mutation(observed)
        with pytest.raises(MODULE.Refusal):
            MODULE.assert_policy(observed, expected)


def test_read_state_refuses_receipt_blob_different_from_pr_file_row(monkeypatch):
    expected = args()
    manifest_raw = CURRENT_MANIFEST.read_bytes()
    receipt_raw = boundary_receipt_bytes()
    files = site_files()
    files[1]["sha"] = "0" * 40

    def fake_api(_token, path, *_args, **_kwargs):
        if path.endswith("/pulls/2"):
            return {
                "state": "open", "draft": False,
                "user": {"login": "rexcoleman"},
                "base": {"ref": "main", "sha": BASE_SHA},
                "head": {"ref": "candidate", "sha": HEAD_SHA},
            }
        if path.endswith("/pulls/2/reviews?per_page=100"):
            return []
        raise AssertionError(path)

    monkeypatch.setattr(MODULE, "api", fake_api)
    monkeypatch.setattr(MODULE, "pull_files", lambda *_args: files)
    monkeypatch.setattr(MODULE, "installation_repositories", lambda _token: [])
    monkeypatch.setattr(MODULE, "ruleset_state", lambda *_args: {})
    monkeypatch.setattr(
        MODULE,
        "content_bytes",
        lambda _token, _repo, path, _ref: (
            manifest_raw if path == MODULE.SITE_MANIFEST else receipt_raw
        ),
    )
    with pytest.raises(MODULE.Refusal, match="Git blob identity"):
        MODULE.read_state("fixture-token", expected)


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
    assert "Exact manifest plus normal-hook receipt file-set SHA-256" in text
    for argument in (
        "--mode",
        "--repository",
        "--pull-request",
        "--expected-head",
        "--expected-files-sha256",
        "--expected-manifest-sha256",
    ):
        assert text.count(argument) == 1
    assert text.count(".github/write-enforcement/independent_review.py") == 1
    convergence = (
        Path(__file__).parents[2] / "workflows/signed-release-convergence.yml"
    ).read_text()
    assert convergence.count(
        ".github/write-enforcement/tests/test_independent_review.py"
    ) == 1
