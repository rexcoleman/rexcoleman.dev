import json
import subprocess
import sys
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import build_frozen_manifest as builder  # noqa: E402
from member_contract import GENERATION_MANIFEST_NAME  # noqa: E402


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def fixture_repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "fixture"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "s88-fixture@example.invalid")
    git(root, "config", "user.name", "s88 fixture")
    (root / "member.txt").write_bytes(b"committed member\n")
    git(root, "add", "member.txt")
    git(root, "commit", "-q", "-m", "fixture")
    return root, git(root, "rev-parse", "HEAD")


def full_population_repositories(
    tmp_path: Path,
) -> tuple[dict[str, Path], dict[str, str]]:
    roots = {}
    commits = {}
    grouped = builder.group_member_contract(builder.EXPECTED_MEMBERS)
    for repository, members in grouped.items():
        root = tmp_path / repository
        root.mkdir()
        git(root, "init", "-q")
        git(root, "config", "user.email", "s132-fixture@example.invalid")
        git(root, "config", "user.name", "s132 totality fixture")
        for member_id, relative in members:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"{member_id}\n".encode())
        git(root, "add", ".")
        git(root, "commit", "-q", "-m", "complete frozen population")
        roots[repository] = root
        commits[repository] = git(root, "rev-parse", "HEAD")
    return roots, commits


def ruleset(path: Path) -> None:
    path.write_text(json.dumps({
        "id": 19564990,
        "name": "newsletter-main-integrity",
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": ["refs/heads/main"],
                "exclude": [],
            },
        },
        "rules": [],
        "bypass_actors": [],
    }), encoding="utf-8")


def test_builder_reads_clean_committed_head_bytes(tmp_path):
    root, commit = fixture_repository(tmp_path)
    assert builder.committed_member_bytes(root, commit, "member.txt") == (
        b"committed member\n"
    )


def test_full_frozen_population_opens_at_selected_authoritative_commits(tmp_path):
    roots, commits = full_population_repositories(tmp_path)
    loaded = builder.open_frozen_population(roots, commits)
    assert set(loaded) == set(builder.EXPECTED_MEMBERS)
    assert len(loaded) == len(builder.EXPECTED_MEMBERS) == 232
    for member_id, raw in loaded.items():
        assert raw == f"{member_id}\n".encode()


def test_full_population_refuses_wrong_member_mapping(tmp_path):
    roots, commits = full_population_repositories(tmp_path)
    contract = dict(builder.EXPECTED_MEMBERS)
    contract["newsletter-upgrade-workflow"] = (
        "newsletter", ".github/workflows/not-the-upgrade-authority.yml"
    )
    with pytest.raises(
        ValueError,
        match="frozen population member unavailable:newsletter-upgrade-workflow",
    ):
        builder.open_frozen_population(roots, commits, contract)


def test_full_population_refuses_absent_repository_mapping(tmp_path):
    roots, commits = full_population_repositories(tmp_path)
    roots.pop("newsletter")
    with pytest.raises(
        ValueError,
        match="frozen population repository mapping invalid:roots_missing=\\['newsletter'\\]",
    ):
        builder.open_frozen_population(roots, commits)


def test_builder_refuses_post_commit_bound_member_mutation(tmp_path):
    root, commit = fixture_repository(tmp_path)
    (root / "member.txt").write_bytes(b"post-commit mutation\n")
    with pytest.raises(ValueError, match="dirty bound member"):
        builder.committed_member_bytes(root, commit, "member.txt")


@pytest.mark.parametrize(
    "member_id",
    [
        "row-complete-full-receipts",
        "row-complete-ledger",
        "row-complete-ancestry-attestation",
    ],
)
def test_row_complete_member_working_tree_mutation_refuses(
        tmp_path, member_id):
    roots, commits = full_population_repositories(tmp_path)
    repository, relative = builder.EXPECTED_MEMBERS[member_id]
    (roots[repository] / relative).write_bytes(b"planted row-complete mutation\n")
    with pytest.raises(ValueError, match="dirty bound member"):
        builder.open_frozen_population(roots, commits)


def test_manifest_build_is_byte_identical_across_three_runs(
        monkeypatch, tmp_path):
    root, commit = fixture_repository(tmp_path)
    ruleset_path = tmp_path / "ruleset.json"
    ruleset(ruleset_path)
    monkeypatch.setattr(
        builder,
        "MEMBERS",
        {"fixture": (("fixture-member", "member.txt"),)},
    )
    outputs = []
    for attempt in range(3):
        output = tmp_path / f"run-{attempt}" / GENERATION_MANIFEST_NAME
        output.parent.mkdir()
        monkeypatch.setattr(sys, "argv", [
            "build_frozen_manifest.py",
            "--output", str(output),
            "--ruleset-json", str(ruleset_path),
            "--root-fixture", str(root),
        ])
        assert builder.main() == 0
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1] == outputs[2]
    manifest = json.loads(outputs[0])
    assert manifest["members"] == [{
        "member_id": "fixture-member",
        "repository": "fixture",
        "commit": commit,
        "path": "member.txt",
        "sha256": builder.sha(b"committed member\n"),
        "byte_length": len(b"committed member\n"),
    }]


def test_builder_refuses_wrong_generation_3_output_name(
        monkeypatch, tmp_path):
    root, _commit = fixture_repository(tmp_path)
    ruleset_path = tmp_path / "ruleset.json"
    ruleset(ruleset_path)
    monkeypatch.setattr(
        builder,
        "MEMBERS",
        {"fixture": (("fixture-member", "member.txt"),)},
    )
    monkeypatch.setattr(sys, "argv", [
        "build_frozen_manifest.py",
        "--output", str(tmp_path / "manifest.json"),
        "--ruleset-json", str(ruleset_path),
        "--root-fixture", str(root),
    ])
    with pytest.raises(ValueError, match="manifest path must end"):
        builder.main()


@pytest.mark.parametrize("logical,slug", [
    ("research_enforcement_activation", "research_enforcement_activation"),
    ("govML", "govML"),
    ("Moonshots_Career_Thesis_v2", "Moonshots_Career_Thesis"),
    ("newsletter", "newsletter"),
    ("rexcoleman.dev", "rexcoleman.dev"),
])
def test_closed_logical_repository_to_authoritative_slug_mapping(logical, slug):
    assert builder.authoritative_repository_slug(logical) == slug


def test_moonshots_reachability_uses_real_authoritative_slug(monkeypatch):
    commit = "a" * 40
    observed = {}

    def run(argv, **kwargs):
        observed["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, commit + "\n", "")

    monkeypatch.setattr(builder.subprocess, "run", run)
    builder.verify_remote_reachability("Moonshots_Career_Thesis_v2", commit)
    assert observed["argv"] == [
        "gh", "api",
        f"repos/rexcoleman/Moonshots_Career_Thesis/commits/{commit}",
        "--jq", ".sha",
    ]


@pytest.mark.parametrize("returncode,stdout", [
    (4, ""),
    (0, ""),
    (0, "b" * 40 + "\n"),
])
def test_reachability_refuses_nonzero_empty_or_mismatched_response(
    monkeypatch, returncode, stdout,
):
    monkeypatch.setattr(
        builder.subprocess, "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, returncode, stdout, "measured stderr"
        ),
    )
    with pytest.raises(ValueError, match="authoritative remote member unreachable"):
        builder.verify_remote_reachability("govML", "a" * 40)


def test_reachability_accepts_only_exact_observed_commit(monkeypatch):
    commit = "c" * 40
    monkeypatch.setattr(
        builder.subprocess, "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, commit + "\n", ""
        ),
    )
    assert builder.verify_remote_reachability("newsletter", commit) is None


def test_repository_mapping_refuses_unknown_missing_and_duplicates(monkeypatch):
    with pytest.raises(ValueError, match="unknown logical repository"):
        builder.authoritative_repository_slug("unknown")

    original = builder.AUTHORITATIVE_REPOSITORY_SLUGS
    monkeypatch.setattr(builder, "AUTHORITATIVE_REPOSITORY_SLUGS", original[:-1])
    with pytest.raises(ValueError, match="mapping invalid.*missing"):
        builder.authoritative_repository_slug("govML")

    monkeypatch.setattr(
        builder, "AUTHORITATIVE_REPOSITORY_SLUGS",
        original[:-1] + (("rexcoleman.dev", "newsletter"),),
    )
    with pytest.raises(ValueError, match="mapping invalid.*duplicate_slugs"):
        builder.authoritative_repository_slug("govML")

    monkeypatch.setattr(
        builder, "AUTHORITATIVE_REPOSITORY_SLUGS",
        original + (("govML", "other-govml"),),
    )
    with pytest.raises(ValueError, match="mapping invalid.*duplicate_logical"):
        builder.authoritative_repository_slug("govML")
