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


def test_builder_refuses_post_commit_bound_member_mutation(tmp_path):
    root, commit = fixture_repository(tmp_path)
    (root / "member.txt").write_bytes(b"post-commit mutation\n")
    with pytest.raises(ValueError, match="dirty bound member"):
        builder.committed_member_bytes(root, commit, "member.txt")


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
