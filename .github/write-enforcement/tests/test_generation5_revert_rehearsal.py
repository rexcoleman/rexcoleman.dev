import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "rehearse_generation5_ruleset_revert.py"
SPEC = importlib.util.spec_from_file_location("revert_rehearsal", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(tool)


def synthetic_manifest():
    repositories = sorted(tool.EXPECTED_REPOSITORIES)
    rows = [
        {"repository": repositories[index % len(repositories)],
         "commit": "a" * 40, "path": f"p{index}"}
        for index in range(tool.EXPECTED_MEMBER_COUNT)
    ]
    return {"members": rows, "normalized_ruleset_sha256": "b" * 64,
            "manifest_digest": "c" * 64}


def test_compare_accepts_only_two_changed_fields_and_identical_members():
    baseline = synthetic_manifest()
    built = json.loads(json.dumps(baseline))
    built["normalized_ruleset_sha256"] = "d" * 64
    built["manifest_digest"] = "e" * 64
    result = tool.compare_manifests(baseline, built, json.loads(json.dumps(built)))
    assert result["changed_fields"] == ["manifest_digest", "normalized_ruleset_sha256"]
    assert result["member_count"] == 259
    assert result["members_byte_identical"] is True
    assert result["two_builds_byte_deterministic"] is True


def test_compare_refuses_member_drift():
    baseline = synthetic_manifest()
    built = json.loads(json.dumps(baseline))
    built["normalized_ruleset_sha256"] = "d" * 64
    built["manifest_digest"] = "e" * 64
    built["members"][0]["path"] = "changed"
    with pytest.raises(tool.Refusal, match="BUILT_MEMBER_ROWS_DIVERGED"):
        tool.compare_manifests(baseline, built, built)


def test_post_revert_ruleset_requires_empty_bypass():
    good = {"id": 19564990, "enforcement": "active", "bypass_actors": []}
    tool.validate_post_revert_ruleset(good)
    bad = dict(good)
    bad["bypass_actors"] = [{"actor_id": 5}]
    with pytest.raises(tool.Refusal, match="RULESET_BYPASS_NOT_REVERTED"):
        tool.validate_post_revert_ruleset(bad)


def test_manifest_commit_population_is_closed():
    manifest = synthetic_manifest()
    commits = tool.manifest_commits(manifest)
    assert set(commits) == set(tool.EXPECTED_REPOSITORIES)
    manifest["members"][0]["repository"] = "unknown"
    with pytest.raises(tool.Refusal, match="MANIFEST_REPOSITORY_REFUSED"):
        tool.manifest_commits(manifest)
