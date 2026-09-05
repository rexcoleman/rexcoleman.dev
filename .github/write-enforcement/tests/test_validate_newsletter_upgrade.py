import importlib.util
import hashlib
import json
import subprocess
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parents[1]
REPO_ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location(
    "newsletter_upgrade_validator", HERE / "validate_newsletter_upgrade.py"
)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)


LEGACY_WORKFLOW = """name: newsletter-integrity

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  newsletter-remote-integrity:
    name: newsletter-remote-integrity
    uses: rexcoleman/Moonshots_Career_Thesis/.github/workflows/newsletter-integrity-authority.yml@44e61952b101aacb222091f04c4cf728b5ec3f04
    permissions:
      contents: read
    with:
      candidate_repository: ${{ github.event.pull_request.head.repo.full_name }}
      event_sha: ${{ github.event.pull_request.head.sha }}
      base_sha: ${{ github.event.pull_request.base.sha }}
      control_sha: ef258446edbcebf988f5136e0b809482f476c8c7
      wea_issuance_run_id: ${{ vars.REA_WEA_RUN_ID }}
    secrets:
      REA_WEA_READ_TOKEN: ${{ secrets.REA_WEA_READ_TOKEN }}
      REA_BUNDLE_READ_TOKEN: ${{ secrets.REA_BUNDLE_READ_TOKEN }}
"""

TARGET_WORKFLOW = LEGACY_WORKFLOW.replace(
    "44e61952b101aacb222091f04c4cf728b5ec3f04",
    validator.TARGET_AUTHORITY_PIN,
)

# Literal pins, deliberately NOT derived from validator.TARGET_AUTHORITY_PIN, so
# that reverting the constant makes the accept case below fail.
GENERATION_5_AUTHORITY_PIN = "e86a3c4ebeec7a1f5cf4cc3c3e849a978a096a54"
GENERATION_4_AUTHORITY_PIN = "71c7835246171126ab657fba28fad649172c345d"


def legacy_pinned_to(commit: str) -> str:
    return LEGACY_WORKFLOW.replace(
        "44e61952b101aacb222091f04c4cf728b5ec3f04", commit
    )


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def authority_commit() -> str:
    return git(REPO_ROOT, "rev-parse", "HEAD")


def write(root: Path, relative: str, raw: str | bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(raw, bytes):
        path.write_bytes(raw)
    else:
        path.write_text(raw, encoding="utf-8")


def candidate(tmp_path: Path) -> tuple[Path, str, str, str]:
    root = tmp_path / "newsletter"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "s132-fixture@example.invalid")
    git(root, "config", "user.name", "s132 validator fixture")
    write(root, str(validator.LEGACY_WORKFLOW), LEGACY_WORKFLOW)
    write(root, "newsletter.md", "published content\n")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    base = git(root, "rev-parse", "HEAD")
    authority = authority_commit()
    write(
        root, str(validator.UPGRADE_WORKFLOW),
        validator.expected_upgrade_workflow(authority),
    )
    write(root, str(validator.CAPABILITY), validator.expected_capability(authority))
    write(root, str(validator.LEGACY_WORKFLOW), TARGET_WORKFLOW)
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "bootstrap upgrade control")
    return root, base, git(root, "rev-parse", "HEAD"), authority


def validate(root: Path, base: str, head: str):
    return validator.validate(
        root, "rexcoleman/newsletter", base, head, REPO_ROOT
    )


def recommit(root: Path, message: str = "adversarial mutation") -> str:
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


def test_exact_two_path_bootstrap_passes_without_candidate_execution(tmp_path):
    root, base, head, authority = candidate(tmp_path)
    result = validate(root, base, head)
    assert result["verdict"] == "PASS"
    assert result["raw_exit"] == 0
    assert result["authority_commit"] == authority
    assert result["changed"] == sorted(validator.ALLOWED_CONTROL_PATHS)
    assert result["registered_transition"] is None
    assert result["candidate_code_executed"] is False
    assert result["mutation_authorized"] is False


@pytest.mark.parametrize("relative,raw,reason", [
    ("newsletter.md", "changed content\n", "CONTROL_CHANGE_SET"),
    (".github/workflows/backdoor.yml", "permissions: write-all\n", "CONTROL_CHANGE_SET"),
    (str(validator.UPGRADE_WORKFLOW), "name: attacker\n", "UPGRADE_WORKFLOW_BYTES_NOT_APPROVED"),
    (str(validator.CAPABILITY), b"{}\n", "BOOTSTRAP_CAPABILITY_BYTES_NOT_APPROVED"),
])
def test_content_extra_workflow_and_bound_control_tampering_refuse(
    tmp_path, relative, raw, reason,
):
    root, base, _head, _authority = candidate(tmp_path)
    write(root, relative, raw)
    head = recommit(root)
    with pytest.raises(validator.Refusal, match=reason):
        validate(root, base, head)


@pytest.mark.parametrize("needle,replacement,reason", [
    ("pull_request_target:", "pull_request:", "LEGACY_EVENT_NOT_PULL_REQUEST_TARGET_ONLY"),
    ("contents: read", "contents: write", "WORKFLOW_WRITE_PERMISSION"),
    (f"@{validator.TARGET_AUTHORITY_PIN}", "@main", "LEGACY_REUSABLE_WORKFLOW_PIN"),
    ("    uses: rexcoleman/", "    steps:\n      - run: true\n    uses: rexcoleman/", "LEGACY_CANDIDATE_EXECUTION"),
])
def test_legacy_control_semantic_attacks_refuse(
    tmp_path, needle, replacement, reason,
):
    raw = TARGET_WORKFLOW.replace(needle, replacement, 1)
    with pytest.raises(validator.Refusal, match=reason):
        validator.validate_legacy_workflow(raw)


def test_superseded_generation_three_authority_pin_refuses():
    with pytest.raises(validator.Refusal, match="LEGACY_REUSABLE_WORKFLOW_PIN"):
        validator.validate_legacy_workflow(LEGACY_WORKFLOW)


def test_superseded_ten_artifact_control_pin_refuses():
    obsolete = TARGET_WORKFLOW.replace(
        validator.TARGET_AUTHORITY_PIN,
        "179b7d30a5904fbc2cde9e3bee0bfe3771114feb",
    )
    with pytest.raises(validator.Refusal, match="LEGACY_REUSABLE_WORKFLOW_PIN"):
        validator.validate_legacy_workflow(obsolete)


def test_generation_five_authority_pin_is_the_registered_upgrade_target():
    """The only accepted destination is Moonshots e86a3c4e.

    e86a3c4e pins rexcoleman.dev verify-write-enforcement.yml@13f6efd2 with
    control_sha 13f6efd2 -- the generation-5 verifier, the only one that passes
    the live 11-artifact issuance. Asserted against a literal so a regression of
    validator.TARGET_AUTHORITY_PIN fails here rather than silently redefining
    what "the target" means.
    """
    assert validator.TARGET_AUTHORITY_PIN == GENERATION_5_AUTHORITY_PIN
    assert (
        validator.validate_legacy_workflow(
            legacy_pinned_to(GENERATION_5_AUTHORITY_PIN)
        )
        is None
    )


def test_superseded_generation_four_authority_pin_refuses():
    """71c78352 pinned the generation-4 verifier c68062541f, which refuses the
    live manifest with WEA_WRONG_BUNDLE: authority_generation."""
    with pytest.raises(validator.Refusal, match="LEGACY_REUSABLE_WORKFLOW_PIN"):
        validator.validate_legacy_workflow(
            legacy_pinned_to(GENERATION_4_AUTHORITY_PIN)
        )


def test_bootstrap_accepts_only_the_generation_five_pinned_legacy_control(tmp_path):
    root, base, head, _authority = candidate(tmp_path)
    assert validate(root, base, head)["verdict"] == "PASS"
    accepted = (root / str(validator.LEGACY_WORKFLOW)).read_text(encoding="utf-8")
    assert (
        "rexcoleman/Moonshots_Career_Thesis/.github/workflows/"
        f"newsletter-integrity-authority.yml@{GENERATION_5_AUTHORITY_PIN}"
    ) in accepted
    assert GENERATION_4_AUTHORITY_PIN not in accepted


def test_wrong_repository_and_checkout_identity_refuse(tmp_path):
    root, base, head, _authority = candidate(tmp_path)
    with pytest.raises(validator.Refusal, match="REPOSITORY_IDENTITY"):
        validator.validate(root, "attacker/newsletter", base, head, REPO_ROOT)
    with pytest.raises(validator.Refusal, match="CHECKOUT_SHA_MISMATCH"):
        validator.validate(root, "rexcoleman/newsletter", base, base, REPO_ROOT)


def test_expected_capability_binds_exact_authority_commit():
    commit = "a" * 40
    loaded = json.loads(validator.expected_capability(commit))
    assert loaded["validator_authority"] == (
        "rexcoleman/rexcoleman.dev@" + commit
        + ":.github/write-enforcement/validate_newsletter_upgrade.py"
    )
    assert loaded["candidate_self_bootstraps"] is True
    assert loaded["candidate_code_executed"] is False


def registered_candidate(tmp_path: Path):
    root = tmp_path / "registered-newsletter"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "s188-fixture@example.invalid")
    git(root, "config", "user.name", "s188 validator fixture")
    before = {
        ".github/integrity/newsletter/control-manifest.json": b"before manifest\n",
        ".github/integrity/newsletter/validate_newsletter_commit.py": b"before validator\n",
    }
    after = {
        ".github/integrity/newsletter/control-manifest.json": b"after manifest\n",
        ".github/integrity/newsletter/validate_newsletter_commit.py": b"after validator\n",
        "tests/test_s188_curated_authority.py": b"faithful and planted tests\n",
    }
    for relative, raw in before.items():
        write(root, relative, raw)
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    base = git(root, "rev-parse", "HEAD")
    for relative, raw in after.items():
        write(root, relative, raw)
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "registered transition")
    head = git(root, "rev-parse", "HEAD")

    def state(raw: bytes):
        return {
            "present": True,
            "byte_length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    files = []
    for relative in sorted(after):
        files.append({
            "path": relative,
            "before": state(before[relative]) if relative in before else {
                "present": False,
            },
            "after": state(after[relative]),
        })
    transition = {
        "transition_id": "s188-fixture-v1",
        "purpose": "Exercise exact before and after byte authority.",
        "files": files,
    }
    return root, base, head, sorted(after), transition


def test_registered_transition_accepts_only_exact_before_and_after_bytes(tmp_path):
    root, base, head, changed, transition = registered_candidate(tmp_path)
    assert validator.validate_registered_transition(
        root, base, head, REPO_ROOT, changed, transitions=[transition]
    ) == "s188-fixture-v1"


@pytest.mark.parametrize("side", ["before", "after"])
def test_registered_transition_refuses_digest_divergence(tmp_path, side):
    root, base, head, changed, transition = registered_candidate(tmp_path)
    transition["files"][0][side]["sha256"] = "0" * 64
    with pytest.raises(
        validator.Refusal,
        match=f"REGISTERED_TRANSITION_{side.upper()}_BYTES",
    ):
        validator.validate_registered_transition(
            root, base, head, REPO_ROOT, changed, transitions=[transition]
        )


def test_registered_transition_refuses_extra_path_and_ambiguous_tuple(tmp_path):
    root, base, head, changed, transition = registered_candidate(tmp_path)
    with pytest.raises(validator.Refusal, match="CONTROL_CHANGE_SET"):
        validator.validate_registered_transition(
            root, base, head, REPO_ROOT, changed + ["newsletter.md"],
            transitions=[transition],
        )
    duplicate = json.loads(json.dumps(transition))
    duplicate["transition_id"] = "s188-fixture-v2"
    with pytest.raises(validator.Refusal, match="CONTROL_CHANGE_SET"):
        validator.validate_registered_transition(
            root, base, head, REPO_ROOT, changed,
            transitions=[transition, duplicate],
        )


def test_s188_index_binds_exact_c6_three_file_transition():
    transitions = validator.load_transition_index(REPO_ROOT)
    assert len(transitions) == 1
    transition = transitions[0]
    assert transition["transition_id"] == "s188-curated-newsletter-authority-v1"
    assert [entry["path"] for entry in transition["files"]] == [
        ".github/integrity/newsletter/control-manifest.json",
        ".github/integrity/newsletter/validate_newsletter_commit.py",
        "tests/test_s188_curated_authority.py",
    ]
    assert transition["files"][2]["before"] == {"present": False}
    assert transition["files"][2]["after"]["sha256"] == (
        "aec0a67169676a9392ff02e1d90990d39e8418ae3f9f465abcd7c3ef3730ffd5"
    )


def test_transition_index_duplicate_keys_refuse():
    with pytest.raises(validator.Refusal, match="TRANSITION_INDEX_DUPLICATE_KEY"):
        json.loads(
            '{"schema_version":"x","schema_version":"y"}',
            object_pairs_hook=validator._reject_duplicate_keys,
        )
