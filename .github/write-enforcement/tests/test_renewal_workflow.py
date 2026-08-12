"""Structural properties of the renewal path, asserted against the YAML itself.

The renewal design rests on four structural facts that are invisible to the
unit tests: which job declares which environment, which jobs each mode reaches,
that the unfrozen authority-bearing modules are pinned by digest inside a file
that IS frozen, and that the version table still describes the live workflow.
Each of those is a one-line edit away from silently disappearing, so each one
is asserted here.
"""

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT.parents[0] / "workflows"
ISSUER = WORKFLOWS / "issue-write-enforcement-attestation.yml"
SCHEDULER = WORKFLOWS / "renew-write-enforcement-attestation.yml"

sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "artifact_contract", ROOT / "artifact_contract.py"
)
CONTRACT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(CONTRACT)

PROTECTED_ENVIRONMENT = "rea-write-enforcement-issuer"
RENEWAL_ENVIRONMENT = "rea-write-enforcement-renewal"


def issuer():
    return yaml.safe_load(ISSUER.read_text())


def scheduler():
    return yaml.safe_load(SCHEDULER.read_text())


def triggers(document):
    # PyYAML resolves the bare key `on` to the boolean True.
    return document[True] if True in document else document["on"]


def raw_job(path, job_id):
    """The verbatim text of one job block.

    yaml.dump() re-wraps long scalars, which silently breaks substring
    assertions about shell commands; these assertions are about the bytes the
    runner executes, so they read the bytes.
    """
    lines = path.read_text().splitlines(keepends=True)
    start = next(
        index for index, line in enumerate(lines) if line == f"  {job_id}:\n"
    )
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            end = index
            break
    return "".join(lines[start:end])


def executable_lines(path):
    """The workflow with full-line comments removed."""
    return "\n".join(
        line for line in path.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


def run_scheduler_resolver(
    tmp_path, rows, target_sha, *, annotated=False, missing=False,
    issuance_run_ids=None, invalid_artifact_run_ids=(),
):
    """Execute the workflow's literal resolver against a closed fake GH API."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    fake = tmp_path / "gh"
    fake.write_text(
        """#!/usr/bin/python3
import json
import os
import sys

args = sys.argv[1:]
if args[:2] == ["run", "list"]:
    print(os.environ["FAKE_ISSUER_RUNS"])
    raise SystemExit(0)
if args and args[0] == "api" and "/actions/runs/" in args[1] and "/artifacts" in args[1]:
    run_id = int(args[1].split("/actions/runs/", 1)[1].split("/", 1)[0])
    runs = {row["databaseId"]: row for row in json.loads(os.environ["FAKE_ISSUER_RUNS"])}
    row = runs[run_id]
    if run_id not in json.loads(os.environ["FAKE_ISSUANCE_RUN_IDS"]):
        print(json.dumps({"total_count": 0, "artifacts": []}))
        raise SystemExit(0)
    artifact = {
        "name": "rea-write-enforcement-attestation-%s" % run_id,
        "expired": False,
        "workflow_run": {
            "id": run_id,
            "head_branch": row["headBranch"],
            "head_sha": row["headSha"],
        },
    }
    if run_id in json.loads(os.environ["FAKE_INVALID_ARTIFACT_RUN_IDS"]):
        artifact["workflow_run"]["head_sha"] = "f" * 40
    print(json.dumps({"total_count": 1, "artifacts": [artifact]}))
    raise SystemExit(0)
if args and args[0] == "api" and "/git/ref/tags/" in args[1]:
    if os.environ.get("FAKE_TAG_MISSING") == "1":
        raise SystemExit(4)
    if os.environ.get("FAKE_TAG_ANNOTATED") == "1":
        print(json.dumps({"object": {"type": "tag", "sha": "b" * 40}}))
    else:
        print(json.dumps({"object": {"type": "commit", "sha": os.environ["FAKE_TAG_TARGET"]}}))
    raise SystemExit(0)
if args and args[0] == "api" and "/git/tags/" in args[1]:
    print(json.dumps({"object": {"type": "commit", "sha": os.environ["FAKE_TAG_TARGET"]}}))
    raise SystemExit(0)
raise SystemExit(9)
"""
    )
    fake.chmod(0o755)
    env_file = tmp_path / "github-env"
    env = dict(os.environ)
    env.update(
        {
            "PATH": str(tmp_path) + os.pathsep + env["PATH"],
            "GH_TOKEN": "fixture-token",
            "GITHUB_ENV": str(env_file),
            "FAKE_ISSUER_RUNS": json.dumps(rows),
            "FAKE_TAG_TARGET": target_sha,
            "FAKE_TAG_ANNOTATED": "1" if annotated else "0",
            "FAKE_TAG_MISSING": "1" if missing else "0",
            "FAKE_ISSUANCE_RUN_IDS": json.dumps(
                [row["databaseId"] for row in rows]
                if issuance_run_ids is None else issuance_run_ids
            ),
            "FAKE_INVALID_ARTIFACT_RUN_IDS": json.dumps(
                list(invalid_artifact_run_ids)
            ),
        }
    )
    resolver = scheduler()["jobs"]["dispatch-renewal"]["steps"][0]["run"]
    result = subprocess.run(
        ["/bin/bash", "-c", resolver],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, env_file.read_text() if env_file.exists() else ""


# ---------------------------------------------------------------------------
# The owner-approved path is untouched.
# ---------------------------------------------------------------------------


def test_capability_change_still_runs_behind_required_reviewers():
    jobs = issuer()["jobs"]
    assert jobs["issue-wea"]["environment"] == PROTECTED_ENVIRONMENT
    assert jobs["issue-wea"]["needs"] == [
        "preflight-predecessor", "preflight-sealed-transfer",
    ]
    assert jobs["seal-downstream"]["environment"] == PROTECTED_ENVIRONMENT


def test_capability_change_jobs_are_skipped_in_renewal_mode():
    jobs = issuer()["jobs"]
    assert jobs["preflight-predecessor"]["if"] == "inputs.mode != 'renew'"
    assert jobs["issue-wea"]["if"] == (
        "inputs.mode == 'capability_change' || "
        "inputs.mode == 'capability_change_existing_secret' || "
        "inputs.mode == 'public_retry'"
    )
    assert jobs["preflight-sealed-transfer"]["if"] == (
        "inputs.mode == 'capability_change' || "
        "inputs.mode == 'capability_change_existing_secret' || "
        "inputs.mode == 'public_retry'"
    )
    assert jobs["seal-downstream"]["if"] == "inputs.mode == 'seal_downstream'"


def test_public_retry_is_protected_and_structurally_has_no_seal_or_secret_write():
    jobs = issuer()["jobs"]
    assert jobs["issue-wea"]["environment"] == PROTECTED_ENVIRONMENT
    preflight = jobs["preflight-sealed-transfer"]["steps"]
    refusal = [row for row in preflight
               if row.get("name") == "Refuse seal inputs and mutation in no-seal modes"]
    assert len(refusal) == 1
    assert refusal[0]["if"] == (
        "inputs.mode == 'public_retry' || "
        "inputs.mode == 'capability_change_existing_secret'"
    )
    assert all("test -z" in refusal[0]["run"] and name in refusal[0]["run"]
               for name in ("TRANSFER_RUN_ID", "KEY_ID", "PUBLIC_KEY_SHA256",
                            "CIPHERTEXT_SHA256"))
    raw = raw_job(ISSUER, "issue-wea")
    assert "Publish authenticated packet to append-only Contents surface" in raw
    assert "secrets/REA_BUNDLE_READ_TOKEN" not in raw
    assert "encrypted_value" not in raw
    seal = raw_job(ISSUER, "seal-downstream")
    assert "inputs.mode == 'seal_downstream'" in seal


def test_existing_secret_capability_change_is_protected_and_never_seals_or_mutates():
    jobs = issuer()["jobs"]
    assert jobs["issue-wea"]["environment"] == PROTECTED_ENVIRONMENT
    preflight = raw_job(ISSUER, "preflight-sealed-transfer")
    assert "capability_change_existing_secret" in preflight
    assert "NO_SEAL_CAPABILITY_PASS" in preflight
    issue = raw_job(ISSUER, "issue-wea")
    assert "inputs.mode == 'capability_change'" in issue
    assert "encrypted_value" not in issue
    assert "actions/secrets" not in issue


def test_renewal_jobs_only_run_in_renewal_mode():
    jobs = issuer()["jobs"]
    for name in ("renew-preflight", "renew-wea"):
        assert jobs[name]["if"] == "inputs.mode == 'renew'"


# ---------------------------------------------------------------------------
# The renewal path removes the human, not the checks.
# ---------------------------------------------------------------------------


def test_renewal_does_not_declare_the_reviewer_gated_environment():
    jobs = issuer()["jobs"]
    assert jobs["renew-wea"]["environment"] == RENEWAL_ENVIRONMENT
    assert jobs["renew-wea"]["environment"] != PROTECTED_ENVIRONMENT
    assert "environment" not in jobs["renew-preflight"]


def test_renewal_keeps_every_verification_the_owner_path_performs():
    """Each named assertion the owner path makes is made by the renewal path."""
    owner = raw_job(ISSUER, "preflight-predecessor") + raw_job(ISSUER, "issue-wea")
    renewal = raw_job(ISSUER, "renew-preflight") + raw_job(ISSUER, "renew-wea")
    for assertion in (
        "sha256sum -c SHA256SUMS",
        "check-predecessor --packet predecessor",
        "public.verify(value, bytes.fromhex(digest))",
        'receipt["event"] == "workflow_dispatch"',
        "checkout_manifest.py",
        "normalize_ruleset",
        "issue_wea.py",
        "verify_hosted_wea.py",
        "PUBLIC_ONLY_ARTIFACT_PASS",
        "current-members --bind-workflow",
        "-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----",
    ):
        assert assertion in owner, f"owner path lost: {assertion}"
        assert assertion in renewal, f"renewal path lacks: {assertion}"


def test_renewal_gate_runs_before_and_after_issuance():
    body = raw_job(ISSUER, "renew-wea")
    precheck = body.index("renewal_contract.py precheck")
    issue = body.index("issue_wea.py")
    classify = body.index("renewal_contract.py classify")
    upload = body.index("upload-artifact")
    assert precheck < issue < classify < upload


def test_renewal_refuses_an_owner_supplied_predecessor_pin():
    body = raw_job(ISSUER, "renew-preflight")
    assert "RENEWAL_OWNER_PIN_REFUSED" in body


def test_renewal_refuses_rather_than_falling_back_to_an_older_run():
    body = raw_job(ISSUER, "renew-preflight")
    assert "RENEWAL_PREDECESSOR_ARTIFACT_UNAVAILABLE" in body


def test_no_named_run_commit_or_actor_is_exempted_anywhere():
    """P-6 forbids satisfying a precondition by a manual out-of-band act.

    A literal run id, commit sha or login in the issuer workflow would be
    exactly such an exemption.  The only long hex literals permitted are the
    action pins on `uses:` lines and the two module digest pins.
    """
    text = ISSUER.read_text()
    permitted = set(re.findall(r"uses: \S+@([0-9a-f]{40})", text))
    permitted |= set(re.findall(r"_SHA256: ([0-9a-f]{64})", text))
    for literal in re.findall(r"\b[0-9a-f]{40,64}\b", text):
        assert literal in permitted, f"unexplained hex literal: {literal}"
    for literal in re.findall(r"\b\d{9,}\b", text):
        assert literal == "19564990", f"unexplained numeric literal: {literal}"


# ---------------------------------------------------------------------------
# The unfrozen modules are inside the frozen boundary, transitively.
# ---------------------------------------------------------------------------


def test_workflow_pins_the_live_bytes_of_the_unfrozen_modules():
    text = ISSUER.read_text()
    for name, path in (
        ("RENEWAL_CONTRACT_SHA256", ROOT / "renewal_contract.py"),
        ("ARTIFACT_CONTRACT_SHA256", ROOT / "artifact_contract.py"),
    ):
        pinned = re.search(rf"{name}: ([0-9a-f]{{64}})", text)
        assert pinned, f"{name} pin absent from the issuer workflow"
        assert pinned.group(1) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_version_table_registers_the_live_issuer_workflow_blob():
    """A workflow edit without a matching table entry breaks the chain.

    verify_current_binding() is what the issuer runs on the hosted runner; if
    the table stops describing the live workflow, every issuance refuses.  This
    catches that here rather than at the one moment it would cost an outage.
    """
    table = CONTRACT.load_table(ROOT / "artifact_contract_versions.json")
    digest = CONTRACT.verify_current_binding(table, ISSUER)
    assert digest == hashlib.sha256(ISSUER.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# The scheduler is a registered automatic trigger and holds no authority.
# ---------------------------------------------------------------------------


def test_scheduler_fires_automatically_and_is_dispatchable_for_testing():
    on = triggers(scheduler())
    assert "workflow_dispatch" in on
    crons = [entry["cron"] for entry in on["schedule"]]
    assert crons and all(re.fullmatch(r"[\d */,-]+", cron) for cron in crons)


def test_scheduler_holds_no_secret_and_declares_no_environment():
    document = scheduler()
    assert "environment" not in document["jobs"]["dispatch-renewal"]
    assert "secrets." not in SCHEDULER.read_text()
    assert document["permissions"] == {"contents": "read", "actions": "write"}


def test_scheduler_can_only_ask_for_a_renewal():
    text = executable_lines(SCHEDULER)
    assert "-f mode=renew" in text
    assert "capability_change" not in text
    assert "RENEWAL_DISPATCH_CREATED_NO_RUN" in text


@pytest.mark.parametrize(
    ("generation_ref", "annotated"),
    [
        ("rea-wea-generation-4-bdbaa8d0756", True),
        ("rea-wea-generation-4-0123456789ab", False),
    ],
)
def test_scheduler_accepts_closed_historical_and_canonical_refs(
    tmp_path, generation_ref, annotated
):
    head_sha = "a" * 40
    result, exported = run_scheduler_resolver(
        tmp_path,
        [{"databaseId": 31320298078, "headBranch": generation_ref, "headSha": head_sha}],
        head_sha,
        annotated=annotated,
    )
    assert result.returncode == 0, result.stderr
    assert f"RENEWAL_GENERATION_REF={generation_ref}\n" in exported
    assert f"RENEWAL_GENERATION_HEAD_SHA={head_sha}\n" in exported
    assert f"ref={generation_ref} run_id=31320298078 head_sha={head_sha}" in result.stdout


@pytest.mark.parametrize(
    "generation_ref",
    [
        "rea-wea-generation-4-0123456789",  # 10 hex
        "rea-wea-generation-4-0123456789abc",  # 13 hex
        "rea-wea-generation-4-BDBAA8D0756",  # malformed case
        "rea-wea-generation-5-bdbaa8d0756",  # exception is exact, not a width rule
    ],
)
def test_scheduler_refuses_unregistered_or_malformed_refs(tmp_path, generation_ref):
    head_sha = "a" * 40
    result, exported = run_scheduler_resolver(
        tmp_path,
        [{"databaseId": 31320298078, "headBranch": generation_ref, "headSha": head_sha}],
        head_sha,
    )
    assert result.returncode == 3
    assert "RENEWAL_NO_GENERATION_TAG_ISSUED" in result.stderr
    assert exported == ""


def test_scheduler_refuses_missing_or_retargeted_live_tag(tmp_path):
    generation_ref = "rea-wea-generation-4-bdbaa8d0756"
    head_sha = "a" * 40
    rows = [{"databaseId": 31320298078, "headBranch": generation_ref, "headSha": head_sha}]

    missing, exported = run_scheduler_resolver(
        tmp_path / "missing", rows, head_sha, annotated=True, missing=True
    )
    assert missing.returncode == 3
    assert "RENEWAL_GENERATION_TAG_MISSING" in missing.stderr
    assert exported == ""

    retargeted, exported = run_scheduler_resolver(
        tmp_path / "retargeted", rows, "c" * 40, annotated=True
    )
    assert retargeted.returncode == 3
    assert "RENEWAL_GENERATION_TAG_RETARGETED" in retargeted.stderr
    assert exported == ""


def test_scheduler_uses_unique_newest_authenticated_run(tmp_path):
    older_sha = "1" * 40
    newest_sha = "2" * 40
    rows = [
        {
            "databaseId": 100,
            "headBranch": "rea-wea-generation-4-0123456789ab",
            "headSha": older_sha,
        },
        {
            "databaseId": 200,
            "headBranch": "rea-wea-generation-4-bdbaa8d0756",
            "headSha": newest_sha,
        },
    ]
    result, exported = run_scheduler_resolver(
        tmp_path, rows, newest_sha, annotated=True
    )
    assert result.returncode == 0, result.stderr
    assert "RENEWAL_GENERATION_REF=rea-wea-generation-4-bdbaa8d0756\n" in exported
    assert f"RENEWAL_GENERATION_HEAD_SHA={newest_sha}\n" in exported

    tied = [rows[1], dict(rows[1])]
    refused, _ = run_scheduler_resolver(
        tmp_path / "tied", tied, newest_sha, annotated=True
    )
    assert refused.returncode == 3
    assert "RENEWAL_GENERATION_TAG_AMBIGUOUS" in refused.stderr


def test_scheduler_excludes_newer_successful_seal_without_wea_artifact(tmp_path):
    issued_sha = "1" * 40
    seal_sha = "2" * 40
    rows = [
        {
            "databaseId": 100,
            "headBranch": "rea-wea-generation-4-0123456789ab",
            "headSha": issued_sha,
        },
        {
            "databaseId": 200,
            "headBranch": "rea-wea-generation-5-abcdef012345",
            "headSha": seal_sha,
        },
    ]
    result, exported = run_scheduler_resolver(
        tmp_path, rows, issued_sha, issuance_run_ids=[100]
    )
    assert result.returncode == 0, result.stderr
    assert "RENEWAL_GENERATION_REF=rea-wea-generation-4-0123456789ab\n" in exported
    assert "run_id=100" in result.stdout
    assert "run_id=200" not in result.stdout


def test_scheduler_refuses_when_no_successful_run_has_wea_artifact(tmp_path):
    head_sha = "2" * 40
    result, exported = run_scheduler_resolver(
        tmp_path,
        [{"databaseId": 200,
          "headBranch": "rea-wea-generation-5-abcdef012345",
          "headSha": head_sha}],
        head_sha,
        issuance_run_ids=[],
    )
    assert result.returncode == 3
    assert "RENEWAL_NO_ISSUED_AUTHORITY" in result.stderr
    assert exported == ""


def test_scheduler_refuses_mismatched_named_wea_artifact(tmp_path):
    head_sha = "2" * 40
    result, exported = run_scheduler_resolver(
        tmp_path,
        [{"databaseId": 200,
          "headBranch": "rea-wea-generation-5-abcdef012345",
          "headSha": head_sha}],
        head_sha,
        invalid_artifact_run_ids=[200],
    )
    assert result.returncode == 3
    assert "RENEWAL_ISSUANCE_ARTIFACT_IDENTITY_REFUSED" in result.stderr
    assert exported == ""


def test_scheduler_dispatch_candidate_is_bound_to_selected_ref_and_sha():
    body = raw_job(SCHEDULER, "dispatch-renewal")
    assert "--json databaseId,headBranch,headSha" in body
    assert '[ "$candidate_ref" = "$RENEWAL_GENERATION_REF" ]' in body
    assert '[ "$candidate_sha" = "$RENEWAL_GENERATION_HEAD_SHA" ]' in body


def test_issuer_exposes_exactly_five_closed_modes():
    on = triggers(issuer())
    assert on["workflow_dispatch"]["inputs"]["mode"]["options"] == [
        "capability_change",
        "capability_change_existing_secret",
        "public_retry",
        "seal_downstream",
        "renew",
    ]
    assert (
        on["workflow_dispatch"]["inputs"]["mode"]["default"] == "capability_change"
    ), "omitting mode must keep the pre-existing owner-approved behaviour"
