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
import re
import sys
from pathlib import Path

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


# ---------------------------------------------------------------------------
# The owner-approved path is untouched.
# ---------------------------------------------------------------------------


def test_capability_change_still_runs_behind_required_reviewers():
    jobs = issuer()["jobs"]
    assert jobs["issue-wea"]["environment"] == PROTECTED_ENVIRONMENT
    assert jobs["issue-wea"]["needs"] == "preflight-predecessor"


def test_capability_change_jobs_are_skipped_in_renewal_mode():
    jobs = issuer()["jobs"]
    for name in ("preflight-predecessor", "issue-wea"):
        assert jobs[name]["if"] == "inputs.mode != 'renew'"


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


def test_issuer_exposes_exactly_two_modes():
    on = triggers(issuer())
    assert on["workflow_dispatch"]["inputs"]["mode"]["options"] == [
        "capability_change",
        "renew",
    ]
    assert (
        on["workflow_dispatch"]["inputs"]["mode"]["default"] == "capability_change"
    ), "omitting mode must keep the pre-existing owner-approved behaviour"
