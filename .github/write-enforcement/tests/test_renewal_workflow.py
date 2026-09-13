"""Structural properties of the renewal path, asserted against the YAML itself.

The renewal design rests on four structural facts that are invisible to the
unit tests: which job declares which environment, which jobs each mode reaches,
that the unfrozen authority-bearing modules are pinned by digest inside a file
that IS frozen, and that the version table still describes the live workflow.
Each of those is a one-line edit away from silently disappearing, so each one
is asserted here.
"""

import copy
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


def _no_seal_step(document=None):
    document = issuer() if document is None else document
    step = next(
        row
        for row in document["jobs"]["preflight-sealed-transfer"]["steps"]
        if row.get("name") == "Refuse seal inputs and mutation in no-seal modes"
    )
    assert step["env"] == {
        "MODE": "${{ inputs.mode }}",
        "TRANSFER_RUN_ID": "${{ inputs.sealed_transfer_run_id }}",
        "DOWNSTREAM_REPOSITORY": "${{ inputs.downstream_repository }}",
        "KEY_ID": "${{ inputs.downstream_key_id }}",
        "PUBLIC_KEY_B64": "${{ inputs.downstream_public_key_b64 }}",
        "PUBLIC_KEY_SHA256": "${{ inputs.downstream_public_key_sha256 }}",
        "CIPHERTEXT_SHA256": "${{ inputs.sealed_ciphertext_sha256 }}",
    }
    return step


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
    assert jobs["issue-wea"]["needs"] == [
        "preflight-predecessor", "preflight-sealed-transfer",
    ]
    assert jobs["seal-downstream"]["environment"] == PROTECTED_ENVIRONMENT


def test_capability_change_jobs_are_skipped_in_renewal_mode():
    jobs = issuer()["jobs"]
    assert jobs["preflight-predecessor"]["if"] == "inputs.mode != 'renew' && inputs.mode != 'history_finalize'"
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
    assert _no_seal_step() == refusal[0]
    assert refusal[0]["if"] == (
        "inputs.mode == 'public_retry' || "
        "inputs.mode == 'capability_change_existing_secret'"
    )
    assert all(
        f'test -z "${name}"' in refusal[0]["run"]
        for name in (
            "TRANSFER_RUN_ID",
            "DOWNSTREAM_REPOSITORY",
            "KEY_ID",
            "PUBLIC_KEY_B64",
            "PUBLIC_KEY_SHA256",
            "CIPHERTEXT_SHA256",
        )
    )
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


def _run_no_seal_preflight(**overrides):
    step = _no_seal_step()
    environment = {
        "PATH": "/usr/bin:/bin",
        "MODE": "capability_change_existing_secret",
        "TRANSFER_RUN_ID": "",
        "DOWNSTREAM_REPOSITORY": "",
        "KEY_ID": "",
        "PUBLIC_KEY_B64": "",
        "PUBLIC_KEY_SHA256": "",
        "CIPHERTEXT_SHA256": "",
    }
    environment.update(overrides)
    return subprocess.run(
        ["/bin/bash", "-c", step["run"]],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_existing_secret_no_seal_preflight_accepts_exact_empty_transfer_inputs():
    completed = _run_no_seal_preflight()
    assert completed.returncode == 0
    assert completed.stdout.strip() == (
        "NO_SEAL_CAPABILITY_PASS mode=capability_change_existing_secret "
        "mutation=false secret_write=false"
    )
    assert completed.stderr == ""


def test_existing_secret_no_seal_preflight_refuses_nonempty_public_key_b64():
    completed = _run_no_seal_preflight(PUBLIC_KEY_B64="cGxhbnRlZA==")
    assert completed.returncode != 0
    assert "NO_SEAL_CAPABILITY_PASS" not in completed.stdout


@pytest.mark.parametrize("plant", ["missing", "misdirected"])
def test_no_seal_contract_refuses_public_key_b64_binding_drift(plant):
    document = copy.deepcopy(issuer())
    step = next(
        row
        for row in document["jobs"]["preflight-sealed-transfer"]["steps"]
        if row.get("name") == "Refuse seal inputs and mutation in no-seal modes"
    )
    if plant == "missing":
        del step["env"]["PUBLIC_KEY_B64"]
    else:
        step["env"]["PUBLIC_KEY_B64"] = (
            "${{ inputs.downstream_public_key_sha256 }}"
        )
    with pytest.raises(AssertionError):
        _no_seal_step(document)


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
    assert "durable_attestation_history.py export" in body
    assert "actions/runs/" not in body and "gh run download" not in body


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
























def test_scheduler_dispatch_candidate_is_bound_to_selected_ref_and_sha():
    body = raw_job(SCHEDULER, "dispatch-renewal")
    assert "--json databaseId,headBranch,headSha" in body
    assert '[ "$candidate_ref" = "$RENEWAL_GENERATION_REF" ]' in body
    assert '[ "$candidate_sha" = "$RENEWAL_GENERATION_HEAD_SHA" ]' in body


def test_issuer_exposes_closed_modes_with_prior_run_finalization():
    on = triggers(issuer())
    assert on["workflow_dispatch"]["inputs"]["mode"]["options"] == [
        "capability_change",
        "capability_change_existing_secret",
        "public_retry",
        "seal_downstream",
        "renew",
        "history_finalize",
    ]
    assert (
        on["workflow_dispatch"]["inputs"]["mode"]["default"] == "capability_change"
    ), "omitting mode must keep the pre-existing owner-approved behaviour"


def test_history_finalization_reuses_renewal_identity_and_pins_before_custody():
    job = issuer()["jobs"]["history-finalize"]
    assert job["environment"] == issuer()["jobs"]["renew-wea"]["environment"]
    assert job["if"] == "inputs.mode == 'history_finalize'"
    assert job["permissions"] == {"contents": "write", "actions": "read"}
    body = raw_job(ISSUER, "history-finalize")
    assert body.index('DURABLE_HISTORY_SHA256') < body.index('secrets.REA_WEA_ED25519_PRIVATE_KEY_B64')
    assert body.index('DURABLE_HISTORY_PUBLIC_KEY_SHA256') < body.index('secrets.REA_WEA_ED25519_PRIVATE_KEY_B64')
    assert 'issue_wea.py' not in body
    assert 'durable_attestation_history.py finalize' in body
    for name, path in [('DURABLE_HISTORY_SHA256', ROOT/'durable_attestation_history.py'),
                       ('DURABLE_HISTORY_PUBLIC_KEY_SHA256', ROOT/'trusted_wea_public.pem')]:
        assert issuer()['env'][name] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_both_preflights_use_independent_durable_success_before_signing():
    for job in ('preflight-predecessor', 'renew-preflight'):
        body=raw_job(ISSUER,job)
        assert 'durable_attestation_history.py export' in body
        assert '--trusted-public-key repo/.github/write-enforcement/trusted_wea_public.pem' in body
        assert 'gh run download' not in body and 'actions/runs/' not in body
        assert body.index('DURABLE_HISTORY_SHA256') < body.index('durable_attestation_history.py export')


def test_scheduler_finalizes_history_on_both_sides_of_renewal():
    steps=scheduler()['jobs']['dispatch-renewal']['steps']
    prepare=[(i,s) for i,s in enumerate(steps) if 'renewal_history_scheduler.py prepare' in s.get('run','')]
    dispatch=next(i for i,s in enumerate(steps) if '-f mode=renew' in s.get('run',''))
    assert len(prepare)==2 and prepare[0][0]<dispatch<prepare[1][0]
    assert prepare[1][1]['if'] == "always() && env.RENEWAL_RUN_ID != ''"
    text=SCHEDULER.read_text()
    assert 'durable_attestation_history.py resolve' in text
    assert '/artifacts' not in text
