"""Controls for the credential custody checker.

Every failure mode the checker claims to catch is planted here as a negative,
and each negative is paired against a positive control built from the SAME
fixture minus the planted defect.  A checker that only ever sees a passing
record has not been shown to discriminate.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
CHECKER = ROOT / "credential_custody.py"
RECORD = ROOT / "credential_custody.json"

SPEC = importlib.util.spec_from_file_location("credential_custody", CHECKER)
CUSTODY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(CUSTODY)


def run_checker(root, record, workflows, *extra):
    proc = subprocess.run(
        [sys.executable, str(CHECKER), "check",
         "--root", str(root), "--record", str(record),
         "--workflows", str(workflows), *extra],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


DETECTION = {
    "detector": ".github/workflows/renew-write-enforcement-attestation.yml",
    "cadence": "cron 17 */6 * * *",
    "how_it_detects": "exercised four times per 24-hour lifetime, so a lapse "
                      "fails a run at least six hours before outage",
}


def complete_row(credential_id="PLANTED_TOKEN@planted-env"):
    """A record row with nothing missing.  Every negative removes one field."""
    return {
        "credential_id": credential_id,
        "secret_name": credential_id.split("@")[0],
        "owner": "rexcoleman",
        "location": {
            "scope": "github-environment-secret",
            "repository": "rexcoleman/rexcoleman.dev",
            "environment": credential_id.split("@")[1],
        },
        "expiry": {
            "kind": "UNRECORDED_AND_UNREADABLE",
            "value": None,
            "reason": "the secrets API exposes updated_at only",
        },
        "lapse_detection": dict(DETECTION),
        "reestablishing_transition": {
            "status": "REGISTERED",
            "path": ".github/write-enforcement/credential_custody.py",
            "invocation": "gh workflow run provision-renewal-signing-key.yml",
        },
    }


@pytest.fixture
def bed(tmp_path):
    """A miniature repository: one workflow, one record, real files on disk."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (tmp_path / ".github" / "write-enforcement").mkdir(parents=True)
    (tmp_path / ".github" / "write-enforcement" / "credential_custody.py").write_text("#\n")
    (tmp_path / ".github" / "write-enforcement" / "RUNBOOK.md").write_text("#\n")
    (workflows / "planted.yml").write_text(
        "name: planted\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  consume:\n"
        "    environment: planted-env\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - env:\n"
        "          TOKEN: ${{ secrets.PLANTED_TOKEN }}\n"
        "        run: 'true'\n"
    )
    record = tmp_path / "custody.json"

    def write(rows):
        record.write_text(json.dumps(
            {"schema_version": "test", "credentials": rows}, indent=1))
        return record

    return tmp_path, workflows, write


# --------------------------------------------------------------------------
# POSITIVE CONTROL.  A complete record over the same workflow set must PASS.
# --------------------------------------------------------------------------

def test_positive_control_complete_record_passes(bed):
    root, workflows, write = bed
    code, out, err = run_checker(root, write([complete_row()]), workflows)
    assert code == 0, err
    assert "CUSTODY_CHECK_PASS" in out


# --------------------------------------------------------------------------
# PLANTED NEGATIVE 1 (mandatory).  A chain credential with NO custody row.
# --------------------------------------------------------------------------

def test_planted_negative_missing_row(bed):
    root, workflows, write = bed
    code, out, err = run_checker(root, write([]), workflows)
    assert code == 3
    assert "CUSTODY_ROW_MISSING" in err
    assert "PLANTED_TOKEN@planted-env" in err


# --------------------------------------------------------------------------
# PLANTED NEGATIVE 2 (mandatory).  A row with NO re-establishing transition.
# --------------------------------------------------------------------------

def test_planted_negative_row_without_transition(bed):
    root, workflows, write = bed
    row = complete_row()
    del row["reestablishing_transition"]
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "CUSTODY_TRANSITION_MISSING" in err

    row = complete_row()
    row["reestablishing_transition"] = {}
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "CUSTODY_TRANSITION_MISSING" in err


# --------------------------------------------------------------------------
# Supporting negatives: each is a way the record could look complete and not be.
# --------------------------------------------------------------------------

def test_declared_p6_violation_fails_strict_check(bed):
    root, workflows, write = bed
    row = complete_row()
    row["reestablishing_transition"] = {
        "status": "NONE_P6_VIOLATION",
        "open_cycle_back": "planted-cycle-back",
        "compensating_lapse_detection": dict(DETECTION),
    }
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "CUSTODY_TRANSITION_MISSING" in err

    code, out, err = run_checker(root, write([row]), workflows, "--allow-declared-open")
    assert code == 0, err
    assert "P6_OPEN" in out


def test_declared_p6_violation_without_compensation_fails_even_waived(bed):
    root, workflows, write = bed
    row = complete_row()
    row["reestablishing_transition"] = {"status": "NONE_P6_VIOLATION"}
    code, out, err = run_checker(root, write([row]), workflows, "--allow-declared-open")
    assert code == 3
    assert "CUSTODY_TRANSITION_INCOMPLETE" in err
    assert "CUSTODY_LAPSE_DETECTION_MISSING" in err


def test_declared_open_budget_caps_the_waiver(bed):
    """The waiver may not become the default.

    Without a budget, the cheapest record that passes --allow-declared-open is
    one where EVERY row is declared open, which would make the flag vacuous.
    """
    root, workflows, write = bed
    rows = []
    for index in range(3):
        row = complete_row(f"PLANTED_TOKEN@planted-env" if index == 0
                           else f"EXTRA_{index}@planted-env")
        row["reestablishing_transition"] = {
            "status": "NONE_P6_VIOLATION",
            "open_cycle_back": "planted",
            "compensating_lapse_detection": dict(DETECTION),
        }
        rows.append(row)
    code, out, err = run_checker(root, write(rows), workflows,
                                 "--allow-declared-open", "--max-declared-open", "2")
    assert code == 3
    assert "CUSTODY_DECLARED_OPEN_BUDGET_EXCEEDED" in err


def test_registered_transition_must_exist_on_disk(bed):
    root, workflows, write = bed
    row = complete_row()
    row["reestablishing_transition"]["path"] = ".github/workflows/does-not-exist.yml"
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "CUSTODY_TRANSITION_DANGLING" in err


def test_unreadable_expiry_without_lapse_detection_fails(bed):
    """The structural compensation is mandatory, not advisory."""
    root, workflows, write = bed
    row = complete_row()
    del row["lapse_detection"]
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "CUSTODY_LAPSE_DETECTION_MISSING" in err


def test_blank_expiry_is_rejected(bed):
    """A blank expiry is the silent-lapse failure mode itself."""
    root, workflows, write = bed
    row = complete_row()
    row["expiry"] = {"kind": "", "value": None, "reason": ""}
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "CUSTODY_EXPIRY_UNTYPED" in err


def test_fabricated_recorded_expiry_must_parse(bed):
    root, workflows, write = bed
    row = complete_row()
    row["expiry"] = {"kind": "RECORDED", "value": "someday", "reason": "minted by owner"}
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "CUSTODY_EXPIRY_UNTYPED" in err


def test_owner_act_sanctioned_needs_ruling_runbook_and_detection(bed):
    root, workflows, write = bed
    row = complete_row()
    row["reestablishing_transition"] = {"status": "OWNER_ACT_SANCTIONED"}
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 3
    assert "sanctioned_by" in err
    assert "runbook" in err
    assert "owner_acts" in err

    row["reestablishing_transition"] = {
        "status": "OWNER_ACT_SANCTIONED",
        "sanctioned_by": "Rex ruling 2026-08-07",
        "runbook": ".github/write-enforcement/RUNBOOK.md",
        "owner_acts": ["mint a token"],
    }
    code, out, err = run_checker(root, write([row]), workflows)
    assert code == 0, err


def test_unscoped_repository_secret_is_reported(bed):
    """This repository holds no repository-level secrets; a job with no
    environment that reads one is a regression, not a normal shape."""
    root, workflows, write = bed
    (workflows / "unscoped.yml").write_text(
        "name: unscoped\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  leak:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - env:\n"
        "          T: ${{ secrets.SOME_REPO_LEVEL_TOKEN }}\n"
        "        run: 'true'\n"
    )
    code, out, err = run_checker(root, write([complete_row()]), workflows)
    assert code == 3
    assert "CUSTODY_SECRET_UNSCOPED" in err
    assert "SOME_REPO_LEVEL_TOKEN" in err


def test_reusable_callee_secrets_are_not_custody_subjects(bed):
    """A workflow_call callee names the CALLER's credentials, held elsewhere."""
    root, workflows, write = bed
    (workflows / "callee.yml").write_text(
        "name: callee\n"
        "on:\n"
        "  workflow_call:\n"
        "    secrets:\n"
        "      REA_WEA_READ_TOKEN:\n"
        "        required: true\n"
        "jobs:\n"
        "  verify:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - env:\n"
        "          GH_TOKEN: ${{ secrets.REA_WEA_READ_TOKEN }}\n"
        "        run: 'true'\n"
    )
    code, out, err = run_checker(root, write([complete_row()]), workflows)
    assert code == 0, err


def test_github_token_is_not_a_custody_subject(bed):
    root, workflows, write = bed
    (workflows / "gh.yml").write_text(
        "name: gh\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  run:\n"
        "    environment: planted-env\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "        run: 'true'\n"
    )
    code, out, err = run_checker(root, write([complete_row()]), workflows)
    assert code == 0, err


# --------------------------------------------------------------------------
# The live record, against the live workflows.
# --------------------------------------------------------------------------

def test_live_record_passes_with_declared_open_rows_waived():
    code, out, err = run_checker(REPO, RECORD, REPO / ".github" / "workflows",
                                 "--allow-declared-open")
    assert code == 0, err + out
    assert "CUSTODY_CHECK_PASS" in out


def test_live_record_is_red_under_strict_check_and_names_why():
    """Strict check is red on this tree BY DESIGN.

    Two credentials genuinely have no registered re-establishing path.  The
    checker refuses rather than letting that sit unrecorded.  If someone builds
    those transitions, this test is the thing that tells them to update it.
    """
    code, out, err = run_checker(REPO, RECORD, REPO / ".github" / "workflows")
    assert code == 3
    assert "REA_WEA_ED25519_PRIVATE_KEY_B64@rea-write-enforcement-issuer" in err
    assert "REA_SECOND_PRINCIPAL_PRIVATE_KEY@rea-write-enforcement-issuer" in err


def test_live_record_covers_every_environment_scoped_secret():
    required, unscoped = CUSTODY.required_credentials(REPO / ".github" / "workflows")
    recorded = {row["credential_id"] for row in json.loads(RECORD.read_text())["credentials"]}
    assert not unscoped, unscoped
    assert set(required) <= recorded, set(required) - recorded
    # The renewal-environment signing key is the whole point of the cycle-back.
    assert "REA_WEA_ED25519_PRIVATE_KEY_B64@rea-write-enforcement-renewal" in required
