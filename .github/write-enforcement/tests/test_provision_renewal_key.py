"""Controls for the registered key-copy transition.

These exercise the REAL code path.  A scripted stand-in for `gh` is placed on
disk and handed to the tool with --gh, so every assertion below is about what
provision_renewal_key.py actually does with a real ed25519 key on stdin, not
about the shape of a YAML file.

No live environment is touched, no PAT is minted, and no issuance is
triggered.  What remains unexercised until the owner acts is stated in the PR
body and in test_what_remains_unexercised below.
"""

import base64
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
TOOL = ROOT / "provision_renewal_key.py"
WORKFLOW = REPO / ".github" / "workflows" / "provision-renewal-signing-key.yml"

SPEC = importlib.util.spec_from_file_location("provision_renewal_key", TOOL)
PROVISION = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(PROVISION)

REPOSITORY = "rexcoleman/rexcoleman.dev"
TARGET = "rea-write-enforcement-renewal"
SECRET = "REA_WEA_ED25519_PRIVATE_KEY_B64"


@pytest.fixture(scope="module")
def key_b64():
    """A throwaway ed25519 private key, generated here, never leaving the tmp
    process.  It stands in for the real signing key's SHAPE only."""
    pem = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519"],
        check=True, capture_output=True,
    ).stdout
    return base64.b64encode(pem).decode()


@pytest.fixture
def fake_gh(tmp_path):
    """A scripted `gh`.

    Behaviour is driven by a JSON control file so each test can plant exactly
    one defect.  Every invocation is appended to a log, which lets the dry-run
    control assert that NO write was attempted.
    """
    control = tmp_path / "control.json"
    log = tmp_path / "gh.log"
    script = tmp_path / "gh"
    script.write_text(f'''#!/usr/bin/env python3
import json, sys, datetime
control = json.load(open({str(control)!r}))
with open({str(log)!r}, "a") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\\n")
argv = sys.argv[1:]
if argv[:1] == ["api"] and argv[1].endswith("/secrets/public-key"):
    if control.get("public_key_rc"):
        sys.stderr.write(control.get("public_key_stderr", "HTTP 403"))
        sys.exit(control["public_key_rc"])
    print(json.dumps({{"key_id": "1234", "key": "not-a-secret-public-key"}}))
    sys.exit(0)
if argv[:2] == ["secret", "set"]:
    payload = sys.stdin.read()
    if control.get("echo_stdin"):
        print("gh received: " + payload)
    if control.get("set_rc"):
        sys.stderr.write(control.get("set_stderr", "write failed"))
        sys.exit(control["set_rc"])
    sys.exit(0)
if argv[:1] == ["api"]:
    if control.get("observe_rc"):
        sys.stderr.write("HTTP 404")
        sys.exit(control["observe_rc"])
    stamp = control.get("observe_updated_at")
    if stamp is None:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(json.dumps({{"name": control.get("observe_name", {SECRET!r}),
                      "updated_at": stamp}}))
    sys.exit(0)
sys.exit(9)
''')
    script.chmod(0o755)
    control.write_text("{}")

    def configure(**kwargs):
        control.write_text(json.dumps(kwargs))
        return str(script)

    configure.log = log
    configure.script = str(script)
    return configure


def invoke(gh, key_b64, token="ghp_planted_not_a_real_token", mode="copy", **extra):
    """Run the real tool, capturing rc/stdout/stderr with no pipe in between."""
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--mode", mode,
         "--repository", REPOSITORY, "--target-environment", TARGET,
         "--secret-name", SECRET, "--gh", gh],
        capture_output=True, text=True,
        env={**os.environ, SECRET: key_b64, "GH_TOKEN": token, **extra},
    )
    return proc.returncode, proc.stdout, proc.stderr


# --------------------------------------------------------------------------
# POSITIVE CONTROLS
# --------------------------------------------------------------------------

def test_positive_control_copy_succeeds_and_verifies_by_name(fake_gh, key_b64):
    gh = fake_gh()
    code, out, err = invoke(gh, key_b64)
    assert code == 0, err
    assert "RENEWAL_SIGNING_KEY_PROVISIONED" in out
    assert f"target={TARGET}" in out
    assert "public_key_sha256=" in out
    log = fake_gh.log.read_text()
    assert "secret set" in log
    assert "secrets/public-key" in log


def test_positive_control_is_idempotent(fake_gh, key_b64):
    gh = fake_gh()
    first = invoke(gh, key_b64)
    second = invoke(gh, key_b64)
    assert first[0] == 0 and second[0] == 0, (first[2], second[2])
    assert "RENEWAL_SIGNING_KEY_PROVISIONED" in second[1]


def test_dry_run_proves_scope_and_writes_nothing(fake_gh, key_b64):
    gh = fake_gh()
    code, out, err = invoke(gh, key_b64, mode="dry-run")
    assert code == 0, err
    assert "PROVISION_DRY_RUN_PASS" in out
    assert "wrote_nothing=true" in out
    log = fake_gh.log.read_text()
    assert "secrets/public-key" in log
    assert "secret set" not in log


# --------------------------------------------------------------------------
# PLANTED NEGATIVES.  Each fails closed with a typed refusal and exit 3.
# --------------------------------------------------------------------------

def test_planted_negative_source_key_absent(fake_gh, key_b64):
    code, out, err = invoke(fake_gh(), "")
    assert code == 3
    assert "SOURCE_SIGNING_KEY_UNREADABLE" in err
    log = fake_gh.log.read_text() if fake_gh.log.exists() else ""
    assert "secret set" not in log


def test_planted_negative_source_key_malformed(fake_gh):
    code, out, err = invoke(fake_gh(), base64.b64encode(b"not a pem").decode())
    assert code == 3
    assert "SOURCE_SIGNING_KEY_MALFORMED" in err


def test_planted_negative_pat_absent(fake_gh, key_b64):
    code, out, err = invoke(fake_gh(), key_b64, token="")
    assert code == 3
    assert "SECRETS_WRITE_PAT_ABSENT" in err
    assert "REA_SECRETS_WRITE_PAT" in err


def test_planted_negative_pat_insufficient_scope(fake_gh, key_b64):
    gh = fake_gh(public_key_rc=1, public_key_stderr="HTTP 403: Resource not accessible")
    code, out, err = invoke(gh, key_b64)
    assert code == 3
    assert "SECRETS_WRITE_PAT_INSUFFICIENT_SCOPE" in err
    assert "Secrets: Read and write" in err
    assert "secret set" not in fake_gh.log.read_text()


def test_planted_negative_write_failed(fake_gh, key_b64):
    code, out, err = invoke(fake_gh(set_rc=1), key_b64)
    assert code == 3
    assert "SECRET_WRITE_FAILED" in err


def test_planted_negative_write_unverified(fake_gh, key_b64):
    """A copy it cannot verify is a FAILURE, not a success."""
    code, out, err = invoke(fake_gh(observe_rc=1), key_b64)
    assert code == 3
    assert "SECRET_WRITE_UNVERIFIED" in err


def test_planted_negative_wrong_secret_name_observed(fake_gh, key_b64):
    code, out, err = invoke(fake_gh(observe_name="SOMETHING_ELSE"), key_b64)
    assert code == 3
    assert "SECRET_WRITE_UNVERIFIED" in err


def test_planted_negative_stale_updated_at_is_not_a_success(fake_gh, key_b64):
    """The anti-no-op control.

    Without it, the cheapest implementation that passes 'verify the target
    secret exists by name' is one that writes nothing at all and observes a
    secret some earlier run left behind.
    """
    code, out, err = invoke(fake_gh(observe_updated_at="2020-01-01T00:00:00Z"), key_b64)
    assert code == 3
    assert "SECRET_WRITE_NOT_OBSERVED" in err
    assert "did not establish it" in err


def test_planted_negative_child_cannot_launder_the_secret_into_our_output(fake_gh, key_b64):
    """A child process that echoes the key back must not get it into the log.

    set_stderr is deliberately EMPTY so the refusal falls through to the
    child's STDOUT, which is where the echoed key is.  With a non-empty stderr
    this control passes vacuously -- removing redact() would not turn it red,
    which is exactly what a mutation run showed before this was tightened.
    """
    gh = fake_gh(echo_stdin=True, set_rc=1, set_stderr="")
    code, out, err = invoke(gh, key_b64)
    assert code == 3
    assert "gh received" in err, "the leaking child output must reach the refusal"
    assert key_b64 not in out + err
    assert key_b64.strip() not in out + err
    assert "***" in err


def test_refuses_a_copy_onto_itself():
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--mode", "copy",
         "--source-environment", "same", "--target-environment", "same"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 3
    assert "PROVISION_SOURCE_EQUALS_TARGET" in proc.stderr


# --------------------------------------------------------------------------
# The secret never reaches argv, a file, or a step output.
# --------------------------------------------------------------------------

def test_secret_is_never_an_argv_element(fake_gh, key_b64):
    invoke(fake_gh(), key_b64)
    for line in fake_gh.log.read_text().splitlines():
        assert key_b64 not in line
        assert "PRIVATE KEY" not in line


def test_redact_removes_both_raw_and_stripped_forms():
    secret = "abc123\n"
    text = "before abc123\n and abc123 after"
    scrubbed = PROVISION.redact(text, secret)
    assert "abc123" not in scrubbed
    assert scrubbed.count("***") == 2


def test_public_key_digest_is_stable_and_is_not_the_private_key(key_b64):
    first = PROVISION.public_key_digest(key_b64)
    second = PROVISION.public_key_digest(key_b64)
    assert first == second and len(first) == 64
    assert first not in key_b64


# --------------------------------------------------------------------------
# Structural properties of the workflow that carries the transition.
# --------------------------------------------------------------------------

def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def triggers(document):
    return document[True] if True in document else document["on"]


def test_only_workflow_dispatch_can_fire_it():
    """It moves a signing key; an untrusted trigger path would be a defect."""
    assert set(triggers(workflow())) == {"workflow_dispatch"}


def test_the_key_touching_job_sits_behind_the_reviewer_gated_environment():
    jobs = workflow()["jobs"]
    assert jobs["copy-signing-key"]["environment"] == "rea-write-enforcement-issuer"
    assert jobs["copy-signing-key"]["needs"] == "preflight"
    # The preflight job must hold no secrets at all.
    assert "environment" not in jobs["preflight"]
    assert "secrets." not in json.dumps(jobs["preflight"])


def test_both_jobs_refuse_a_ref_other_than_main():
    """rea-write-enforcement-issuer carries NO deployment branch policy, so the
    ref restriction has to be enforced in-job or it is not enforced at all."""
    raw = WORKFLOW.read_text()
    assert raw.count('GITHUB_REF" = "refs/heads/main"') >= 1
    assert raw.count('GITHUB_REF" != "refs/heads/main"') >= 1
    for job in workflow()["jobs"].values():
        assert any("refs/heads/main" in json.dumps(step) for step in job["steps"])


def test_it_does_not_edit_the_guard_it_makes_reachable():
    """The renew-wea guard must still be present and still fail closed."""
    issuer = (REPO / ".github" / "workflows"
              / "issue-write-enforcement-attestation.yml").read_text()
    assert "rea-write-enforcement-renewal holds no REA_WEA_ED25519_PRIVATE_KEY_B64." in issuer
    assert "REFUSED RENEWAL_SIGNING_KEY_UNPROVISIONED" in issuer


def test_third_party_actions_are_pinned_by_commit_sha():
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            uses = step.get("uses")
            if uses:
                assert len(uses.split("@")[1]) == 40, uses


def test_what_remains_unexercised():
    """Named here so it cannot be quietly forgotten.

    Everything above runs against a scripted `gh`.  Three things can only be
    exercised after the owner mints REA_SECRETS_WRITE_PAT and approves one
    deployment: that a fine-grained PAT with Secrets: Read and write really
    does authorise the environment secrets endpoints; that real `gh secret set`
    accepts the value on stdin for an environment secret; and that the live
    renew-wea guard then passes.  Nothing in this file claims otherwise.
    """
    assert "gh secret set" in TOOL.read_text()
