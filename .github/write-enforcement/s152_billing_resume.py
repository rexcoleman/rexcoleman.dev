#!/usr/bin/env python3
"""Checked, resumable owner boundary for the GitHub billing suspension.

First invocation records that the exact browser gate was presented and prints
the account Billing & plans URL.  It performs no remote mutation.  After the
owner resolves billing, the same command row is run again: it reruns only the
two exact failed artifact-integrity runs for govML PR 92, waits for the exact
required check at commit cb165ab, and merges only that PR if green.  Any stale
identity, non-billing failure, failed retry, or malformed state refuses.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


HOST = "gios-dev"
MARKER = "rea-s152-billing-resume-checked-v1"
REPOSITORY = "rexcoleman/govML"
PR_NUMBER = 92
HEAD_SHA = "cb165ab643cca3a6759058e48bdeb6afdae1146c"
RUN_IDS = (31556353513, 31556363206)
REQUIRED_CHECK = "artifact-integrity-exact-commit"
BILLING_MESSAGE = (
    "The job was not started because recent account payments have failed or "
    "your spending limit needs to be increased. Please check the 'Billing & "
    "plans' section in your settings"
)
BILLING_URL = "https://github.com/settings/billing"
STATE = Path("/home/azureuser/.local/state/rea_enforcement/s152_billing_resume.json")


class Refusal(RuntimeError):
    pass


def command(argv):
    completed = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False,
    )
    if completed.returncode:
        raise Refusal("COMMAND_REFUSED exit=%s subject=%s" % (
            completed.returncode, " ".join(argv[:4])
        ))
    return completed.stdout


def api(path):
    raw = command(["gh", "api", path])
    try:
        return json.loads(raw)
    except ValueError:
        raise Refusal("API_MALFORMED path=%s" % path) from None


def exact_pr():
    value = api("repos/%s/pulls/%s" % (REPOSITORY, PR_NUMBER))
    if (
        value.get("head", {}).get("sha") != HEAD_SHA
        or value.get("base", {}).get("ref") != "main"
        or value.get("draft") is not False
        or value.get("state") not in {"open", "closed"}
    ):
        raise Refusal("GOVML_PR_IDENTITY_REFUSED")
    if value.get("state") == "closed" and value.get("merged") is not True:
        raise Refusal("GOVML_PR_CLOSED_UNMERGED")
    return value


def billing_annotation(run_id):
    value = api("repos/%s/actions/runs/%s/jobs" % (REPOSITORY, run_id))
    jobs = value.get("jobs") if isinstance(value, dict) else None
    if not isinstance(jobs, list) or len(jobs) != 1:
        raise Refusal("BILLING_RUN_JOB_IDENTITY_REFUSED run=%s" % run_id)
    job = jobs[0]
    if (
        job.get("name") != REQUIRED_CHECK
        or job.get("head_sha") not in {None, HEAD_SHA}
        or job.get("conclusion") != "failure"
        or job.get("steps") not in (None, [])
        or not isinstance(job.get("id"), int)
    ):
        raise Refusal("BILLING_RUN_IDENTITY_REFUSED run=%s" % run_id)
    annotations = api(
        "repos/%s/check-runs/%s/annotations" % (REPOSITORY, job["id"])
    )
    messages = [row.get("message") for row in annotations if isinstance(row, dict)] \
        if isinstance(annotations, list) else []
    if messages != [BILLING_MESSAGE]:
        raise Refusal("NON_BILLING_CHECK_FAILURE run=%s" % run_id)


def write_presented_state():
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.exists() or STATE.is_symlink():
        raise Refusal("BILLING_STATE_UNEXPECTED")
    temporary = STATE.with_name(".%s.%s" % (STATE.name, os.getpid()))
    payload = {
        "schema_version": "rea.s152.billing-resume.v1",
        "phase": "BILLING_GATE_PRESENTED",
        "repository": REPOSITORY,
        "pr": PR_NUMBER,
        "head_sha": HEAD_SHA,
        "failed_runs": list(RUN_IDS),
    }
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(STATE))
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_state():
    if not STATE.is_file() or STATE.is_symlink():
        raise Refusal("BILLING_STATE_ABSENT_OR_UNSAFE")
    try:
        value = json.loads(STATE.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise Refusal("BILLING_STATE_MALFORMED") from None
    if value != {
        "schema_version": "rea.s152.billing-resume.v1",
        "phase": "BILLING_GATE_PRESENTED",
        "repository": REPOSITORY,
        "pr": PR_NUMBER,
        "head_sha": HEAD_SHA,
        "failed_runs": list(RUN_IDS),
    }:
        raise Refusal("BILLING_STATE_MISMATCH")


def check_state():
    value = api("repos/%s/commits/%s/check-runs" % (REPOSITORY, HEAD_SHA))
    rows = value.get("check_runs") if isinstance(value, dict) else None
    matches = [row for row in rows or [] if row.get("name") == REQUIRED_CHECK]
    successes = [row for row in matches if row.get("status") == "completed"
                 and row.get("conclusion") == "success"]
    return len(successes) == 1


def rerun_and_wait():
    for run_id in RUN_IDS:
        command(["gh", "run", "rerun", str(run_id), "--repo", REPOSITORY, "--failed"])
    for _attempt in range(120):
        if check_state():
            return
        time.sleep(5)
    raise Refusal("BILLING_RETRY_TIMEOUT")


def merge_pr():
    command([
        "gh", "pr", "merge", str(PR_NUMBER), "--repo", REPOSITORY,
        "--merge", "--delete-branch=false",
    ])
    value = exact_pr()
    if value.get("merged") is not True:
        raise Refusal("GOVML_PR_MERGE_POSTCHECK_REFUSED")


def runtime_ready():
    if os.environ.get("REA_S152_CHECKED_WRAPPER") != MARKER:
        raise Refusal("CHECKED_WRAPPER_REQUIRED")
    if socket.gethostname().split(".", 1)[0] != HOST:
        raise Refusal("HOST_REFUSED")
    if os.geteuid() == 0 or not sys.stdin.isatty():
        raise Refusal("OWNER_RUNTIME_REFUSED")
    return exact_pr()


def preflight():
    value = runtime_ready()
    if value.get("merged") is True:
        raise Refusal("GOVML_PR_ALREADY_MERGED")
    for run_id in RUN_IDS:
        billing_annotation(run_id)
    print(
        "PREFLIGHT_PASS host=gios-dev govml_pr=92 head=%s billing_failure=exact "
        "state_mutation=false remote_mutation=false" % HEAD_SHA
    )
    print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
    return 0


def run():
    value = runtime_ready()
    if value.get("merged") is True:
        print("BILLING_RECOVERY_PASS govml_pr=92 already_merged=true")
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
        return 0
    for run_id in RUN_IDS:
        billing_annotation(run_id)
    if not STATE.exists():
        write_presented_state()
        print("REFUSE(S152_BILLING_RESUME): BILLING_GATE_PRESENTED")
        print("Open this exact page in the gios-dev VS Code browser, repair the "
              "failed payment or spending limit, then run this SAME row again:")
        print(BILLING_URL)
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
        return 2
    read_state()
    rerun_and_wait()
    merge_pr()
    print("BILLING_RECOVERY_PASS govml_pr=92 merged=true exact_check=success")
    print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)
    try:
        return preflight() if args.preflight else run()
    except Refusal as exc:
        print("REFUSE(S152_BILLING_RESUME): %s" % exc, file=sys.stderr)
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false", file=sys.stderr)
        return 2
    except Exception as exc:
        print("REFUSE(S152_BILLING_RESUME): UNEXPECTED_%s" % type(exc).__name__,
              file=sys.stderr)
        print("SAFE_TO_PASTE_BACK=true secret_bytes_printed=false", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
