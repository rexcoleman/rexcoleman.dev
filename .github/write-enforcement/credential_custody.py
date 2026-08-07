#!/usr/bin/env python3
"""The written credential custody rule, made mechanical.

A credential nobody wrote down lapses silently.  That already happened in this
repository and it cost the cycle an outage.  This checker exists so that the
custody record cannot drift away from the workflows that actually consume the
credentials.

The required set is DERIVED, never declared.  Every job in
`.github/workflows/*.yml` that declares an `environment:` is scanned for
`secrets.NAME` references, and each (NAME, environment) pair must have a
custody row.  A new environment secret therefore fails this checker the moment
it is referenced, without anyone remembering to update a list.

`secrets.NAME` inside a job with NO environment is a repository-level secret
usage.  This repository holds no repository-level secrets -- measured
2026-08-07, `gh secret list --repo rexcoleman/rexcoleman.dev` returned nothing
-- so such a reference is itself reported (CUSTODY_SECRET_UNSCOPED).  The one
documented exception is a `workflow_call` callee: its `secrets.` references
name the CALLER's credentials, held in another repository, and are excluded.

What each row must answer:

  owner                      who holds it
  location                   exact environment and its protection rules
  expiry                     the real expiry, or a typed marker saying the
                             expiry is genuinely unreadable.  Never blank,
                             never invented.
  reestablishing_transition  the named executable path that restores it

A credential with no re-establishing transition is a P-6 violation.  It is
recorded loudly as NONE_P6_VIOLATION rather than hidden, and strict `check`
FAILS on it -- that failure IS the open cycle-back, made mechanical.

Where the expiry is genuinely unreadable the record must compensate
STRUCTURALLY: a lapse_detection block naming an executable detector, its
cadence, and how it observes lapse BEFORE an outage.  A row that says "expiry
unknown" and stops is rejected.

Exit codes: 0 pass, 3 custody violation, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

VIOLATION_EXIT = 3
INPUT_EXIT = 2

SECRET_REFERENCE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_-]*)")

# github.token / GITHUB_TOKEN is minted per run by GitHub; nobody holds it and
# nothing re-establishes it, so it is not a custody subject.
NON_CUSTODY_SECRETS = {"GITHUB_TOKEN", "github_token"}

EXPIRY_KINDS = {
    "RECORDED",
    "NON_EXPIRING",
    "UNRECORDED_AND_UNREADABLE",
    "PENDING_PROVISION",
}
# Kinds that carry no usable date and therefore MUST be compensated
# structurally by a lapse detector.
EXPIRY_KINDS_NEEDING_DETECTION = {"UNRECORDED_AND_UNREADABLE", "PENDING_PROVISION"}

TRANSITION_STATUSES = {"REGISTERED", "OWNER_ACT_SANCTIONED", "NONE_P6_VIOLATION"}

DETECTION_FIELDS = ("detector", "cadence", "how_it_detects")

CUSTODY_ROW_MISSING = "CUSTODY_ROW_MISSING"
CUSTODY_ROW_INCOMPLETE = "CUSTODY_ROW_INCOMPLETE"
CUSTODY_EXPIRY_UNTYPED = "CUSTODY_EXPIRY_UNTYPED"
CUSTODY_LAPSE_DETECTION_MISSING = "CUSTODY_LAPSE_DETECTION_MISSING"
CUSTODY_TRANSITION_MISSING = "CUSTODY_TRANSITION_MISSING"
CUSTODY_TRANSITION_INCOMPLETE = "CUSTODY_TRANSITION_INCOMPLETE"
CUSTODY_TRANSITION_DANGLING = "CUSTODY_TRANSITION_DANGLING"
CUSTODY_TRANSITION_STATUS_UNRECOGNISED = "CUSTODY_TRANSITION_STATUS_UNRECOGNISED"
CUSTODY_SECRET_UNSCOPED = "CUSTODY_SECRET_UNSCOPED"
CUSTODY_DECLARED_OPEN_BUDGET_EXCEEDED = "CUSTODY_DECLARED_OPEN_BUDGET_EXCEEDED"


def triggers(document):
    # PyYAML resolves the bare key `on` to the boolean True.
    if isinstance(document, dict):
        if True in document:
            return document[True]
        return document.get("on")
    return None


def is_reusable_callee(document) -> bool:
    on = triggers(document)
    if isinstance(on, dict):
        return "workflow_call" in on
    if isinstance(on, list):
        return "workflow_call" in on
    return on == "workflow_call"


def secret_names(node) -> set:
    """Every `secrets.NAME` appearing anywhere under this YAML subtree."""
    text = json.dumps(node, default=str)
    return {
        name for name in SECRET_REFERENCE.findall(text)
        if name not in NON_CUSTODY_SECRETS
    }


def required_credentials(workflow_dir: Path):
    """Derive (credential_id, provenance) from the workflows themselves."""
    required = {}
    unscoped = []
    for path in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
        document = yaml.safe_load(path.read_text())
        if not isinstance(document, dict):
            continue
        callee = is_reusable_callee(document)
        for job_id, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            environment = job.get("environment")
            if isinstance(environment, dict):
                environment = environment.get("name")
            for name in sorted(secret_names(job)):
                where = f"{path.name}:{job_id}"
                if environment:
                    required[f"{name}@{environment}"] = where
                elif not callee:
                    unscoped.append((name, where))
    return required, unscoped


def text_of(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def check_detection(block, label, credential_id, violations):
    if not isinstance(block, dict):
        violations.append(
            (CUSTODY_LAPSE_DETECTION_MISSING, credential_id,
             f"{label} is absent; an unreadable or unset expiry must be "
             "compensated structurally by a named detector")
        )
        return
    missing = [field for field in DETECTION_FIELDS if not text_of(block.get(field))]
    if missing:
        violations.append(
            (CUSTODY_LAPSE_DETECTION_MISSING, credential_id,
             f"{label} is missing {', '.join(missing)}")
        )


def check_row(row, root: Path, violations, declared_open):
    credential_id = text_of(row.get("credential_id")) or "<unnamed row>"

    for field in ("owner", "secret_name"):
        if not text_of(row.get(field)):
            violations.append(
                (CUSTODY_ROW_INCOMPLETE, credential_id, f"{field} is empty")
            )
    location = row.get("location")
    if not isinstance(location, dict) or not text_of(location.get("environment")):
        violations.append(
            (CUSTODY_ROW_INCOMPLETE, credential_id,
             "location.environment is empty; custody must name the exact scope")
        )

    expiry = row.get("expiry")
    kind = text_of(expiry.get("kind")) if isinstance(expiry, dict) else ""
    if kind not in EXPIRY_KINDS:
        violations.append(
            (CUSTODY_EXPIRY_UNTYPED, credential_id,
             f"expiry.kind {kind or '<absent>'!r} is not one of "
             f"{sorted(EXPIRY_KINDS)}; a blank or invented expiry is exactly "
             "the silent-lapse failure this record exists to prevent")
        )
    elif not text_of(expiry.get("reason")):
        violations.append(
            (CUSTODY_ROW_INCOMPLETE, credential_id, "expiry.reason is empty")
        )
    elif kind == "RECORDED":
        try:
            dt.date.fromisoformat(text_of(expiry.get("value"))[:10])
        except ValueError:
            violations.append(
                (CUSTODY_EXPIRY_UNTYPED, credential_id,
                 "expiry.kind is RECORDED but expiry.value is not an ISO date")
            )
    if kind in EXPIRY_KINDS_NEEDING_DETECTION:
        check_detection(row.get("lapse_detection"), "lapse_detection",
                        credential_id, violations)

    transition = row.get("reestablishing_transition")
    if not isinstance(transition, dict) or not transition:
        violations.append(
            (CUSTODY_TRANSITION_MISSING, credential_id,
             "no reestablishing_transition; a credential with no registered "
             "re-establishing path is itself a P-6 violation")
        )
        return
    status = text_of(transition.get("status"))
    if status not in TRANSITION_STATUSES:
        violations.append(
            (CUSTODY_TRANSITION_STATUS_UNRECOGNISED, credential_id,
             f"{status or '<absent>'!r} is not one of {sorted(TRANSITION_STATUSES)}")
        )
        return

    if status == "REGISTERED":
        target = text_of(transition.get("path"))
        if not target:
            violations.append(
                (CUSTODY_TRANSITION_INCOMPLETE, credential_id,
                 "REGISTERED transition names no path")
            )
        elif not (root / target).exists():
            violations.append(
                (CUSTODY_TRANSITION_DANGLING, credential_id,
                 f"REGISTERED transition names {target}, which does not exist; "
                 "an unreachable transition is not a transition")
            )
        if not text_of(transition.get("invocation")):
            violations.append(
                (CUSTODY_TRANSITION_INCOMPLETE, credential_id,
                 "REGISTERED transition names no invocation")
            )
    elif status == "OWNER_ACT_SANCTIONED":
        if not text_of(transition.get("sanctioned_by")):
            violations.append(
                (CUSTODY_TRANSITION_INCOMPLETE, credential_id,
                 "OWNER_ACT_SANCTIONED without sanctioned_by; an owner act is "
                 "only acceptable when a ruling explicitly sanctions it")
            )
        runbook = text_of(transition.get("runbook"))
        if not runbook:
            violations.append(
                (CUSTODY_TRANSITION_INCOMPLETE, credential_id,
                 "OWNER_ACT_SANCTIONED names no runbook")
            )
        elif not (root / runbook).exists():
            violations.append(
                (CUSTODY_TRANSITION_DANGLING, credential_id,
                 f"OWNER_ACT_SANCTIONED names runbook {runbook}, which does not exist")
            )
        if not transition.get("owner_acts"):
            violations.append(
                (CUSTODY_TRANSITION_INCOMPLETE, credential_id,
                 "OWNER_ACT_SANCTIONED enumerates no owner_acts")
            )
        check_detection(row.get("lapse_detection"), "lapse_detection",
                        credential_id, violations)
    else:  # NONE_P6_VIOLATION
        complete = True
        if not text_of(transition.get("open_cycle_back")):
            complete = False
            violations.append(
                (CUSTODY_TRANSITION_INCOMPLETE, credential_id,
                 "NONE_P6_VIOLATION without open_cycle_back; an acknowledged "
                 "gap must name the cycle-back that closes it")
            )
        detection = transition.get("compensating_lapse_detection")
        if not isinstance(detection, dict) or any(
            not text_of(detection.get(field)) for field in DETECTION_FIELDS
        ):
            complete = False
            check_detection(detection, "compensating_lapse_detection",
                            credential_id, violations)
        declared_open.append((credential_id, complete))


def check(args) -> int:
    root = args.root.resolve()
    record_path = args.record
    try:
        record = json.loads(record_path.read_text())
    except (OSError, ValueError) as exc:
        print(f"REFUSED CUSTODY_RECORD_UNREADABLE: {record_path}: {exc}", file=sys.stderr)
        return INPUT_EXIT

    rows = record.get("credentials")
    if not isinstance(rows, list):
        print("REFUSED CUSTODY_RECORD_UNREADABLE: no credentials list", file=sys.stderr)
        return INPUT_EXIT

    violations = []
    declared_open = []
    known = set()
    for row in rows:
        if isinstance(row, dict):
            known.add(text_of(row.get("credential_id")))
            check_row(row, root, violations, declared_open)

    required, unscoped = required_credentials(args.workflows)
    for credential_id, where in sorted(required.items()):
        if credential_id not in known:
            violations.append(
                (CUSTODY_ROW_MISSING, credential_id,
                 f"consumed at {where} with no custody row; every credential "
                 "the enforcement chain consumes must be written down")
            )
    for name, where in sorted(unscoped):
        violations.append(
            (CUSTODY_SECRET_UNSCOPED, name,
             f"referenced at {where} by a job that declares no environment; "
             "this repository holds no repository-level secrets")
        )

    hard = list(violations)
    for credential_id, complete in declared_open:
        if not args.allow_declared_open:
            hard.append(
                (CUSTODY_TRANSITION_MISSING, credential_id,
                 "no registered re-establishing transition (declared "
                 "NONE_P6_VIOLATION); this is an open P-6 instance")
            )
        elif complete:
            print(
                f"P6_OPEN {credential_id}: acknowledged, compensated, "
                "and waived only because --allow-declared-open was passed"
            )
    if args.allow_declared_open and len(declared_open) > args.max_declared_open:
        hard.append(
            (CUSTODY_DECLARED_OPEN_BUDGET_EXCEEDED, "<record>",
             f"{len(declared_open)} rows declare NONE_P6_VIOLATION, budget is "
             f"{args.max_declared_open}; the waiver may not become the default")
        )

    for code, subject, detail in hard:
        print(f"REFUSED {code} {subject}: {detail}", file=sys.stderr)
    if hard:
        print(
            f"CUSTODY_CHECK_FAIL violations={len(hard)} "
            f"rows={len(rows)} required={len(required)}",
            file=sys.stderr,
        )
        return VIOLATION_EXIT
    print(
        f"CUSTODY_CHECK_PASS rows={len(rows)} required={len(required)} "
        f"declared_open={len(declared_open)}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    here = Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    checker = sub.add_parser("check")
    checker.add_argument("--root", type=Path, default=here.parents[2])
    checker.add_argument("--record", type=Path, default=here.parent / "credential_custody.json")
    checker.add_argument("--workflows", type=Path, default=here.parents[1] / "workflows")
    checker.add_argument(
        "--allow-declared-open",
        action="store_true",
        help="downgrade fully-documented NONE_P6_VIOLATION rows to a loud "
             "warning; still fails on missing rows, incomplete declarations, "
             "dangling paths, and on more open rows than --max-declared-open",
    )
    checker.add_argument("--max-declared-open", type=int, default=2)
    checker.set_defaults(handler=check)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
