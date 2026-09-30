#!/usr/bin/env python3
"""CC-QL: quality-loop cleanliness gate (research_enforcement_activation s200).

WHY THIS EXISTS
---------------
`scripts/quality_loop.sh` was installed on every enrolled project and invoked by
NOTHING in the enforcement chain.  `check_all_gates.sh` only READ
`outputs/quality_loop_report.json` when that file happened to exist, and its
failure mode there was WARN.  The single stated close-blocker of the cycle --
EXPERIMENTAL_DESIGN.md 22.1 CC-QL -- was therefore enforced by nothing.

WHAT CC-QL ACTUALLY SAYS
------------------------
"A quality_loop run that returns FIX_REQUIRED, a non-zero exit, a score below
its threshold, or a skipped T3 is not clean, and its non-cleanliness is a block
on close, not a warning attached to a close."

Two exceptions and nothing else, both govML-track:
  1. the check_gate05 lock false-positive; and
  2. the disposed single-vendor semantic_review false-positive.

"An exception applies only when the failing step IS one of those two, identified
by reading the failing step itself."  And: "The exceptions are per-step, not
per-run.  A run whose only failure is check_gate05 is covered; a run that fails
check_gate05 AND something else is not, and the something else is the reason."

THE EVALUATION MODEL (per-step, never verdict-string matching)
--------------------------------------------------------------
PRIMARY -- enumerate concrete FAILING STEPS, each carrying its own identity
(category + location + detail) so a reader is never left with "fail: 1" and
nothing named:
  * gate-line FAILs from the report's gaps[]
  * semantic_review FAIL issues, read from outputs/semantic_review.json issues[]
    (the report's own key is `issues`, NOT `gaps`; reading `gaps` there is why
    this FAIL previously read as unnamed)
  * findings-audit failure
  * substitution-gate failure
  * a skipped/unavailable authoritative T3 -- CC-QL names this explicitly

DERIVED COLOURS -- action==FIX_REQUIRED, score < threshold, and the raw
check_all_gates exit are deliberately NOT treated as independent blocking
reasons.  CC-QL forbids reading the run's colour instead of its failing step,
and treating them as independent would refuse a run whose only real failure is
an excepted one (the excepted failure is itself what drags the score under the
threshold and sets FIX_REQUIRED).  They are used ONLY as a completeness
cross-check: a colour that says non-clean while zero steps were enumerated is an
UNATTRIBUTED non-cleanliness and blocks fail-closed, because a red nobody can
name is not a clean run.

CLEAN iff every enumerated failing step is excepted AND nothing is unattributed.

EXCEPTION MATCHING IS EVIDENCE-BOUND, NOT ASSUMED
-------------------------------------------------
Exception 2 requires the semantic_review FAIL to have been DISPOSED.  A
disposition is a recorded artifact -- a `disposition` field on the issue, or an
entry in outputs/ccql_dispositions.json -- never an inference from the fact that
semantic_review is single-vendor.  An undisposed semantic FAIL is a real
blocking step.  This is what keeps "a standing red hides new failures" from
recurring: a genuinely new semantic FAIL arriving inside a long-standing red is
undisposed, so it blocks.

Exit codes: 0 clean, 1 non-clean (named), 2 cannot-evaluate (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

EXIT_CLEAN = 0
EXIT_NOT_CLEAN = 1
EXIT_CANNOT_EVALUATE = 2

# The two named exceptions, and nothing else.  Identities are matched against the
# failing STEP, never against the run verdict.
EXC_GATE05 = "check_gate05_lock_false_positive"
EXC_SEMANTIC = "disposed_single_vendor_semantic_review_false_positive"


def _load_json(path):
    try:
        with open(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))
    except FileNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001 - unreadable is cannot-evaluate
        return {"__unreadable__": str(exc)}


def _argv_runs_quality_loop(argv):
    """True only if this argv is EXECUTING quality_loop.sh.

    Matching the raw command line as one string is the pgrep self-match defect
    wearing a different hat: any shell whose `-c` script body merely MENTIONS
    quality_loop.sh -- including the wrapper that invoked this gate, or a
    session running a command that names it -- would look like the loop itself
    and the gate would defer forever, which is a gate that refuses to evaluate
    anything. So match per-argv-element on the basename, and skip the body that
    follows an inline-command flag, since that body is data, not a program.
    """
    skip_next = False
    for element in argv:
        if not element:
            continue
        if skip_next:
            skip_next = False
            continue
        if element in ("-c", "-lc", "-cl", "--command"):
            skip_next = True
            continue
        if os.path.basename(element.strip()) == "quality_loop.sh":
            return True
    return False


def is_reentrant():
    """True when this gate is firing from INSIDE a quality_loop run.

    quality_loop.sh runs scripts/run_gates.sh, which reaches check_all_gates.sh,
    which sources run_gates_enforcement_block.sh -- the block that fires this
    gate.  Invoking the loop from here unguarded is therefore infinite
    recursion, and even evaluating is wrong: the report on disk mid-run is the
    previous run, which is exactly the "stale run" CC-QL's falsifier names.

    Detection is by PROCESS ANCESTRY rather than a marker exported from
    quality_loop.sh, because scripts/quality_loop.sh is a governed, manifested
    artifact and this wiring must not require editing it.  Walking the PPID
    chain is also immune to the pgrep self-match that catches a bare
    `pgrep -f quality_loop.sh` (the matcher finds its own command line).
    An explicit env marker is still honoured for callers that set one.
    """
    if os.environ.get("GOVML_QUALITY_LOOP_ACTIVE"):
        return True
    try:
        pid = os.getpid()
        for _ in range(64):  # bounded walk; never trust the chain to terminate
            try:
                with open("/proc/%d/stat" % pid, "rb") as fh:
                    stat_line = fh.read().decode("utf-8", "replace")
                ppid = int(stat_line[stat_line.rindex(")") + 2:].split()[1])
            except (OSError, ValueError, IndexError):
                return False
            if ppid <= 1 or ppid == pid:
                return False
            try:
                with open("/proc/%d/cmdline" % ppid, "rb") as fh:
                    raw = fh.read().decode("utf-8", "replace")
            except OSError:
                return False
            if _argv_runs_quality_loop(raw.split("\0")):
                return True
            pid = ppid
    except Exception:  # noqa: BLE001 - detection must never crash the gate
        return False
    return False


def _text(value):
    return value if isinstance(value, str) else ""


def _is_gate05_lock(step):
    """Exception 1: the check_gate05 lock false-positive, read from the step."""
    blob = " ".join(
        [_text(step.get("step_id")), _text(step.get("category")),
         _text(step.get("location")), _text(step.get("detail"))]
    ).lower()
    return "check_gate05" in blob and "lock" in blob


def _load_dispositions(project_dir):
    path = os.path.join(project_dir, "outputs", "ccql_dispositions.json")
    data = _load_json(path)
    if not isinstance(data, dict) or "__unreadable__" in data:
        return set()
    out = set()
    for row in data.get("disposed", []) or []:
        if isinstance(row, dict):
            kind = _text(row.get("exception"))
            ident = _text(row.get("location")) or _text(row.get("category"))
            if kind == EXC_SEMANTIC and ident:
                out.add(ident)
    return out


def _is_disposed_semantic(step, disposed_ids):
    """Exception 2: a semantic_review FAIL carrying a RECORDED disposition."""
    if step.get("source") != "semantic_review":
        return False
    if _text(step.get("disposition")).strip():
        return True
    ident = _text(step.get("location")) or _text(step.get("category"))
    return bool(ident) and ident in disposed_ids


def enumerate_failing_steps(project_dir, report):
    """PRIMARY: build the named failing-step list from every real source."""
    steps = []

    # 1. gate-line FAILs recorded by the loop itself
    for gap in report.get("gaps", []) or []:
        if not isinstance(gap, dict):
            continue
        if _text(gap.get("severity")).upper() != "FAIL":
            continue
        steps.append({
            "step_id": "gate_line",
            "source": "quality_loop_report.gaps",
            "category": _text(gap.get("classification")) or "gate_fail",
            "location": _text(gap.get("location")) or "check_all_gates",
            "detail": _text(gap.get("message")),
        })

    # 2. semantic_review FAIL issues -- read issues[], the key that exists
    if _text(report.get("semantic_review")).upper() == "FAIL":
        sem_path = os.path.join(project_dir, "outputs", "semantic_review.json")
        sem = _load_json(sem_path)
        named = 0
        if isinstance(sem, dict) and "__unreadable__" not in sem:
            for issue in sem.get("issues", []) or []:
                if not isinstance(issue, dict):
                    continue
                if _text(issue.get("severity")).upper() != "FAIL":
                    continue
                named += 1
                steps.append({
                    "step_id": "semantic_review",
                    "source": "semantic_review",
                    "category": _text(issue.get("category")) or "semantic_fail",
                    "location": _text(issue.get("location")),
                    "detail": _text(issue.get("detail")),
                    "disposition": _text(issue.get("disposition")),
                })
        if named == 0:
            # The summary says FAIL but no issue could be named.  That is not a
            # pass -- it is an unnameable red, which fails closed.
            steps.append({
                "step_id": "semantic_review",
                "source": "semantic_review",
                "category": "unnameable_semantic_fail",
                "location": sem_path,
                "detail": ("semantic_review reports FAIL but no FAIL issue could be "
                           "read from issues[]; a red that cannot be named is not clean"),
            })

    # 3. findings audit
    try:
        fa_exit = int(report.get("findings_audit_raw_exit") or 0)
    except (TypeError, ValueError):
        fa_exit = 0
    if fa_exit != 0:
        steps.append({
            "step_id": "findings_audit",
            "source": "quality_loop_report",
            "category": "findings_audit",
            "location": "gen_findings_audit",
            "detail": "findings audit raw exit %s (status=%s, critical=%s)" % (
                fa_exit, report.get("findings_audit_status"),
                report.get("findings_audit_critical")),
        })

    # 4. substitution gate, when the loop recorded one
    try:
        sub_exit = int(report.get("substitution_raw_exit") or 0)
    except (TypeError, ValueError):
        sub_exit = 0
    if sub_exit != 0:
        steps.append({
            "step_id": "substitution_gate",
            "source": "quality_loop_report",
            "category": "operational_definition_substitution",
            "location": "substitution gate",
            "detail": "substitution gate raw exit %s" % sub_exit,
        })

    # 5. authoritative T3 -- CC-QL names a skipped T3 as non-clean outright, and
    #    a skipped T3 is not one of the two exceptions, so it always blocks.
    t3_status = _text(report.get("t3_status"))
    t3_composite = report.get("t3_composite")
    if t3_status and t3_status.lower() not in ("ok", "pass", "complete", "scored"):
        steps.append({
            "step_id": "t3_authoritative",
            "source": "quality_loop_report",
            "category": "t3_not_scored",
            "location": "authoritative T3",
            "detail": "T3 status=%s composite=%s; CC-QL names a skipped T3 as "
                      "not clean and it is not one of the two exceptions" % (
                          t3_status, t3_composite if t3_composite is not None
                          else "unavailable"),
        })
    elif t3_composite is None:
        steps.append({
            "step_id": "t3_authoritative",
            "source": "quality_loop_report",
            "category": "t3_not_scored",
            "location": "authoritative T3",
            "detail": "T3 composite unavailable (status=%s)" % (t3_status or "absent"),
        })

    return steps


def derived_colours(report):
    """DERIVED: run-level colours, used only as a completeness cross-check."""
    colours = []
    action = _text(report.get("action")).upper()
    if action and action != "PASS":
        colours.append("action=%s" % action)
    try:
        score = float(report.get("score"))
        threshold = float(report.get("threshold"))
        if score < threshold:
            colours.append("score=%s below threshold=%s" % (score, threshold))
    except (TypeError, ValueError):
        colours.append("score/threshold unreadable")
    try:
        raw = int(report.get("check_all_gates_raw_exit") or 0)
        if raw != 0:
            colours.append("check_all_gates_raw_exit=%s" % raw)
    except (TypeError, ValueError):
        colours.append("check_all_gates_raw_exit unreadable")
    return colours


def evaluate(project_dir, report_path):
    report = _load_json(report_path)
    if report is None:
        return {
            "gate": "quality_loop_cleanliness",
            "verdict": "CANNOT_EVALUATE",
            "clean": False,
            "exit": EXIT_CANNOT_EVALUATE,
            "reason": "quality_loop_report.json absent at %s; CC-QL cannot be "
                      "asserted from a run that did not happen (non-evaluation "
                      "is never consent)" % report_path,
            "blocking_steps": [],
            "excepted_steps": [],
            "derived_colours": [],
        }
    if not isinstance(report, dict) or "__unreadable__" in report:
        return {
            "gate": "quality_loop_cleanliness",
            "verdict": "CANNOT_EVALUATE",
            "clean": False,
            "exit": EXIT_CANNOT_EVALUATE,
            "reason": "quality_loop_report.json unreadable or not an object",
            "blocking_steps": [],
            "excepted_steps": [],
            "derived_colours": [],
        }

    disposed_ids = _load_dispositions(project_dir)
    steps = enumerate_failing_steps(project_dir, report)
    colours = derived_colours(report)

    blocking, excepted = [], []
    for step in steps:
        if _is_gate05_lock(step):
            step = dict(step, exception=EXC_GATE05)
            excepted.append(step)
        elif _is_disposed_semantic(step, disposed_ids):
            step = dict(step, exception=EXC_SEMANTIC)
            excepted.append(step)
        else:
            blocking.append(step)

    unattributed = bool(colours) and not steps
    if unattributed:
        blocking.append({
            "step_id": "unattributed_non_cleanliness",
            "source": "quality_loop_report",
            "category": "unattributed",
            "location": report_path,
            "detail": "the run reports non-clean colours (%s) but no failing "
                      "step could be enumerated; an unnameable red fails closed"
                      % "; ".join(colours),
        })

    clean = not blocking
    result = {
        "gate": "quality_loop_cleanliness",
        "close_condition": "EXPERIMENTAL_DESIGN.md 22.1 CC-QL",
        "verdict": "CLEAN" if clean else "NOT_CLEAN",
        "clean": clean,
        "exit": EXIT_CLEAN if clean else EXIT_NOT_CLEAN,
        "report": report_path,
        "score": report.get("score"),
        "threshold": report.get("threshold"),
        "action": report.get("action"),
        "t3_status": report.get("t3_status"),
        "t3_composite": report.get("t3_composite"),
        "blocking_steps": blocking,
        "excepted_steps": excepted,
        "derived_colours": colours,
    }
    if clean and excepted:
        result["reason"] = ("every failing step is one of the two named CC-QL "
                            "exceptions; run is clean per-step")
    elif clean:
        result["reason"] = "no failing step enumerated and no unattributed colour"
    else:
        result["reason"] = ("%d blocking failing step(s) outside the two named "
                            "CC-QL exceptions" % len(blocking))
    return result


def render(result, stream=sys.stdout):
    print("CC-QL quality-loop cleanliness: %s" % result["verdict"], file=stream)
    print("  close condition: %s" % result.get("close_condition", "CC-QL"), file=stream)
    if result.get("score") is not None:
        print("  score=%s threshold=%s action=%s t3=%s/%s" % (
            result.get("score"), result.get("threshold"), result.get("action"),
            result.get("t3_status"), result.get("t3_composite")), file=stream)
    for step in result.get("excepted_steps", []):
        print("  EXCEPTED [%s] %s :: %s" % (
            step.get("exception"), step.get("category"), step.get("location")),
            file=stream)
    for step in result.get("blocking_steps", []):
        # Name the blocking item.  Never "fail: 1" with nothing named.
        print("  BLOCKING step_id=%s category=%s" % (
            step.get("step_id"), step.get("category")), file=stream)
        print("      location: %s" % (step.get("location") or "(none recorded)"),
              file=stream)
        detail = (step.get("detail") or "").strip().replace("\n", " ")
        if detail:
            print("      detail: %s" % detail, file=stream)
    if result.get("derived_colours"):
        print("  derived colours (cross-check only, never the verdict): %s" %
              "; ".join(result["derived_colours"]), file=stream)
    print("  reason: %s" % result.get("reason", ""), file=stream)


# ───────────────────────── self-test ─────────────────────────
# A gate that refuses everything is as broken as one that refuses nothing, so
# the self-test carries BOTH directions and, critically, the per-step
# distinction CC-QL turns on: excepted-only is clean, excepted PLUS anything
# else is not, and the something-else is named as the reason.

_CLEAN_REPORT = {
    "score": 8.6, "threshold": 8.0, "action": "PASS", "semantic_review": "PASS",
    "findings_audit_raw_exit": 0, "check_all_gates_raw_exit": 0,
    "t3_status": "ok", "t3_composite": 8.2, "gaps": [],
}


def _write(project, report, semantic=None, dispositions=None):
    os.makedirs(os.path.join(project, "outputs"), exist_ok=True)
    with open(os.path.join(project, "outputs", "quality_loop_report.json"), "w") as fh:
        json.dump(report, fh)
    if semantic is not None:
        with open(os.path.join(project, "outputs", "semantic_review.json"), "w") as fh:
            json.dump(semantic, fh)
    if dispositions is not None:
        with open(os.path.join(project, "outputs", "ccql_dispositions.json"), "w") as fh:
            json.dump(dispositions, fh)
    return os.path.join(project, "outputs", "quality_loop_report.json")


def self_test():
    cases = []
    root = tempfile.mkdtemp(prefix="ccql_selftest_")
    try:
        # 1. genuinely clean run -> CLEAN (the honest positive control)
        p = os.path.join(root, "clean"); path = _write(p, dict(_CLEAN_REPORT))
        r = evaluate(p, path)
        cases.append(("clean run is CLEAN", r["exit"] == EXIT_CLEAN, r))

        # 2. excepted-only (check_gate05 lock) -> CLEAN, per-step
        rep = dict(_CLEAN_REPORT, score=7.9, action="FIX_REQUIRED",
                   check_all_gates_raw_exit=1,
                   gaps=[{"severity": "FAIL", "classification": "gate",
                          "message": "check_gate05: lock file present, false positive"}])
        p = os.path.join(root, "exc_only"); path = _write(p, rep)
        r = evaluate(p, path)
        cases.append(("excepted-only (check_gate05 lock) is CLEAN",
                      r["exit"] == EXIT_CLEAN and len(r["excepted_steps"]) == 1, r))

        # 3. excepted PLUS something else -> NOT_CLEAN, and the something else
        #    is the named reason.  This is the distinction CC-QL turns on.
        rep = dict(_CLEAN_REPORT, score=7.5, action="FIX_REQUIRED",
                   check_all_gates_raw_exit=1,
                   gaps=[{"severity": "FAIL", "classification": "gate",
                          "message": "check_gate05: lock file present, false positive"},
                         {"severity": "FAIL", "classification": "gate",
                          "message": "baseline comparison absent"}])
        p = os.path.join(root, "exc_plus"); path = _write(p, rep)
        r = evaluate(p, path)
        ok = (r["exit"] == EXIT_NOT_CLEAN and len(r["excepted_steps"]) == 1
              and len(r["blocking_steps"]) == 1
              and "baseline comparison absent" in r["blocking_steps"][0]["detail"])
        cases.append(("excepted PLUS other is NOT_CLEAN and names the other", ok, r))

        # 4. undisposed semantic FAIL -> NOT_CLEAN, named from issues[]
        rep = dict(_CLEAN_REPORT, score=7.9, action="FIX_REQUIRED",
                   semantic_review="FAIL", check_all_gates_raw_exit=1)
        sem = {"status": "FAIL", "fail": 1, "issues": [
            {"category": "circular_eval", "severity": "FAIL",
             "location": "ED 0.1", "detail": "seed freeze not enforced"}]}
        p = os.path.join(root, "sem_undisposed"); path = _write(p, rep, semantic=sem)
        r = evaluate(p, path)
        ok = (r["exit"] == EXIT_NOT_CLEAN and len(r["blocking_steps"]) == 1
              and r["blocking_steps"][0]["category"] == "circular_eval")
        cases.append(("undisposed semantic FAIL is NOT_CLEAN and named", ok, r))

        # 5. the SAME semantic FAIL, recorded as disposed -> CLEAN
        p = os.path.join(root, "sem_disposed")
        path = _write(p, rep, semantic=sem, dispositions={"disposed": [
            {"exception": EXC_SEMANTIC, "location": "ED 0.1"}]})
        r = evaluate(p, path)
        cases.append(("recorded single-vendor disposition is CLEAN",
                      r["exit"] == EXIT_CLEAN and len(r["excepted_steps"]) == 1, r))

        # 6. skipped T3 -> NOT_CLEAN (CC-QL names it; never excepted)
        rep = dict(_CLEAN_REPORT, t3_status="skipped_structural_fails",
                   t3_composite=None, score=7.9, action="FIX_REQUIRED")
        p = os.path.join(root, "t3"); path = _write(p, rep)
        r = evaluate(p, path)
        ok = r["exit"] == EXIT_NOT_CLEAN and any(
            s["step_id"] == "t3_authoritative" for s in r["blocking_steps"])
        cases.append(("skipped T3 is NOT_CLEAN", ok, r))

        # 7. non-clean colour with no enumerable step -> NOT_CLEAN, unattributed
        rep = dict(_CLEAN_REPORT, score=7.2, action="FIX_REQUIRED")
        p = os.path.join(root, "unattr"); path = _write(p, rep)
        r = evaluate(p, path)
        ok = r["exit"] == EXIT_NOT_CLEAN and any(
            s["step_id"] == "unattributed_non_cleanliness" for s in r["blocking_steps"])
        cases.append(("unattributed non-clean colour fails closed", ok, r))

        # 9/10. re-entrancy must discriminate. Matching the raw command line
        #       as one string made a shell whose -c body merely MENTIONED
        #       quality_loop.sh look like the loop, so the gate deferred on a
        #       normal invocation and evaluated nothing -- a gate that refuses
        #       to judge is as broken as one that judges everything clean.
        cases.append(("re-entrancy detects a real quality_loop argv",
                      _argv_runs_quality_loop(
                          ["/bin/bash", "/p/scripts/quality_loop.sh"]), None))
        cases.append(("re-entrancy ignores a -c body that merely names it",
                      not _argv_runs_quality_loop(
                          ["bash", "-c", "echo running quality_loop.sh"]), None))

        # 8. absent report -> CANNOT_EVALUATE (never a silent pass)
        p = os.path.join(root, "absent"); os.makedirs(p, exist_ok=True)
        r = evaluate(p, os.path.join(p, "outputs", "quality_loop_report.json"))
        cases.append(("absent report is CANNOT_EVALUATE",
                      r["exit"] == EXIT_CANNOT_EVALUATE, r))
    finally:
        shutil.rmtree(root, ignore_errors=True)

    failed = 0
    for name, ok, _r in cases:
        print("  %s  %s" % ("PASS" if ok else "FAIL", name))
        if not ok:
            failed += 1
    print("CC-QL self-test: %d/%d passed" % (len(cases) - failed, len(cases)))
    return 0 if failed == 0 else 1


def main():
    ap = argparse.ArgumentParser(description="CC-QL quality-loop cleanliness gate")
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--report", default=None)
    ap.add_argument("--emit", default=None,
                    help="path to write the machine-readable verdict")
    ap.add_argument("--autorun", action="store_true",
                    help="invoke quality_loop.sh when no report exists")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    project = os.path.abspath(args.project_dir)
    report_path = args.report or os.path.join(
        project, "outputs", "quality_loop_report.json")

    if is_reentrant():
        # The owning quality_loop run holds the verdict. Stepping aside is not a
        # pass granted to a dirty loop: the OUTER invocation of this same gate,
        # after the loop finishes, is the one that decides and can still block.
        print("CC-QL: DEFERRED (re-entrant -- firing from inside a quality_loop "
              "run; the owning run holds the verdict)")
        return EXIT_CLEAN

    autorun_note = None
    if args.autorun and not os.path.exists(report_path):
        loop = os.path.join(project, "scripts", "quality_loop.sh")
        if os.path.exists(loop) and not os.environ.get("GOVML_QUALITY_LOOP_ACTIVE"):
            env = dict(os.environ)
            env["GOVML_QUALITY_LOOP_ACTIVE"] = "1"
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env.setdefault("TMPDIR", "/tmp")
            print("  CC-QL: no quality_loop report present -- invoking the loop "
                  "(this is the invocation the chain previously lacked)")
            proc = subprocess.run(["bash", loop], cwd=project, env=env)
            rc = proc.returncode
            autorun_note = "quality_loop.sh autorun raw_exit=%s" % rc
            print("  CC-QL: %s" % autorun_note)
        else:
            autorun_note = "autorun unavailable (loop absent or re-entrant)"

    result = evaluate(project, report_path)
    if autorun_note:
        result["autorun"] = autorun_note
    render(result)
    if args.json:
        print(json.dumps(result, indent=2))

    emit = args.emit or os.path.join(project, "outputs", "quality_loop_cleanliness.json")
    try:
        os.makedirs(os.path.dirname(emit), exist_ok=True)
        with open(emit, "w") as fh:
            json.dump(result, fh, indent=2)
            fh.write("\n")
        print("  emitted: %s" % emit)
    except OSError as exc:
        print("  WARN: could not emit verdict to %s (%s)" % (emit, exc))

    return result["exit"]


if __name__ == "__main__":
    sys.exit(main())
