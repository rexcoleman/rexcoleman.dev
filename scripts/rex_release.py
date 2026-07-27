#!/usr/bin/env python3
"""BLG-09/10 release boundary CLI.

`push` reaches only a non-main PR branch and returns PRE_MAIN_BOUNDARY.
It can never claim that protected main or deployment has completed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rex_hybrid_mount import (
    CANONICAL_REPO,
    RexHybridRefusal,
    branch_push_plan,
    build_branch_push_subject,
    build_deploy_subject,
    consume_deploy,
    deploy_plan,
    push_pr_branch,
    record_protected_main_merge,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("push", "record-main", "deploy"))
    parser.add_argument("--pr", type=int)
    args = parser.parse_args()
    try:
        if args.operation == "push":
            if args.pr is not None:
                raise RexHybridRefusal("EFFECT_PLAN_INVALID", "push:pr")
            candidate = build_branch_push_subject(CANONICAL_REPO)
            plan, target = branch_push_plan(candidate)
            receipt = push_pr_branch(
                candidate=candidate,
                effect_plan=plan,
                target=target,
            )
        elif args.operation == "record-main":
            if args.pr is None:
                raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "pr_required")
            receipt = record_protected_main_merge(args.pr)
        elif args.operation == "deploy":
            if args.pr is None:
                raise RexHybridRefusal("MAIN_RECEIPT_INVALID", "pr_required")
            main = record_protected_main_merge(args.pr)
            candidate = build_deploy_subject(Path(main["receipt_path"]))
            plan, target = deploy_plan(candidate)
            receipt = consume_deploy(
                candidate=candidate,
                effect_plan=plan,
                target=target,
            )
        else:
            raise RexHybridRefusal("UNMANAGED_PRODUCTION_ROUTE", args.operation)
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    except RexHybridRefusal as exc:
        print(str(exc), file=sys.stderr)
        return exc.raw_exit


if __name__ == "__main__":
    raise SystemExit(main())
