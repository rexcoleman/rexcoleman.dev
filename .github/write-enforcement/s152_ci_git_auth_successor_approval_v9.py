#!/usr/bin/env python3
"""Checked s152 owner arc for the exact-full-SHA CI Git-auth successor."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SOURCE = Path(__file__).with_name("s152_ci_git_auth_successor_approval_v8.py")
SPEC = importlib.util.spec_from_file_location("s152_successor_v9_base", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("V9_BASE_IMPORT_REFUSED")
V8 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V8)
BASE = V8.BASE

BASE.MARKER = "rea-s152-ci-git-auth-successor-approval-v9"
BASE.REVIEW_RUN_ID = 31612726051
BASE.REVIEW_JOB_ID = 94167879518
BASE.REVIEW_WORKFLOW_SHA = "6bb0a49a347897523b3b50a8bcae9b406192d325"
BASE.MANIFEST_PR = 94
BASE.MANIFEST_HEAD = "8bc4c88a3d43c5f0a96b49762602a4db44e09ca0"
BASE.MANIFEST_FILE_SHA256 = (
    "0c92a7f1fefafcdb7a1a2c3de7ab96a3e56f2c61a920dc91a6a83a2ed9cde475"
)
BASE.MANIFEST_DIGEST = (
    "2ac8c65a61603da0b8182adf7ba8b019d7ec0ad8e684d85cafa115ff09ab1e3e"
)
BASE.ISSUER_TAG = "rea-wea-generation-5-8bc4c88a3d43"
BASE.REVIEW_EXPECTED_HEAD = BASE.MANIFEST_HEAD


def main(argv=None):
    return BASE.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
