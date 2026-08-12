#!/usr/bin/env python3
"""Checked s152 owner arc for the signed CI Git-auth successor authority."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SOURCE = Path(__file__).with_name("s152_ci_decoder_successor_approval_v7.py")
SPEC = importlib.util.spec_from_file_location("s152_successor_v8_base", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("V8_BASE_IMPORT_REFUSED")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)

# New incident identity.  The reviewed helper keeps the already-tested dynamic
# predecessor, review->merge->tag->public_retry, no-seal, and no-secret-mutation
# rail while binding this successor's exact immutable subjects.
BASE.MARKER = "rea-s152-ci-git-auth-successor-approval-v8"
BASE.REVIEW_RUN_ID = 31612053165
BASE.REVIEW_JOB_ID = 94165574632
BASE.REVIEW_WORKFLOW_SHA = "3cfe0356725dd68ecbeaf2939d4ba79a2bea5515"
BASE.MANIFEST_PR = 94
BASE.MANIFEST_HEAD = "8bc4c88624ce85e5a91385bea3212114c2aa2ba8"
BASE.MANIFEST_FILE_SHA256 = (
    "0c92a7f1fefafcdb7a1a2c3de7ab96a3e56f2c61a920dc91a6a83a2ed9cde475"
)
BASE.MANIFEST_DIGEST = (
    "2ac8c65a61603da0b8182adf7ba8b019d7ec0ad8e684d85cafa115ff09ab1e3e"
)
BASE.ISSUER_TAG = "rea-wea-generation-5-8bc4c88624ce"
BASE.REVIEW_EXPECTED_HEAD = BASE.MANIFEST_HEAD


def main(argv=None):
    return BASE.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
