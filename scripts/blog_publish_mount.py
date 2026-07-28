#!/usr/bin/env python3
"""BLG-08 final-byte authorization consumer for publish.sh."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import uuid
from pathlib import Path


INSTALLED_RUNTIME_MOUNT = Path(
    "/home/azureuser/.local/libexec/rea_enforcement/runtime_mount.py"
)
ISOLATED_MOUNT_ENV = "REA_WRITE_INTEGRITY_ISOLATED_RUNTIME_MOUNT"
ISOLATED_CONTEXT_ENV = "REA_WRITE_INTEGRITY_ISOLATED_HYBRID_CONTEXT"


def runtime_mount_path() -> Path:
    isolated = os.environ.get(ISOLATED_MOUNT_ENV)
    if isolated:
        if not os.environ.get(ISOLATED_CONTEXT_ENV):
            raise RuntimeError(
                "REFUSE(ISOLATED_HARNESS_REQUIRED): runtime mount override"
            )
        return Path(isolated).resolve()
    return INSTALLED_RUNTIME_MOUNT


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate")
    parser.add_argument("destination")
    args = parser.parse_args()

    mount_path = runtime_mount_path()
    spec = importlib.util.spec_from_file_location("rea_runtime_mount", mount_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"REFUSE(CONSUMER_BINDING_MISSING): {mount_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    candidate = Path(args.candidate).read_bytes()
    try:
        module.atomic_write(
            route_id="BLG-08",
            surface="blog",
            candidate=candidate,
            destination=args.destination,
            requested_effect="write",
            run_id=(
                "rex-publish-blg-08-"
                + hashlib.sha256(candidate).hexdigest()[:12]
                + "-"
                + uuid.uuid4().hex
            ),
        )
    except module.MountRefusal as exc:
        raise SystemExit(exc.raw_exit) from None


if __name__ == "__main__":
    main()
