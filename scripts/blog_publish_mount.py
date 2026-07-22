#!/usr/bin/env python3
"""BLG-08 final-byte authorization consumer for publish.sh."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


RUNTIME_MOUNT = Path(
    "/home/azureuser/research_enforcement_activation/"
    "write_integrity/mounts/runtime_mount.py"
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate")
    parser.add_argument("destination")
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("rea_runtime_mount", RUNTIME_MOUNT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"REFUSE(CONSUMER_BINDING_MISSING): {RUNTIME_MOUNT}")
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
            run_id="rex-publish-blg-08",
        )
    except module.MountRefusal as exc:
        raise SystemExit(exc.raw_exit) from None


if __name__ == "__main__":
    main()
