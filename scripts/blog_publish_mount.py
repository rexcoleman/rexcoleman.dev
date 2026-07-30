#!/usr/bin/env python3
"""BLG-08 exact Hugo bundle consumer."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import stat
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rex_hybrid_mount import (
    CANONICAL_REPO,
    RexHybridRefusal,
    build_bundle,
    bundle_plan,
    bundle_target,
    consume_exact_bundle,
)

DEFAULT_INSTALLED_RUNTIME_MOUNT = (
    Path.home() / ".local/libexec/rea_enforcement/runtime_mount.py"
)
# Isolated fixture tests may monkeypatch this module constant in-process. The
# production CLI has no argument or environment seam that can select it.
INSTALLED_RUNTIME_MOUNT = DEFAULT_INSTALLED_RUNTIME_MOUNT


def _regular_bytes(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RexHybridRefusal(
            "FINAL_BYTES_UNAVAILABLE", f"{path}:{type(exc).__name__}"
        ) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RexHybridRefusal("FINAL_BYTES_UNAVAILABLE", str(path))
    return path.read_bytes()


def _image_members(source: Path | None, slug: str) -> list[tuple[str, bytes]]:
    if source is None or not source.exists():
        return []
    if source.is_symlink() or not source.is_dir():
        raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(source))
    members: list[tuple[str, bytes]] = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(path))
        if path.is_dir():
            continue
        relative = path.relative_to(source).as_posix()
        members.append((f"static/images/{slug}/{relative}", _regular_bytes(path)))
    return members


def _isolated_fixture_consume(args: argparse.Namespace) -> int:
    """Preserve the s104/s120 proof seam without exposing a production override."""
    site_root = Path(__file__).resolve().parents[1]
    try:
        site_root.relative_to(Path("/tmp").resolve())
        args.candidate.resolve().relative_to(Path("/tmp").resolve())
        args.destination.resolve().relative_to(Path("/tmp").resolve())
    except ValueError:
        raise RexHybridRefusal(
            "ISOLATED_HARNESS_REQUIRED", "fixture paths must be under /tmp"
        ) from None
    spec = importlib.util.spec_from_file_location(
        "rea_runtime_mount_fixture", INSTALLED_RUNTIME_MOUNT
    )
    if spec is None or spec.loader is None:
        raise RexHybridRefusal(
            "CONSUMER_BINDING_MISSING", str(INSTALLED_RUNTIME_MOUNT)
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    candidate = _regular_bytes(args.candidate)
    try:
        module.atomic_write(
            route_id="BLG-08",
            surface="blog",
            candidate=candidate,
            destination=args.destination,
            requested_effect="write",
            run_id=(
                "rex-publish-blg-08-fixture-"
                + hashlib.sha256(candidate).hexdigest()[:12]
                + "-"
                + uuid.uuid4().hex
            ),
        )
    except module.MountRefusal as exc:
        return exc.raw_exit
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--image-source", type=Path)
    args = parser.parse_args()
    try:
        if INSTALLED_RUNTIME_MOUNT != DEFAULT_INSTALLED_RUNTIME_MOUNT:
            fixture_exit = _isolated_fixture_consume(args)
            if fixture_exit != 0:
                raise SystemExit(fixture_exit)
            return 0
        destination = args.destination.absolute()
        expected_parent = (CANONICAL_REPO / "content/posts").absolute()
        if (
            destination.parent != expected_parent
            or destination.suffix != ".md"
            or destination.stem == ""
        ):
            raise RexHybridRefusal("ARBITRARY_SINK_REFUSED", str(destination))
        slug = destination.stem
        members = [
            (f"content/posts/{slug}.md", _regular_bytes(args.candidate)),
            *_image_members(args.image_source, slug),
        ]
        candidate = build_bundle("BLG-08", slug, members)
        receipt = consume_exact_bundle(
            route_id="BLG-08",
            candidate=candidate,
            effect_plan=bundle_plan("BLG-08", candidate),
            target=bundle_target("BLG-08", candidate),
        )
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    except RexHybridRefusal as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(exc.raw_exit) from None


if __name__ == "__main__":
    raise SystemExit(main())
