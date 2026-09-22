#!/usr/bin/env python3
"""Report the retired owner-held PAT route without collecting credentials."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys


CREDENTIAL_FILE = Path("/home/azureuser/.config/govml/env")
REQUIRED = (
    "GOVML_AUTHORITY_TOKEN",
    "REA_BUNDLE_READ_TOKEN",
)
NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Refusal(RuntimeError):
    pass


def parse(raw: bytes) -> tuple[list[str], dict[str, str]]:
    try:
        rows = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise Refusal("CREDENTIAL_FILE_UTF8_REFUSED") from exc
    found: dict[str, str] = {}
    for number, source in enumerate(rows, 1):
        row = source.strip()
        if not row or row.startswith("#"):
            continue
        if row.startswith("export "):
            row = row[7:].lstrip()
        if "=" not in row:
            raise Refusal(f"CREDENTIAL_FILE_PARSE_REFUSED line={number}")
        name, value = row.split("=", 1)
        name = name.strip()
        if NAME_PATTERN.fullmatch(name) is None:
            raise Refusal(f"CREDENTIAL_FILE_PARSE_REFUSED line={number}")
        if name not in REQUIRED:
            continue
        if name in found:
            raise Refusal(f"CREDENTIAL_FILE_DUPLICATE_REFUSED name={name}")
        value = value.strip()
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1:] != value[:1]:
                raise Refusal(f"CREDENTIAL_FILE_PARSE_REFUSED line={number}")
            value = value[1:-1]
        found[name] = value
    return rows, found


def secure_file(path: Path = CREDENTIAL_FILE) -> bytes:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise Refusal("CREDENTIAL_FILE_UNREADABLE") from exc
    if (
        not stat.S_ISREG(observed.st_mode)
        or path.is_symlink()
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise Refusal("CREDENTIAL_FILE_SECURITY_REFUSED")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise Refusal("CREDENTIAL_FILE_UNREADABLE") from exc


def presence(path: Path = CREDENTIAL_FILE) -> tuple[list[str], bytes, dict[str, str]]:
    raw = secure_file(path)
    rows, found = parse(raw)
    states = {name: "SET" if found.get(name) else "UNSET" for name in REQUIRED}
    if len(set(states.values())) != 1:
        raise Refusal("PARTIAL_REQUIRED_CREDENTIAL_SET_REFUSED")
    return rows, raw, states


def preflight(path: Path = CREDENTIAL_FILE) -> dict[str, str]:
    unused_rows, unused_raw, states = presence(path)
    return {"status": "RETIRED", **states}


def apply(path: Path = CREDENTIAL_FILE) -> dict[str, str]:
    preflight(path)
    raise Refusal("OWNER_PAT_ROUTE_RETIRED use=GOVML_REA_READ_APP")


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preflight", action="store_true")
    modes.add_argument("--apply", action="store_true")
    arguments = parser.parse_args()
    try:
        result = apply() if arguments.apply else preflight()
    except (OSError, Refusal) as exc:
        print(f"REA_S170_CREDENTIAL_REFUSED reason={exc}", file=sys.stderr)
        return 3
    print(
        "REA_S170_CREDENTIAL_" + result["status"]
        + " " + " ".join(f"{name}={result[name]}" for name in REQUIRED)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
