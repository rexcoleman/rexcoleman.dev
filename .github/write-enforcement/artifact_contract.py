#!/usr/bin/env python3
"""Generation-aware published-artifact contract for the write-enforcement chain.

A predecessor issuance is evidence produced under the contract that was in
force *at the predecessor's own generation*.  Validating it against the
current generation asks the past to conform to the present (P-4: a validator
derives what it certifies) and makes the current generation's precondition
unreachable by any registered transition (P-6).

The generation is DERIVED, never declared: every ``issuance_receipt.json``
records ``workflow_blob_sha256``, the SHA-256 of the exact issuer workflow file
that produced the artifact.  That value changes if and only if the issuer
contract changes, and it is present in every published receipt back to the
earliest run.  The version table maps those observed digests to the exact
member set that generation published.

Nothing here relaxes what a run must PRODUCE.  It constrains only what a run
may INHERIT.  Every path either resolves to an exact set or raises a typed
refusal; there is no permissive default and no smallest-set fallback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = "rea.write.artifact-contract-versions.v1"
DEFAULT_TABLE = Path(__file__).resolve().parent / "artifact_contract_versions.json"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class ContractRefusal(RuntimeError):
    """A typed refusal.  Every failure path raises this, never a fallback."""


def _refuse(reason: str) -> "ContractRefusal":
    return ContractRefusal(reason)


def load_table(path: Path | str = DEFAULT_TABLE) -> dict:
    """Load and fully validate the version table.

    The table itself is validated for monotonicity and closure before it may
    be used, so a malformed table refuses rather than silently admitting a
    wrong set.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _refuse(f"CONTRACT_TABLE_UNREADABLE:{type(exc).__name__}") from None
    try:
        table = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise _refuse("CONTRACT_TABLE_UNPARSEABLE") from None
    if not isinstance(table, dict) or table.get("schema_version") != SCHEMA_VERSION:
        raise _refuse("CONTRACT_TABLE_SCHEMA_REFUSED")
    versions = table.get("versions")
    if not isinstance(versions, list) or not versions:
        raise _refuse("CONTRACT_TABLE_VERSIONS_REFUSED")

    seen_digests: set[str] = set()
    previous: set[str] = set()
    for index, entry in enumerate(versions):
        if not isinstance(entry, dict):
            raise _refuse(f"CONTRACT_TABLE_ENTRY_REFUSED:{index}")
        version = entry.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise _refuse(f"CONTRACT_TABLE_VERSION_REFUSED:{index}")
        if version != index + 1:
            # Versions are dense and strictly increasing from 1.  A gap would
            # mean an unrepresented generation could be silently skipped.
            raise _refuse(f"CONTRACT_TABLE_VERSION_SEQUENCE_REFUSED:{version}")

        digests = entry.get("workflow_blob_sha256")
        if (not isinstance(digests, list) or not digests
                or not all(isinstance(d, str) and _SHA256_RE.fullmatch(d) for d in digests)
                or len(set(digests)) != len(digests)):
            raise _refuse(f"CONTRACT_TABLE_DIGESTS_REFUSED:{version}")
        for digest in digests:
            if digest in seen_digests:
                # Closure: one workflow blob resolves to exactly one generation.
                raise _refuse(f"CONTRACT_TABLE_DIGEST_COLLISION:{digest}")
            seen_digests.add(digest)

        members = entry.get("members")
        if (not isinstance(members, list) or not members
                or not all(isinstance(m, str) and _NAME_RE.fullmatch(m) for m in members)
                or len(set(members)) != len(members)
                or list(members) != sorted(members)):
            raise _refuse(f"CONTRACT_TABLE_MEMBERS_REFUSED:{version}")
        current = set(members)
        if previous and not previous < current:
            # Monotonic: contract versions only ever GAIN members.  A version
            # that dropped a member would let a later run inherit less than an
            # earlier one already proved.
            raise _refuse(f"CONTRACT_TABLE_NOT_MONOTONIC:{version}")
        previous = current
    return table


def known_member_names(table: dict) -> frozenset[str]:
    """Every member name any known generation ever published."""
    names: set[str] = set()
    for entry in table["versions"]:
        names.update(entry["members"])
    return frozenset(names)


def current_entry(table: dict) -> dict:
    """The highest registered generation: the contract this issuer produces."""
    return table["versions"][-1]


def current_members(table: dict) -> tuple[str, ...]:
    return tuple(current_entry(table)["members"])


def read_receipt(packet: Path | str) -> dict:
    """Read the predecessor's own receipt.  Unparseable refuses."""
    path = Path(packet) / "issuance_receipt.json"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _refuse(f"PREDECESSOR_RECEIPT_UNREADABLE:{type(exc).__name__}") from None
    try:
        receipt = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise _refuse("PREDECESSOR_RECEIPT_UNPARSEABLE") from None
    if not isinstance(receipt, dict):
        raise _refuse("PREDECESSOR_RECEIPT_SHAPE_REFUSED")
    return receipt


def resolve_generation(receipt: dict, table: dict) -> dict:
    """Map a predecessor receipt to its registered generation entry.

    Refuses on an absent, malformed, or unregistered generation marker.  There
    is deliberately no fallback: an unrecognised generation is a refusal, not
    the smallest set.
    """
    if not isinstance(receipt, dict):
        raise _refuse("PREDECESSOR_RECEIPT_SHAPE_REFUSED")
    marker = receipt.get("workflow_blob_sha256")
    if marker is None:
        raise _refuse("PREDECESSOR_GENERATION_MARKER_ABSENT")
    if not isinstance(marker, str) or not _SHA256_RE.fullmatch(marker):
        raise _refuse("PREDECESSOR_GENERATION_MARKER_MALFORMED")
    for entry in table["versions"]:
        if marker in entry["workflow_blob_sha256"]:
            return entry
    raise _refuse(f"PREDECESSOR_UNKNOWN_GENERATION:{marker}")


def expected_members(receipt: dict, table: dict) -> tuple[str, ...]:
    return tuple(resolve_generation(receipt, table)["members"])


def validate_predecessor_set(observed: set[str], receipt: dict, table: dict) -> dict:
    """Enforce the predecessor's OWN generation contract, exactly.

    Returns the resolved generation entry.  Raises a typed refusal otherwise.
    """
    entry = resolve_generation(receipt, table)
    expected = set(entry["members"])
    universe = known_member_names(table)

    for name in sorted(observed - universe):
        # A name no registered generation ever published.
        raise _refuse(f"PREDECESSOR_UNKNOWN_MEMBER_NAME:{name}")
    for name in sorted(expected - observed):
        # Missing a member its OWN generation required.
        raise _refuse(f"PREDECESSOR_MEMBER_MISSING:{name}")
    for name in sorted(observed - expected):
        # A known name, but not one this generation published.
        raise _refuse(f"PREDECESSOR_MEMBER_UNEXPECTED:{name}")
    if observed != expected:  # pragma: no cover - defensive
        raise _refuse("PREDECESSOR_ARTIFACT_SET_REFUSED")
    return entry


def observe_packet(packet: Path | str) -> set[str]:
    """Top-level regular files in a downloaded artifact packet.

    Symlinks and directories are not members; anything unexpected in the
    packet is surfaced to the set check rather than silently ignored.
    """
    root = Path(packet)
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise _refuse(f"PREDECESSOR_ARTIFACT_UNREADABLE:{type(exc).__name__}") from None
    names = set()
    for path in entries:
        if path.is_symlink() or not path.is_file():
            raise _refuse(f"PREDECESSOR_ARTIFACT_ENTRY_REFUSED:{path.name}")
        names.add(path.name)
    return names


def verify_current_binding(table: dict, workflow_path: Path | str) -> str:
    """Bind the table's current generation to the live issuer workflow bytes.

    The current generation's digest must be the SHA-256 of the issuer workflow
    file that is actually running.  This is what stops the table and the
    workflow from drifting: a table edited to widen or narrow the current
    generation no longer matches the workflow it claims to describe.
    """
    path = Path(workflow_path)
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise _refuse(f"LIVE_WORKFLOW_UNREADABLE:{type(exc).__name__}") from None
    entry = current_entry(table)
    if digest not in entry["workflow_blob_sha256"]:
        raise _refuse(f"CURRENT_GENERATION_BINDING_REFUSED:{digest}")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", default=str(DEFAULT_TABLE))
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check-predecessor")
    check.add_argument("--packet", required=True)

    show = sub.add_parser("current-members")
    show.add_argument("--bind-workflow", default=None)

    args = parser.parse_args(argv)
    try:
        table = load_table(args.table)
        if args.command == "check-predecessor":
            receipt = read_receipt(args.packet)
            observed = observe_packet(args.packet)
            entry = validate_predecessor_set(observed, receipt, table)
            print(f"PREDECESSOR_GENERATION_RESOLVED version={entry['version']} "
                  f"marker={receipt['workflow_blob_sha256']} "
                  f"members={len(entry['members'])}")
            for name in entry["members"]:
                print(f"  expected {name}")
            print("PREDECESSOR_ARTIFACT_SET_PASS")
        else:
            # Diagnostics go to stderr so stdout is exactly the member list and
            # can be compared byte-for-byte against the workflow's own literal.
            if args.bind_workflow:
                digest = verify_current_binding(table, args.bind_workflow)
                print(f"CURRENT_GENERATION_BINDING_PASS blob_sha256={digest}",
                      file=sys.stderr)
            entry = current_entry(table)
            print(f"CURRENT_GENERATION version={entry['version']} "
                  f"members={len(entry['members'])}", file=sys.stderr)
            for name in entry["members"]:
                print(name)
    except ContractRefusal as exc:
        print(f"REFUSED {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
