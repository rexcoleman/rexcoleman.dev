#!/usr/bin/env python3
"""Renewal contract: what an unattended re-issuance may and may not move.

The write-enforcement authority expires 24 hours after it is issued.  The only
registered issuance path declares a GitHub environment carrying
``required_reviewers``, and environment approvals are per-run, so keeping
enforcement alive costs a named human one click per day, in perpetuity.  The
seed requires enforcement that fires "automatically from a standard scaffold
with no manual invocation", and managed invariant P-6's subset-proof reads
"satisfying one by a manual out-of-band act does not pass" -- a daily human
click is exactly a manual out-of-band act.

This module draws the only line that makes an unattended re-issuance safe:

* A **renewal** re-issues over an *identical capability basis*.  Every field
  that says what the authority may authorise stays byte-identical; only the
  lifetime-bearing and chain-bearing fields move.
* A **capability change** is anything else -- a moved bundle manifest digest, a
  changed member set, a widened publishing scope, a new required surface, a
  changed ruleset, a rotated key, a changed issuer source.  Those keep the
  owner-approved ``workflow_dispatch`` path exactly as it is.

Two properties make this fail closed rather than fail open:

1. **Field closure.**  The union of the two payloads' keys must be exactly the
   classified universe.  A field that is in neither list is a refusal, never a
   silent pass.  Without this, any future field added to the attestation would
   become an unwatched capability widening -- the P-4 failure shape, a
   validator certifying a property it never derived.
2. **No exemptions.**  There is no named run, named commit, named actor, or
   named digest that bypasses a check.  P-6's subset-proof rules that out by
   name, and every refusal here is a function of the compared bytes alone.

Nothing in this module relaxes what a run must produce or verify.  The renewal
path still authenticates its predecessor, still verifies the frozen bundle,
still proves public-only custody, and still signs with the protected key.  It
removes the human, not the checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = "rea.write.renewal-contract.v1"

# Exactly 24 hours.  ``test_renewal_contract.py`` pins this against
# ``issue_wea.issuance_times`` so the two cannot drift apart silently.
AUTHORITY_LIFETIME = timedelta(hours=24)

APPROVED_PATH = (
    "workflow_dispatch mode=capability_change on "
    ".github/workflows/issue-write-enforcement-attestation.yml, whose issuing "
    "job declares environment rea-write-enforcement-issuer "
    "(required_reviewers)"
)

#: Fields that state WHAT the authority authorises.  A renewal may not move any
#: of them.  Derived by reading every key ``issue_wea.py`` writes into the WEA
#: payload and asking, for each: if this changed, would the authority permit
#: something it did not permit before, or rest on a different basis?
CAPABILITY_FIELDS = frozenset({
    "schema_version",
    "purpose",
    "state",
    "issuer",
    "issuer_source_digest",
    "renewal_policy_digest",
    "coverage_registry_digest",
    "coverage_registry_generation",
    "publishing_capability_scope",
    "required_surfaces",
    "enforcement_bundle_manifest_digest",
    "claim_policy_digest",
    "trusted_key_id",
})

#: Fields that carry lifetime or chain position.  A renewal moves these and
#: only these, and each one is constrained below -- none of them is free.
CHAIN_FIELDS = frozenset({
    "authority_epoch",
    "predecessor_wea_digest",
    "issuance_receipt_digest",
    "issued_at",
    "not_before",
    "expires_at",
    "signature",
})

CLASSIFIED_FIELDS = CAPABILITY_FIELDS | CHAIN_FIELDS

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class RenewalRefusal(RuntimeError):
    """A typed, fail-closed refusal.  Every failure path raises this."""

    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


def _refuse(reason_code: str, detail: str) -> RenewalRefusal:
    return RenewalRefusal(reason_code, detail)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_wea(raw: bytes, *, role: str) -> dict:
    """Parse an attestation.  Anything but a JSON object refuses."""
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise _refuse("RENEWAL_WEA_UNPARSEABLE", role) from None
    if not isinstance(value, dict):
        raise _refuse("RENEWAL_WEA_SHAPE_REFUSED", role)
    return value


def _parse_instant(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _refuse("RENEWAL_TIMESTAMP_MALFORMED", field)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise _refuse("RENEWAL_TIMESTAMP_MALFORMED", field) from None
    return parsed.astimezone(timezone.utc)


def assert_field_closure(predecessor: dict, candidate: dict) -> None:
    """Every key in either payload must be classified.  No silent passes.

    This is the property that keeps the classifier honest as the attestation
    grows.  A new capability-bearing field added to ``issue_wea.py`` without
    being classified here refuses every renewal until it is classified, which
    is the correct direction to fail.
    """
    for role, payload in (("predecessor", predecessor), ("candidate", candidate)):
        unclassified = sorted(set(payload) - CLASSIFIED_FIELDS)
        if unclassified:
            raise _refuse(
                "RENEWAL_FIELD_UNCLASSIFIED",
                f"{role}:{','.join(unclassified)}",
            )
        missing = sorted(CLASSIFIED_FIELDS - set(payload))
        if missing:
            raise _refuse(
                "RENEWAL_FIELD_ABSENT", f"{role}:{','.join(missing)}"
            )


def assert_capability_basis_identical(predecessor: dict, candidate: dict) -> None:
    """Refuse on the first capability-bearing field that moved."""
    for field in sorted(CAPABILITY_FIELDS):
        if predecessor[field] != candidate[field]:
            raise _refuse(
                "RENEWAL_CAPABILITY_CHANGE_REFUSED",
                f"field={field} approved_path={APPROVED_PATH}",
            )


def assert_chain_advance(
    predecessor: dict, candidate: dict, predecessor_raw: bytes
) -> None:
    """The chain-bearing fields move, but none of them moves freely."""
    for role, payload in (("predecessor", predecessor), ("candidate", candidate)):
        epoch = payload["authority_epoch"]
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise _refuse("RENEWAL_EPOCH_MALFORMED", role)

    if candidate["authority_epoch"] != predecessor["authority_epoch"] + 1:
        raise _refuse(
            "RENEWAL_EPOCH_NOT_SUCCESSOR",
            f"predecessor={predecessor['authority_epoch']} "
            f"candidate={candidate['authority_epoch']}",
        )

    observed = digest(predecessor_raw)
    if candidate["predecessor_wea_digest"] != observed:
        raise _refuse(
            "RENEWAL_PREDECESSOR_LINK_REFUSED",
            f"declared={candidate['predecessor_wea_digest']} observed={observed}",
        )

    if not _SHA256_RE.fullmatch(str(candidate["issuance_receipt_digest"])):
        raise _refuse("RENEWAL_RECEIPT_DIGEST_MALFORMED", "candidate")
    if candidate["issuance_receipt_digest"] == predecessor["issuance_receipt_digest"]:
        # A replayed receipt digest means the run identity did not move: the
        # candidate is not a fresh issuance.
        raise _refuse("RENEWAL_RECEIPT_NOT_FRESH", "issuance_receipt_digest")

    issued = _parse_instant(candidate["issued_at"], "issued_at")
    not_before = _parse_instant(candidate["not_before"], "not_before")
    expires = _parse_instant(candidate["expires_at"], "expires_at")
    predecessor_issued = _parse_instant(
        predecessor["issued_at"], "predecessor.issued_at"
    )

    if not_before != issued:
        raise _refuse("RENEWAL_LIFETIME_REFUSED", "not_before!=issued_at")
    if expires - issued != AUTHORITY_LIFETIME:
        raise _refuse(
            "RENEWAL_LIFETIME_REFUSED",
            f"lifetime={expires - issued} expected={AUTHORITY_LIFETIME}",
        )
    if issued <= predecessor_issued:
        raise _refuse(
            "RENEWAL_NOT_MONOTONIC",
            f"candidate={candidate['issued_at']} "
            f"predecessor={predecessor['issued_at']}",
        )

    signature = candidate["signature"]
    if (
        not isinstance(signature, dict)
        or signature.get("algorithm") != "ed25519"
        or not _SHA256_RE.fullmatch(str(signature.get("signed_digest")))
        or not isinstance(signature.get("value"), str)
        or not signature["value"]
    ):
        raise _refuse("RENEWAL_SIGNATURE_SHAPE_REFUSED", "candidate")
    unsigned = {key: item for key, item in candidate.items() if key != "signature"}
    if signature["signed_digest"] != digest(canonical(unsigned)):
        # Not a substitute for verifying the signature against the trust root;
        # that stays in verify_hosted_wea.py.  This only refuses a payload whose
        # own signed digest does not cover the bytes being compared here.
        raise _refuse("RENEWAL_SIGNED_DIGEST_MISMATCH", "candidate")


def classify(predecessor_raw: bytes, candidate_raw: bytes) -> dict:
    """Return the renewal verdict, or raise a typed refusal.

    A verdict of RENEWAL means: identical capability basis, correct successor
    position on the chain, exact 24-hour lifetime, fresh run identity.
    """
    predecessor = load_wea(predecessor_raw, role="predecessor")
    candidate = load_wea(candidate_raw, role="candidate")
    assert_field_closure(predecessor, candidate)
    assert_capability_basis_identical(predecessor, candidate)
    assert_chain_advance(predecessor, candidate, predecessor_raw)
    return {
        "schema_version": SCHEMA,
        "verdict": "RENEWAL",
        "capability_basis_digest": digest(
            canonical({field: candidate[field] for field in sorted(CAPABILITY_FIELDS)})
        ),
        "predecessor_epoch": predecessor["authority_epoch"],
        "authority_epoch": candidate["authority_epoch"],
        "predecessor_wea_sha256": digest(predecessor_raw),
        "wea_sha256": digest(candidate_raw),
        "issued_at": candidate["issued_at"],
        "expires_at": candidate["expires_at"],
    }


def precheck(predecessor_raw: bytes, manifest_raw: bytes) -> dict:
    """Fail fast, before the protected key is ever materialised.

    Every capability-bearing field except the live ruleset and the key identity
    is derived from members of the frozen bundle, and the bundle is identified
    by exactly one value: its manifest digest.  So an unchanged manifest digest
    is a necessary condition for a renewal, and it is checkable with no key and
    no signing.  It is deliberately not treated as sufficient -- ``classify``
    re-checks every field against the emitted bytes after issuance.
    """
    predecessor = load_wea(predecessor_raw, role="predecessor")
    try:
        manifest = json.loads(manifest_raw)
    except (ValueError, UnicodeDecodeError):
        raise _refuse("RENEWAL_MANIFEST_UNPARSEABLE", "manifest") from None
    if not isinstance(manifest, dict) or not _SHA256_RE.fullmatch(
        str(manifest.get("manifest_digest"))
    ):
        raise _refuse("RENEWAL_MANIFEST_SHAPE_REFUSED", "manifest_digest")
    declared = predecessor.get("enforcement_bundle_manifest_digest")
    if declared != manifest["manifest_digest"]:
        raise _refuse(
            "RENEWAL_CAPABILITY_CHANGE_REFUSED",
            "field=enforcement_bundle_manifest_digest "
            f"predecessor={declared} candidate={manifest['manifest_digest']} "
            f"approved_path={APPROVED_PATH}",
        )
    return {
        "schema_version": SCHEMA,
        "verdict": "RENEWAL_PRECHECK_PASS",
        "enforcement_bundle_manifest_digest": manifest["manifest_digest"],
    }


def _read(path: str, label: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise _refuse(f"RENEWAL_{label}_UNREADABLE", type(exc).__name__) from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Renewal contract gate.")
    sub = parser.add_subparsers(dest="command", required=True)

    pre = sub.add_parser("precheck")
    pre.add_argument("--predecessor", required=True)
    pre.add_argument("--manifest", required=True)

    full = sub.add_parser("classify")
    full.add_argument("--predecessor", required=True)
    full.add_argument("--candidate", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "precheck":
            report = precheck(
                _read(args.predecessor, "PREDECESSOR"),
                _read(args.manifest, "MANIFEST"),
            )
        else:
            report = classify(
                _read(args.predecessor, "PREDECESSOR"),
                _read(args.candidate, "CANDIDATE"),
            )
    except RenewalRefusal as exc:
        print(f"REFUSED {exc.reason_code}: {exc.detail}", file=sys.stderr)
        return 3
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
