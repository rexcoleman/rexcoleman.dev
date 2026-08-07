#!/usr/bin/env python3
"""The REGISTERED transition that establishes the renewal signing key.

P-6, precondition reachability: every precondition a gate requires must be
establishable by a registered transition, executable without passing through
the gate that requires it, and NOT by a manual out-of-band act.

`issue-write-enforcement-attestation.yml` job `renew-wea` declares environment
`rea-write-enforcement-renewal` and refuses at its first step unless that
environment holds REA_WEA_ED25519_PRIVATE_KEY_B64.  That guard is correct and
fails closed.  What was missing was any registered way to SATISFY it: the key
had only ever reached `rea-write-enforcement-issuer` by hand.  This module is
that registered way.  It does not weaken, bypass, or edit the guard; it makes
the guard's precondition reachable.

Handling rules, all enforced below rather than merely documented:

  * The signing key value is read from the process environment and is passed
    to `gh` on STDIN.  It is never an argv element (argv is world-readable in
    /proc), never written to a file, never placed in a step output, never
    interpolated into a log line.
  * Every byte this module prints passes through redact(), which replaces the
    secret value -- and its whitespace-stripped form -- with `***`.  A child
    process that echoes the value back cannot launder it into our stdout.
  * The key is identified in logs by the SHA-256 of its DER-encoded PUBLIC
    key, derived through `openssl pkey -pubout` with the PEM on stdin.  A
    public key is not secret and its digest lets an operator confirm WHICH key
    landed without any path to the private half.
  * Verification is by NAME, through the API, after the write, and the
    observed `updated_at` must be at or after the instant sampled immediately
    before the write.  A pre-existing secret this run did not touch is a
    FAILURE (SECRET_WRITE_NOT_OBSERVED), not a success.

Every refusal is typed, printed to stderr, and exits 3.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys

REFUSAL_EXIT = 3

SOURCE_SIGNING_KEY_UNREADABLE = "SOURCE_SIGNING_KEY_UNREADABLE"
SOURCE_SIGNING_KEY_MALFORMED = "SOURCE_SIGNING_KEY_MALFORMED"
SECRETS_WRITE_PAT_ABSENT = "SECRETS_WRITE_PAT_ABSENT"
SECRETS_WRITE_PAT_INSUFFICIENT_SCOPE = "SECRETS_WRITE_PAT_INSUFFICIENT_SCOPE"
SECRET_WRITE_FAILED = "SECRET_WRITE_FAILED"
SECRET_WRITE_UNVERIFIED = "SECRET_WRITE_UNVERIFIED"
SECRET_WRITE_NOT_OBSERVED = "SECRET_WRITE_NOT_OBSERVED"

# A public key digest is safe to print; a private key never is.  Nothing else
# derived from the secret is ever emitted.
PUBLIC_DIGEST_LABEL = "public_key_sha256"


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def redact(text: str, secret: str) -> str:
    """Remove the secret value from anything we are about to print.

    Both the raw value and its stripped form are replaced, because `gh` and
    the shell routinely round-trip a value with a trailing newline attached.
    """
    if not text:
        return ""
    for candidate in {secret, secret.strip()}:
        if candidate:
            text = text.replace(candidate, "***")
    return text


def run(argv, *, stdin_bytes=None, secret="", timeout=120):
    """Run a child process, capturing output and scrubbing it immediately."""
    completed = subprocess.run(
        argv,
        input=stdin_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    out = redact(completed.stdout.decode("utf-8", "replace"), secret)
    err = redact(completed.stderr.decode("utf-8", "replace"), secret)
    return completed.returncode, out, err


def public_key_digest(key_b64: str) -> str:
    """SHA-256 of the DER public key derived from the base64-wrapped PEM.

    This both validates the shape of the material (refusing anything that is
    not a base64-wrapped private key openssl will parse) and yields a log-safe
    identifier for it.  The private PEM reaches openssl on stdin only.
    """
    try:
        pem = base64.b64decode(key_b64.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refusal(
            SOURCE_SIGNING_KEY_MALFORMED,
            f"source value is not valid base64 ({type(exc).__name__})",
        ) from exc
    if b"PRIVATE KEY" not in pem:
        raise Refusal(
            SOURCE_SIGNING_KEY_MALFORMED,
            "decoded source value is not a PEM private key",
        )
    # stdout is binary DER and must NOT go through the text redactor; stderr
    # is a diagnostic string and must.
    completed = subprocess.run(
        ["openssl", "pkey", "-pubout", "-outform", "DER"],
        input=pem,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if completed.returncode != 0 or not completed.stdout:
        detail = redact(completed.stderr.decode("utf-8", "replace"), key_b64).strip()
        raise Refusal(
            SOURCE_SIGNING_KEY_MALFORMED,
            "openssl refused to parse the source private key "
            f"(rc={completed.returncode}) {detail}",
        )
    return hashlib.sha256(completed.stdout).hexdigest()


def parse_iso8601(value: str) -> dt.datetime:
    text = value.strip().replace("Z", "+00:00")
    return dt.datetime.fromisoformat(text).astimezone(dt.timezone.utc)


def probe_write_scope(gh: str, repository: str, environment: str, secret: str) -> str:
    """Prove the token can reach the target environment's secret machinery.

    GET .../secrets/public-key is the first half of the API's public-key
    encryption path and is gated by the same repository `Secrets` permission
    the write needs.  Probing it first turns an under-scoped token into a
    typed refusal BEFORE any write is attempted, and gives the dry run
    something real to assert.
    """
    code, out, err = run(
        [gh, "api", f"repos/{repository}/environments/{environment}/secrets/public-key"],
        secret=secret,
    )
    if code != 0:
        raise Refusal(
            SECRETS_WRITE_PAT_INSUFFICIENT_SCOPE,
            "the supplied token cannot read "
            f"repos/{repository}/environments/{environment}/secrets/public-key "
            f"(gh rc={code}); a fine-grained PAT scoped to repository "
            f"{repository} with Secrets: Read and write is required. {err.strip()}",
        )
    try:
        key_id = json.loads(out)["key_id"]
    except (ValueError, KeyError) as exc:
        raise Refusal(
            SECRETS_WRITE_PAT_INSUFFICIENT_SCOPE,
            f"public-key response carried no key_id ({type(exc).__name__})",
        ) from exc
    return str(key_id)


def observe_secret(gh: str, repository: str, environment: str, name: str, secret: str):
    code, out, err = run(
        [gh, "api", f"repos/{repository}/environments/{environment}/secrets/{name}"],
        secret=secret,
    )
    if code != 0:
        return None, err
    try:
        return json.loads(out), err
    except ValueError:
        return None, err


def provision(args, environ) -> int:
    gh = args.gh
    key_b64 = environ.get(args.source_env_var, "") or ""
    token = environ.get("GH_TOKEN", "") or ""

    if not key_b64.strip():
        raise Refusal(
            SOURCE_SIGNING_KEY_UNREADABLE,
            f"{args.source_env_var} is empty in this job; the job must declare "
            f"environment {args.source_environment}, which holds it",
        )
    digest = public_key_digest(key_b64)
    print(f"SOURCE_SIGNING_KEY_READABLE {PUBLIC_DIGEST_LABEL}={digest}")

    if not token.strip():
        raise Refusal(
            SECRETS_WRITE_PAT_ABSENT,
            "GH_TOKEN is empty; the owner-minted fine-grained PAT "
            f"({args.pat_secret_name}) is not provisioned into environment "
            f"{args.source_environment}",
        )

    key_id = probe_write_scope(gh, args.repository, args.target_environment, key_b64)
    print(f"SECRETS_WRITE_SCOPE_PROVEN environment={args.target_environment} key_id={key_id}")

    if args.mode == "dry-run":
        print(
            "PROVISION_DRY_RUN_PASS "
            f"repository={args.repository} target={args.target_environment} "
            f"secret={args.secret_name} {PUBLIC_DIGEST_LABEL}={digest} "
            "wrote_nothing=true"
        )
        return 0

    # Sampled BEFORE the write so the post-write observation can prove that
    # THIS run moved the secret.  One minute of slack absorbs clock skew
    # between the runner and GitHub's API without admitting a stale row: the
    # authority lifetime is 24 hours, so a minute is far inside any window
    # that could matter.
    before = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)

    # The value travels on stdin.  `gh secret set` performs the API's
    # public-key encryption path itself -- it GETs the environment public key
    # and PUTs a libsodium sealed box -- using the copy of gh that GitHub
    # ships preinstalled on the runner.  That is deliberately preferred over
    # pip-installing a crypto library at job time: a step that handles a
    # signing key should not open a PyPI supply-chain surface.
    code, out, err = run(
        [
            gh, "secret", "set", args.secret_name,
            "--repo", args.repository,
            "--env", args.target_environment,
        ],
        stdin_bytes=key_b64.encode(),
        secret=key_b64,
    )
    if code != 0:
        raise Refusal(
            SECRET_WRITE_FAILED,
            f"gh secret set exited {code}: {err.strip() or out.strip()}",
        )
    print(f"SECRET_WRITE_ATTEMPTED secret={args.secret_name} target={args.target_environment}")

    observed, oerr = observe_secret(
        gh, args.repository, args.target_environment, args.secret_name, key_b64
    )
    if observed is None or observed.get("name") != args.secret_name:
        raise Refusal(
            SECRET_WRITE_UNVERIFIED,
            f"{args.secret_name} is not readable by name in environment "
            f"{args.target_environment} after the write; a copy that cannot be "
            f"verified is a failure. {oerr.strip()}",
        )
    try:
        updated = parse_iso8601(str(observed.get("updated_at", "")))
    except ValueError as exc:
        raise Refusal(
            SECRET_WRITE_UNVERIFIED,
            f"updated_at was unparseable ({type(exc).__name__})",
        ) from exc
    if updated < before:
        raise Refusal(
            SECRET_WRITE_NOT_OBSERVED,
            f"{args.secret_name} exists in {args.target_environment} but its "
            f"updated_at {updated.isoformat()} predates this run's write at "
            f"{before.isoformat()}; this run did not establish it",
        )

    print(
        "RENEWAL_SIGNING_KEY_PROVISIONED "
        f"repository={args.repository} target={args.target_environment} "
        f"secret={args.secret_name} {PUBLIC_DIGEST_LABEL}={digest} "
        f"updated_at={updated.isoformat()}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("dry-run", "copy"), default="dry-run")
    parser.add_argument("--repository", default="rexcoleman/rexcoleman.dev")
    parser.add_argument("--source-environment", default="rea-write-enforcement-issuer")
    parser.add_argument("--target-environment", default="rea-write-enforcement-renewal")
    parser.add_argument("--secret-name", default="REA_WEA_ED25519_PRIVATE_KEY_B64")
    parser.add_argument("--source-env-var", default="REA_WEA_ED25519_PRIVATE_KEY_B64")
    parser.add_argument("--pat-secret-name", default="REA_SECRETS_WRITE_PAT")
    parser.add_argument("--gh", default="gh")
    return parser


def main(argv=None, environ=None) -> int:
    args = build_parser().parse_args(argv)
    environ = os.environ if environ is None else environ
    if args.source_environment == args.target_environment:
        print(
            "REFUSED PROVISION_SOURCE_EQUALS_TARGET: refusing a no-op copy",
            file=sys.stderr,
        )
        return REFUSAL_EXIT
    try:
        return provision(args, environ)
    except Refusal as refusal:
        print(f"REFUSED {refusal.code}: {refusal.detail}", file=sys.stderr)
        return REFUSAL_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
