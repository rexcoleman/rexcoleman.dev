#!/usr/bin/env python3
"""Select the governed-project read credential for exactly one hosted run.

Custody precedence is fixed by
``.github/write-enforcement/CREDENTIAL_CUSTODY.md`` section "Primary GitHub App
custody for governed-project reads":

1. a COMPLETE ``GOVML_REA_READ_APP_ID`` / ``GOVML_REA_READ_APP_PRIVATE_KEY_B64``
   pair mints one short-lived installation token through the signed installed
   minter and takes precedence even when a compatibility name is still
   configured;
2. a PARTIAL pair REFUSES.  It never downgrades to the compatibility route,
   because a half-provisioned App is an operator error, not a fallback;
3. only when the App pair is wholly absent may the deprecated compatibility
   label ``REA_BUNDLE_READ_TOKEN`` be selected;
4. nothing present REFUSES.

The selected credential is written atomically to a caller-named mode-0600 file
by the minter's own writer, so both routes share one reviewed implementation.
Neither a credential value nor a digest of one is ever printed, logged, or
placed in argv.

The minter is located by an explicit ``--minter`` argument.  This module never
derives a path from ``$HOME``, ``~``, ``$PWD`` or any other ambient location:
the caller must name the exact signed copy it intends to run.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import stat
import sys
from pathlib import Path

APP_ID_ENV = "GOVML_REA_READ_APP_ID"
APP_KEY_ENV = "GOVML_REA_READ_APP_PRIVATE_KEY_B64"
LEGACY_ENV = "REA_BUNDLE_READ_TOKEN"

APP_ROUTE = "github_app_installation_token"
LEGACY_ROUTE = "deprecated_compatibility_rea_bundle_read_token"

# Test-only seam.  Production can never reach it: it requires an explicit mode
# flag, refuses any API root that is not an http loopback address, and refuses
# outright inside GitHub Actions.  Setting the root without the flag is itself
# a refusal, so a stray environment variable cannot silently redirect a mint.
TEST_MODE_ENV = "GOVML_GOVERNED_READ_TEST_MODE"
TEST_API_ROOT_ENV = "GOVML_GOVERNED_READ_TEST_API_ROOT"
LOOPBACK_API_ROOT = re.compile(r"^http://127\.0\.0\.1:[1-9][0-9]{0,4}$")


class Refusal(RuntimeError):
    """A public refusal carrying a stable code and no credential bytes."""


def _present(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def load_minter(path: Path):
    """Load the signed minter from an exact caller-named path."""
    raw = str(path)
    if "~" in raw:
        raise Refusal("GOVERNED_READ_MINTER_PATH_REFUSED")
    if not path.is_absolute():
        path = Path(os.getcwd()) / path
    if not path.is_file() or path.is_symlink():
        raise Refusal("GOVERNED_READ_MINTER_ABSENT")
    spec = importlib.util.spec_from_file_location(
        "govml_read_app_minter", str(path),
    )
    if spec is None or spec.loader is None:
        raise Refusal("GOVERNED_READ_MINTER_UNLOADABLE")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise Refusal("GOVERNED_READ_MINTER_UNLOADABLE") from None
    for attribute in ("mint_and_verify", "_write_token", "Refusal", "API_ROOT"):
        if not hasattr(module, attribute):
            raise Refusal("GOVERNED_READ_MINTER_CONTRACT_REFUSED")
    return module


def apply_test_seam(module) -> str | None:
    """Honour the loopback test API root, or refuse.  Never reachable in CI."""
    requested = os.environ.get(TEST_API_ROOT_ENV, "").strip()
    enabled = os.environ.get(TEST_MODE_ENV, "").strip() == "1"
    if not requested and not enabled:
        return None
    if (
        not requested
        or not enabled
        or LOOPBACK_API_ROOT.fullmatch(requested) is None
        or os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true"
    ):
        raise Refusal("GOVERNED_READ_TEST_SEAM_REFUSED")
    module.API_ROOT = requested
    return requested


def classify() -> str:
    """Return the route name required by custody, or raise a Refusal."""
    app_id = os.environ.get(APP_ID_ENV, "").strip()
    app_key = os.environ.get(APP_KEY_ENV, "").strip()
    if app_id and app_key:
        return APP_ROUTE
    if app_id or app_key:
        # Exactly one half of the pair is configured.  Downgrading here would
        # silently reinstate the expiring PAT the App route exists to remove.
        raise Refusal("GOVERNED_READ_APP_PAIR_PARTIAL")
    if _present(LEGACY_ENV):
        return LEGACY_ROUTE
    raise Refusal("GOVERNED_READ_CREDENTIAL_ABSENT")


def verify_written(path: Path) -> int:
    if not path.is_file():
        raise Refusal("GOVERNED_READ_OUTPUT_ABSENT")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise Refusal("GOVERNED_READ_OUTPUT_MODE_REFUSED:%04o" % mode)
    size = path.stat().st_size
    if size < 2:
        raise Refusal("GOVERNED_READ_OUTPUT_EMPTY")
    return size


def select(minter_path: Path, output: Path | None, legacy_only: bool) -> str:
    module = load_minter(minter_path)
    apply_test_seam(module)
    route = classify()
    if route == APP_ROUTE and legacy_only:
        # seal_downstream installs its payload as a long-lived downstream
        # repository secret.  Custody states the minted installation token is
        # never stored as a repository secret, and it expires in about an hour,
        # so sealing one would install a credential that is dead on arrival.
        raise Refusal("GOVERNED_READ_APP_ROUTE_NOT_SEALABLE")
    if route == APP_ROUTE:
        try:
            token = module.mint_and_verify()
        except module.Refusal as exc:
            raise Refusal("GOVERNED_READ_APP_MINT_REFUSED:%s" % exc) from None
    else:
        token = os.environ[LEGACY_ENV].strip()
    if output is not None:
        module._write_token(output, token)
        verify_written(output)
    del token
    return route


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--minter", type=Path, required=True,
        help="exact path to the signed github_app_installation_token.py",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--output", type=Path)
    parser.add_argument(
        "--legacy-only", action="store_true",
        help="refuse the App route; for consumers that seal a long-lived secret",
    )
    args = parser.parse_args(argv)
    try:
        route = select(args.minter, args.output, args.legacy_only)
    except Refusal as exc:
        print("REFUSE(%s)" % exc, file=sys.stderr)
        return 2
    print(
        "GOVERNED_READ_CREDENTIAL_READY route=%s written=%s legacy_only=%s"
        % (route, "false" if args.output is None else "true",
           "true" if args.legacy_only else "false")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
