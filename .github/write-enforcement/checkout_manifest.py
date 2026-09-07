#!/usr/bin/env python3
"""Checkout the one commit per repository bound by the WEA manifest."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

TOKEN_ENV = "REA_BUNDLE_READ_TOKEN"
# Internal, child-process-only carrier.  The askpass helper reads this name so
# the same helper serves both the deprecated compatibility environment route
# and a governed read credential handed over in a mode-0600 file.  It is never
# exported to this process's own environment.
CARRIER_ENV = "GOVML_GIT_READ_CREDENTIAL"

ORIGINS = {
    "research_enforcement_activation": "https://github.com/rexcoleman/research_enforcement_activation.git",
    "govML": "https://github.com/rexcoleman/govML.git",
    "Moonshots_Career_Thesis_v2": "https://github.com/rexcoleman/Moonshots_Career_Thesis.git",
    "newsletter": "https://github.com/rexcoleman/newsletter.git",
}


def read_token_file(path: Path) -> str:
    """Read a governed read credential from an exact mode-0600 file."""
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"token file unavailable: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise ValueError(f"token file mode {mode:04o} is not 0600: {path}")
    token = path.read_text(encoding="ascii").strip()
    if not token or any(character.isspace() for character in token):
        raise ValueError(f"token file contents refused: {path}")
    return token


def authenticated_git_environment(root: Path, token_file: Path | None = None) -> dict[str, str]:
    """Create a non-persistent askpass helper; never place the token in argv/config."""
    if token_file is None:
        token = os.environ.get(TOKEN_ENV, "")
        if not token:
            raise ValueError(f"{TOKEN_ENV} unavailable")
    else:
        token = read_token_file(token_file)
    askpass = root / "github-askpass.sh"
    askpass.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
        f"  *Password*) printf '%s\\n' \"${CARRIER_ENV}\" ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    env = os.environ.copy()
    # Artifact/API authority must never become an implicit Git credential.
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    env.update({
        CARRIER_ENV: token,
        "GIT_ASKPASS": str(askpass),
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        # A configured credential helper would let git answer from a cache or
        # store instead of the askpass helper above.  On gios-dev the global
        # config sets `credential.helper = cache --timeout=7200`, which made a
        # local rehearsal with a deliberately WRONG credential still succeed.
        # A hosted runner has no such helper today, so this is latent rather
        # than active there, but the run must depend on the credential it was
        # handed and on nothing else.
        "GIT_CONFIG_NOSYSTEM": "1",
    })
    return env


# `-c credential.helper=` resets the helper list to empty for this invocation
# only; an empty value is the documented way to discard inherited helpers.  It
# carries no credential, so it is safe in argv.
NO_CREDENTIAL_HELPER = ("-c", "credential.helper=")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument(
        "--token-file", type=Path, default=None,
        help="mode-0600 file holding the governed read credential; when "
             "omitted the deprecated %s environment route is used" % TOKEN_ENV,
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    manifest, destination = json.loads(args.manifest.read_bytes()), args.destination
    commits: dict[str, set[str]] = {}
    for row in manifest["members"]:
        commits.setdefault(row["repository"], set()).add(row["commit"])
    external = {repository: values for repository, values in commits.items()
                if repository != "rexcoleman.dev"}
    if set(external) != set(ORIGINS):
        raise ValueError(f"repository population: {sorted(external)}")
    with tempfile.TemporaryDirectory(prefix="rea-bundle-auth-") as raw:
        git_env = authenticated_git_environment(Path(raw), args.token_file)
        for repository, values in external.items():
            if len(values) != 1:
                raise ValueError(f"repository commit population: {repository}")
            target, commit = destination / repository, next(iter(values))
            subprocess.run(
                ["git", *NO_CREDENTIAL_HELPER, "clone", "--filter=blob:none",
                 "--no-checkout", ORIGINS[repository], str(target)],
                check=True, env=git_env,
            )
            subprocess.run(
                ["git", *NO_CREDENTIAL_HELPER, "-C", str(target),
                 "fetch", "origin", commit],
                check=True, env=git_env,
            )
            subprocess.run(
                ["git", *NO_CREDENTIAL_HELPER, "-C", str(target),
                 "checkout", "--detach", commit],
                check=True, env=git_env,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
