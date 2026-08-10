#!/usr/bin/env python3
"""Checkout the one commit per repository bound by the WEA manifest."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TOKEN_ENV = "REA_BUNDLE_READ_TOKEN"

ORIGINS = {
    "research_enforcement_activation": "https://github.com/rexcoleman/research_enforcement_activation.git",
    "govML": "https://github.com/rexcoleman/govML.git",
    "Moonshots_Career_Thesis_v2": "https://github.com/rexcoleman/Moonshots_Career_Thesis.git",
    "newsletter": "https://github.com/rexcoleman/newsletter.git",
}


def authenticated_git_environment(root: Path) -> dict[str, str]:
    """Create a non-persistent askpass helper; never place the token in argv/config."""
    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        raise ValueError(f"{TOKEN_ENV} unavailable")
    askpass = root / "github-askpass.sh"
    askpass.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
        f"  *Password*) printf '%s\\n' \"${TOKEN_ENV}\" ;;\n"
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
        "GIT_ASKPASS": str(askpass),
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
    })
    return env


def main() -> int:
    manifest, destination = json.loads(Path(sys.argv[1]).read_bytes()), Path(sys.argv[2])
    commits: dict[str, set[str]] = {}
    for row in manifest["members"]:
        commits.setdefault(row["repository"], set()).add(row["commit"])
    external = {repository: values for repository, values in commits.items()
                if repository != "rexcoleman.dev"}
    if set(external) != set(ORIGINS):
        raise ValueError(f"repository population: {sorted(external)}")
    with tempfile.TemporaryDirectory(prefix="rea-bundle-auth-") as raw:
        git_env = authenticated_git_environment(Path(raw))
        for repository, values in external.items():
            if len(values) != 1:
                raise ValueError(f"repository commit population: {repository}")
            target, commit = destination / repository, next(iter(values))
            subprocess.run(
                ["git", "clone", "--filter=blob:none", "--no-checkout",
                 ORIGINS[repository], str(target)],
                check=True, env=git_env,
            )
            subprocess.run(
                ["git", "-C", str(target), "fetch", "origin", commit],
                check=True, env=git_env,
            )
            subprocess.run(
                ["git", "-C", str(target), "checkout", "--detach", commit],
                check=True, env=git_env,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
