#!/usr/bin/env python3
"""Checkout the one commit per repository bound by the WEA manifest."""

import json
import subprocess
import sys
from pathlib import Path

ORIGINS = {
    "research_enforcement_activation": "https://github.com/rexcoleman/research_enforcement_activation.git",
    "govML": "https://github.com/rexcoleman/govML.git",
    "Moonshots_Career_Thesis_v2": "https://github.com/rexcoleman/Moonshots_Career_Thesis.git",
    "newsletter": "https://github.com/rexcoleman/newsletter.git",
}


def main() -> int:
    manifest, destination = json.loads(Path(sys.argv[1]).read_bytes()), Path(sys.argv[2])
    commits: dict[str, set[str]] = {}
    for row in manifest["members"]:
        commits.setdefault(row["repository"], set()).add(row["commit"])
    for repository, values in commits.items():
        if repository == "rexcoleman.dev":
            continue
        if repository not in ORIGINS or len(values) != 1:
            raise ValueError(f"repository commit population: {repository}")
        target, commit = destination / repository, next(iter(values))
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", ORIGINS[repository], str(target)], check=True)
        subprocess.run(["git", "-C", str(target), "fetch", "origin", commit], check=True)
        subprocess.run(["git", "-C", str(target), "checkout", "--detach", commit], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
