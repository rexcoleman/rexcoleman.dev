#!/usr/bin/env python3
"""Fail-closed protected transition for the downstream bundle-read secret.

This program runs only in the owner-approved ``rea-write-enforcement-issuer``
job.  It proves the existing environment ``REA_BUNDLE_READ_TOKEN`` can read an
exact Git commit in each of the five frozen repositories.  Only after every
read succeeds does it use ``REA_SECRETS_WRITE_PAT`` to set the same
Contents-only token as ``REA_BUNDLE_READ_TOKEN`` in the downstream REA
repository.  The signed authority packet travels separately over the issuer's
append-only public Git surface, so this token needs no cross-repository Actions
permission.  Secret values travel only in process memory, child-process
environment, or stdin; they are never argv elements, files, or output.

Every refusal is typed and exits 3.  A failed validation cannot degrade into a
write, and a write without an exact post-name/update observation is a failure.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict


REFUSAL_EXIT = 3
SOURCE_TOKEN_ABSENT = "SOURCE_TOKEN_ABSENT"
WRITE_TOKEN_ABSENT = "WRITE_TOKEN_ABSENT"
MANIFEST_REFUSED = "MANIFEST_REFUSED"
GIT_READ_REFUSED = "GIT_READ_REFUSED"
SECRET_WRITE_REFUSED = "SECRET_WRITE_REFUSED"
SECRET_POSTCHECK_REFUSED = "SECRET_POSTCHECK_REFUSED"

SOURCE_ENV = "REA_BUNDLE_READ_TOKEN"
WRITE_ENV = "REA_SECRETS_WRITE_PAT"
TARGET_REPOSITORY = "rexcoleman/research_enforcement_activation"
SECRET_NAME = "REA_BUNDLE_READ_TOKEN"
LOGICAL_REPOSITORIES = {
    "research_enforcement_activation": "rexcoleman/research_enforcement_activation",
    "govML": "rexcoleman/govML",
    "Moonshots_Career_Thesis_v2": "rexcoleman/Moonshots_Career_Thesis",
    "newsletter": "rexcoleman/newsletter",
    "rexcoleman.dev": "rexcoleman/rexcoleman.dev",
}


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def redact(text: str, *secrets: str) -> str:
    for secret in secrets:
        for candidate in {secret, secret.strip()}:
            if candidate:
                text = text.replace(candidate, "***")
    return text


def api(token: str, path: str, *, raw: bool = False):
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "rea-protected-bundle-secret-transition",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        status = getattr(exc, "code", type(exc).__name__)
        raise Refusal(GIT_READ_REFUSED, "status=%s path=%s" % (status, path)) from None
    if raw:
        return body
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal(GIT_READ_REFUSED, "malformed_json path=%s" % path) from None


def manifest_commits(path: Path) -> Dict[str, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refusal(MANIFEST_REFUSED, type(exc).__name__) from None
    rows = value.get("members") if isinstance(value, dict) else None
    if not isinstance(rows, list) or not rows:
        raise Refusal(MANIFEST_REFUSED, "members_absent")
    commits: Dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise Refusal(MANIFEST_REFUSED, "member_shape")
        logical, commit = row.get("repository"), row.get("commit")
        if logical not in LOGICAL_REPOSITORIES or not isinstance(commit, str):
            raise Refusal(MANIFEST_REFUSED, "member_identity")
        if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
            raise Refusal(MANIFEST_REFUSED, "commit_shape repository=%s" % logical)
        if logical in commits and commits[logical] != commit:
            raise Refusal(MANIFEST_REFUSED, "commit_ambiguous repository=%s" % logical)
        commits[logical] = commit
    if set(commits) != set(LOGICAL_REPOSITORIES):
        raise Refusal(MANIFEST_REFUSED, "repository_set")
    return commits


def validate_source_reads(token: str, commits: Dict[str, str]) -> None:
    for logical, repository in LOGICAL_REPOSITORIES.items():
        commit = commits[logical]
        try:
            value = api(token, "/repos/%s/git/commits/%s" % (repository, commit))
        except Refusal as exc:
            raise Refusal(GIT_READ_REFUSED, "repository=%s %s" % (repository, exc.detail)) from None
        if (
            not isinstance(value, dict)
            or value.get("sha") != commit
            or not isinstance(value.get("tree"), dict)
            or not isinstance(value["tree"].get("sha"), str)
        ):
            raise Refusal(GIT_READ_REFUSED, "repository=%s identity" % repository)



def run_gh(argv, *, token: str, stdin_value: str = "", source_secret: str = ""):
    environment = dict(os.environ)
    environment["GH_TOKEN"] = token
    completed = subprocess.run(
        argv,
        input=stdin_value,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=environment,
        timeout=120,
    )
    return (
        completed.returncode,
        redact(completed.stdout, token, source_secret),
        redact(completed.stderr, token, source_secret),
    )


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)


def copy_and_verify(bundle_token: str, write_token: str, gh: str) -> None:
    before = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    code, out, err = run_gh(
        [gh, "secret", "set", SECRET_NAME, "--repo", TARGET_REPOSITORY],
        token=write_token,
        stdin_value=bundle_token,
        source_secret=bundle_token,
    )
    if code:
        raise Refusal(SECRET_WRITE_REFUSED, "gh_exit=%s %s" % (code, (err or out).strip()))
    code, out, err = run_gh(
        [gh, "secret", "list", "--repo", TARGET_REPOSITORY, "--json", "name,updatedAt"],
        token=write_token,
        source_secret=bundle_token,
    )
    if code:
        raise Refusal(SECRET_POSTCHECK_REFUSED, "gh_exit=%s %s" % (code, err.strip()))
    try:
        rows = json.loads(out)
        matches = [row for row in rows if row.get("name") == SECRET_NAME]
        updated = parse_time(matches[0]["updatedAt"]) if len(matches) == 1 else None
    except (KeyError, TypeError, ValueError):
        raise Refusal(SECRET_POSTCHECK_REFUSED, "malformed") from None
    if updated is None or updated < before:
        raise Refusal(SECRET_POSTCHECK_REFUSED, "name_or_update_not_observed")


def transition(args, environ) -> int:
    bundle_token = environ.get(SOURCE_ENV, "") or ""
    write_token = environ.get(WRITE_ENV, "") or ""
    if not bundle_token.strip():
        raise Refusal(SOURCE_TOKEN_ABSENT, SOURCE_ENV)
    if not write_token.strip():
        raise Refusal(WRITE_TOKEN_ABSENT, WRITE_ENV)
    if bundle_token == write_token:
        raise Refusal(WRITE_TOKEN_ABSENT, "source_and_write_tokens_must_be_distinct")
    commits = manifest_commits(Path(args.manifest))
    validate_source_reads(bundle_token, commits)
    print(
        "PROTECTED_BUNDLE_CONTENTS_READ_VALIDATED repositories=5 "
        "actions_permission_required=false"
    )
    copy_and_verify(bundle_token, write_token, args.gh)
    print(
        "DOWNSTREAM_BUNDLE_SECRET_PROVISIONED repository=%s secret=%s "
        "post_name_check=pass secret_bytes_printed=false"
        % (TARGET_REPOSITORY, SECRET_NAME)
    )
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--manifest", required=True)
    value.add_argument("--gh", default="gh")
    return value


def main(argv=None, environ=None) -> int:
    args = parser().parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        return transition(args, environ)
    except Refusal as exc:
        print("REFUSED %s: %s" % (exc.code, exc.detail), file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT
    except Exception as exc:
        print("REFUSED UNEXPECTED_%s" % type(exc).__name__, file=sys.stderr)
        print("secret_bytes_printed=false", file=sys.stderr)
        return REFUSAL_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
