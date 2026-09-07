#!/usr/bin/env python3
"""Mint and verify one short-lived read-only GitHub App installation token.

The long-lived App private key is accepted only through the canonical
environment variable and is never written outside a mode-0600 temporary key
file.  The minted token is either withheld (``--check``) or atomically written
to a caller-selected mode-0600 file.  No credential bytes are printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


APP_ID_ENV = "GOVML_REA_READ_APP_ID"
PRIVATE_KEY_ENV = "GOVML_REA_READ_APP_PRIVATE_KEY_B64"
API_ROOT = "https://api.github.com"
OWNER = "rexcoleman"
REQUIRED_REPOSITORIES = frozenset({
    "govML",
    "research_enforcement_activation",
    "Moonshots_Career_Thesis",
    "newsletter",
    "rexcoleman.dev",
})
API_VERSION = "2022-11-28"


class Refusal(RuntimeError):
    """A public refusal containing a stable code and no credential bytes."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _credentials() -> tuple[str, bytes]:
    app_id = os.environ.get(APP_ID_ENV, "").strip()
    encoded_key = os.environ.get(PRIVATE_KEY_ENV, "").strip()
    if not app_id and not encoded_key:
        raise Refusal("GITHUB_APP_CREDENTIALS_ABSENT")
    if re.fullmatch(r"[1-9][0-9]*", app_id) is None or not encoded_key:
        raise Refusal("GITHUB_APP_CREDENTIALS_PARTIAL_OR_INVALID")
    try:
        key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Refusal("GITHUB_APP_PRIVATE_KEY_INVALID") from None
    if (
        len(key) < 256
        or len(key) > 32_768
        or b"-----BEGIN" not in key
        or b"PRIVATE KEY-----" not in key
        or b"\x00" in key
    ):
        raise Refusal("GITHUB_APP_PRIVATE_KEY_INVALID")
    return app_id, key


def _sign_jwt(app_id: str, key: bytes, now: int | None = None) -> str:
    issued = int(time.time() if now is None else now)
    header = _b64url(json.dumps(
        {"alg": "RS256", "typ": "JWT"}, separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii"))
    payload = _b64url(json.dumps(
        {"exp": issued + 540, "iat": issued - 60, "iss": app_id},
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii"))
    signing_input = f"{header}.{payload}".encode("ascii")
    with tempfile.TemporaryDirectory(prefix="govml-app-key-") as raw_root:
        key_path = Path(raw_root) / "private-key.pem"
        key_path.write_bytes(key)
        key_path.chmod(0o600)
        try:
            completed = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
                input=signing_input,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            raise Refusal("GITHUB_APP_SIGNER_UNAVAILABLE") from None
    if completed.returncode != 0 or not completed.stdout:
        raise Refusal("GITHUB_APP_PRIVATE_KEY_INVALID")
    return f"{header}.{payload}.{_b64url(completed.stdout)}"


def _api(
    method: str,
    path: str,
    bearer: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    raw = None if payload is None else json.dumps(
        payload, separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    request = Request(
        API_ROOT + path,
        data=raw,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {bearer}",
            "X-GitHub-Api-Version": API_VERSION,
            **({"Content-Type": "application/json"} if raw is not None else {}),
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            body = response.read()
    except HTTPError as exc:
        raise Refusal(f"GITHUB_APP_API_REFUSED_HTTP_{exc.code}") from None
    except (OSError, URLError):
        raise Refusal("GITHUB_APP_API_UNAVAILABLE") from None
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise Refusal("GITHUB_APP_API_RESPONSE_INVALID") from None
    if not isinstance(value, dict):
        raise Refusal("GITHUB_APP_API_RESPONSE_INVALID")
    return value


def mint_and_verify() -> str:
    app_id, key = _credentials()
    jwt = _sign_jwt(app_id, key)
    installation_ids: set[int] = set()
    for repository in sorted(REQUIRED_REPOSITORIES):
        value = _api(
            "GET", f"/repos/{OWNER}/{repository}/installation", jwt,
        )
        installation_id = value.get("id")
        account = value.get("account")
        permissions = value.get("permissions")
        if (
            isinstance(installation_id, bool)
            or not isinstance(installation_id, int)
            or installation_id <= 0
            or not isinstance(account, dict)
            or account.get("login") != OWNER
            or not isinstance(permissions, dict)
            or permissions.get("contents") != "read"
            or any(level not in {"read"} for level in permissions.values())
        ):
            raise Refusal("GITHUB_APP_INSTALLATION_SCOPE_INVALID")
        installation_ids.add(installation_id)
    if len(installation_ids) != 1:
        raise Refusal("GITHUB_APP_INSTALLATION_IDENTITY_AMBIGUOUS")
    installation_id = next(iter(installation_ids))
    issued = _api(
        "POST", f"/app/installations/{installation_id}/access_tokens", jwt,
        {
            "permissions": {"contents": "read"},
            "repositories": sorted(REQUIRED_REPOSITORIES),
        },
    )
    token = issued.get("token")
    permissions = issued.get("permissions")
    repositories = issued.get("repositories")
    observed_repositories = {
        row.get("name") for row in repositories
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    } if isinstance(repositories, list) else set()
    if (
        not isinstance(token, str)
        or re.fullmatch(r"\S{20,}", token) is None
        or not isinstance(permissions, dict)
        or permissions.get("contents") != "read"
        or any(level not in {"read"} for level in permissions.values())
        or observed_repositories != REQUIRED_REPOSITORIES
    ):
        raise Refusal("GITHUB_APP_INSTALLATION_TOKEN_SCOPE_INVALID")
    for repository in sorted(REQUIRED_REPOSITORIES):
        value = _api("GET", f"/repos/{OWNER}/{repository}", token)
        if value.get("full_name") != f"{OWNER}/{repository}":
            raise Refusal("GITHUB_APP_REPOSITORY_READ_INVALID")
    return token


def _write_token(path: Path, token: str) -> None:
    selected = path.absolute()
    selected.parent.mkdir(parents=True, exist_ok=True)
    fd, pending_name = tempfile.mkstemp(
        prefix=f".{selected.name}.", dir=selected.parent,
    )
    pending = Path(pending_name)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(token + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(pending, selected)
    finally:
        if pending.exists():
            pending.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        token = mint_and_verify()
        if args.output is not None:
            _write_token(args.output, token)
    except Refusal as exc:
        print(f"REFUSE({exc})")
        return 2
    print(
        "GITHUB_APP_INSTALLATION_TOKEN_READY "
        f"repository_count={len(REQUIRED_REPOSITORIES)} contents=read"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
