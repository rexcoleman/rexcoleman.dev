#!/usr/bin/env python3
"""Dispatch the govML external-judge workflow as the registered GitHub App.

The long-lived App private key is accepted only from the protected GitHub
environment.  Neither it nor the minted installation token is printed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API = "https://api.github.com"
API_VERSION = "2022-11-28"
APP_ID_ENV = "GOVML_REA_READ_APP_ID"
APP_KEY_ENV = "GOVML_REA_READ_APP_PRIVATE_KEY_B64"
OWNER = "rexcoleman"
REPOSITORY = "govML"
WORKFLOW = "issue-external-judge-authority.yml"


class Refusal(RuntimeError):
    """Stable non-secret refusal."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _credentials() -> tuple[str, bytes]:
    app_id = os.environ.get(APP_ID_ENV, "").strip()
    encoded = os.environ.get(APP_KEY_ENV, "").strip()
    if re.fullmatch(r"[1-9][0-9]*", app_id) is None or not encoded:
        raise Refusal("APP_CREDENTIALS_ABSENT_OR_PARTIAL")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Refusal("APP_PRIVATE_KEY_INVALID") from None
    if not (256 <= len(key) <= 32768) or b"PRIVATE KEY-----" not in key or b"\0" in key:
        raise Refusal("APP_PRIVATE_KEY_INVALID")
    return app_id, key


def _jwt(app_id: str, key: bytes, now: int | None = None) -> str:
    issued = int(time.time() if now is None else now)
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":"), sort_keys=True).encode("ascii"))
    payload = _b64url(json.dumps({"exp": issued + 540, "iat": issued - 60, "iss": app_id}, separators=(",", ":"), sort_keys=True).encode("ascii"))
    signing_input = f"{header}.{payload}".encode("ascii")
    with tempfile.TemporaryDirectory(prefix="s213-app-key-") as root:
        path = Path(root) / "key.pem"
        path.write_bytes(key)
        path.chmod(0o600)
        try:
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(path)],
                input=signing_input, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False,
            )
        except OSError:
            raise Refusal("APP_SIGNER_UNAVAILABLE") from None
    if result.returncode or not result.stdout:
        raise Refusal("APP_PRIVATE_KEY_INVALID")
    return f"{header}.{payload}.{_b64url(result.stdout)}"


def _request(method: str, path: str, bearer: str, payload: dict | None = None) -> tuple[int, bytes]:
    raw = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    request = Request(
        API + path, data=raw, method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + bearer,
            "X-GitHub-Api-Version": API_VERSION,
            **({"Content-Type": "application/json"} if raw is not None else {}),
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()
    except (OSError, URLError):
        raise Refusal("GITHUB_API_UNAVAILABLE") from None


def _object(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise Refusal("GITHUB_RESPONSE_INVALID") from None
    if not isinstance(value, dict):
        raise Refusal("GITHUB_RESPONSE_INVALID")
    return value


def dispatch(request_b64: str, request_sha256: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", request_sha256) is None:
        raise Refusal("REQUEST_SHA256_INVALID")
    try:
        request_raw = base64.b64decode(request_b64, validate=True)
        request_raw.decode("ascii")
    except (ValueError, UnicodeError):
        raise Refusal("REQUEST_BYTES_INVALID") from None
    if hashlib.sha256(request_raw).hexdigest() != request_sha256:
        raise Refusal("REQUEST_DIGEST_MISMATCH")

    app_id, key = _credentials()
    jwt = _jwt(app_id, key)
    status, raw = _request("GET", f"/repos/{OWNER}/{REPOSITORY}/installation", jwt)
    if status != 200:
        raise Refusal(f"APP_INSTALLATION_LOOKUP_HTTP_{status}")
    installation = _object(raw)
    installation_id = installation.get("id")
    if not isinstance(installation_id, int) or isinstance(installation_id, bool) or installation_id <= 0:
        raise Refusal("APP_INSTALLATION_ID_INVALID")

    # Omit a permissions override: the token receives the installation's
    # current permissions.  The dispatch itself is the empirical actions:write
    # test and must return GitHub's real authorization result.
    status, raw = _request(
        "POST", f"/app/installations/{installation_id}/access_tokens", jwt,
        {"repositories": [REPOSITORY]},
    )
    if status != 201:
        raise Refusal(f"APP_TOKEN_MINT_HTTP_{status}")
    issued = _object(raw)
    token = issued.get("token")
    repositories = issued.get("repositories")
    names = {
        row.get("name") for row in repositories
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    } if isinstance(repositories, list) else set()
    if not isinstance(token, str) or re.fullmatch(r"\S{20,}", token) is None or names != {REPOSITORY}:
        raise Refusal("APP_TOKEN_SCOPE_INVALID")

    status, raw = _request(
        "POST",
        f"/repos/{OWNER}/{REPOSITORY}/actions/workflows/{WORKFLOW}/dispatches",
        token,
        {
            "ref": "main",
            "inputs": {
                "request_b64": request_b64,
                "request_sha256": request_sha256,
            },
        },
    )
    if status == 204:
        print(f"APP_DISPATCH_ACCEPTED repository={OWNER}/{REPOSITORY} workflow={WORKFLOW} request_sha256={request_sha256}")
        return
    message = ""
    try:
        value = _object(raw)
        if isinstance(value.get("message"), str):
            message = value["message"]
    except Refusal:
        pass
    if status == 403 and message == "Resource not accessible by integration":
        raise Refusal("APP_DISPATCH_HTTP_403_RESOURCE_NOT_ACCESSIBLE_BY_INTEGRATION")
    raise Refusal(f"APP_DISPATCH_HTTP_{status}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-b64", required=True)
    parser.add_argument("--request-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        dispatch(args.request_b64, args.request_sha256)
    except Refusal as exc:
        print("APP_DISPATCH_REFUSED reason=" + str(exc))
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
