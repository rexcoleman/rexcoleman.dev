"""s210: the governed read credential lane, rehearsed end to end.

Two branches are rehearsed here so that the only untested variable left is the
real GitHub App itself:

* the REFUSAL branch -- nothing configured, a PARTIAL App pair, the deprecated
  compatibility fallback, App precedence over that fallback, and the
  ``--legacy-only`` refusal that stops a one-hour installation token from being
  sealed into a permanent downstream repository secret; and

* the SUCCESS branch -- a hermetic stub of the three GitHub App API calls the
  minter makes, reached through a test-only seam that refuses in production,
  driving a real mint, a real atomic mode-0600 write, a real authenticated
  clone of a real local git remote over HTTP Basic auth, and the removal of the
  credential file.

The minter itself is byte-identical to the signed govML template copy and is
NOT modified here; the seam lives in the selector, which this repository owns.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
ISSUER = WORKFLOWS / "issue-write-enforcement-attestation.yml"
EXTERNAL_JUDGE = WORKFLOWS / "issue-external-judge-authority.yml"
VERIFIER = WORKFLOWS / "verify-write-enforcement.yml"

SELECTOR = ROOT / "select_governed_read_credential.py"
MINTER = ROOT / "github_app_installation_token.py"
GIT_HTTP_BACKEND = Path("/usr/lib/git-core/git-http-backend")

REPOSITORIES = (
    "govML",
    "research_enforcement_activation",
    "Moonshots_Career_Thesis",
    "newsletter",
    "rexcoleman.dev",
)
# checkout_manifest's own logical names, which differ from the App's repository
# slugs for the Moonshots repository.
BUNDLE_REPOSITORIES = (
    "research_enforcement_activation",
    "govML",
    "Moonshots_Career_Thesis_v2",
    "newsletter",
)

sys.path.insert(0, str(ROOT))
import checkout_manifest  # noqa: E402

INSTALLATION_ID = 991234
MINTED_TOKEN = "ghs_s210RehearsalInstallationToken0123456789"
LEGACY_TOKEN = "ghp_s210RehearsalLegacyCompatibilityToken00"


# --------------------------------------------------------------------------
# Stub GitHub App API.  Three endpoints, exactly what mint_and_verify() calls.
# --------------------------------------------------------------------------
class _AppApiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # pragma: no cover - noise suppression
        pass

    def _reply(self, status, payload):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.seen.append(("GET", path))
        matched = re.fullmatch(r"/repos/rexcoleman/([A-Za-z0-9_.\-]+)/installation", path)
        if matched and matched.group(1) in REPOSITORIES:
            self._reply(200, {
                "id": INSTALLATION_ID,
                "account": {"login": "rexcoleman"},
                "permissions": {"contents": "read"},
            })
            return
        matched = re.fullmatch(r"/repos/rexcoleman/([A-Za-z0-9_.\-]+)", path)
        if matched and matched.group(1) in REPOSITORIES:
            authorization = self.headers.get("Authorization", "")
            if authorization != "Bearer " + MINTED_TOKEN:
                self._reply(403, {"message": "installation token required"})
                return
            self._reply(200, {"full_name": "rexcoleman/" + matched.group(1)})
            return
        self._reply(404, {"message": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        self.server.seen.append(("POST", path))
        if path == "/app/installations/%d/access_tokens" % INSTALLATION_ID:
            self._reply(201, {
                "token": MINTED_TOKEN,
                "permissions": {"contents": "read"},
                "repositories": [{"name": name} for name in REPOSITORIES],
            })
            return
        self._reply(404, {"message": "not found"})


# --------------------------------------------------------------------------
# Authenticated local git remote.  Basic auth is REQUIRED, so a clone can only
# succeed if the credential really travelled through the askpass helper.
# --------------------------------------------------------------------------
class _GitHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # pragma: no cover - noise suppression
        pass

    def _authorized(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header[6:]).decode("utf-8")
        except Exception:
            return False
        user, _, password = raw.partition(":")
        self.server.presented.append((user, password))
        return user == "x-access-token" and password == self.server.expected

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def _serve(self, method):
        if not self._authorized():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="git"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        parsed = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        environment = {
            "PATH": "/usr/bin:/bin",
            "GIT_PROJECT_ROOT": str(self.server.project_root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": parsed.path,
            "QUERY_STRING": parsed.query,
            "REQUEST_METHOD": method,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(length),
            "REMOTE_USER": "x-access-token",
            "REMOTE_ADDR": "127.0.0.1",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "GIT_PROTOCOL": self.headers.get("Git-Protocol", ""),
        }
        completed = subprocess.run(
            [str(GIT_HTTP_BACKEND)], input=body, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment,
        )
        head, _, payload = completed.stdout.partition(b"\r\n\r\n")
        status = 200
        headers = []
        for line in head.split(b"\r\n"):
            if not line:
                continue
            name, _, value = line.partition(b":")
            name, value = name.strip().decode(), value.strip().decode()
            if name.lower() == "status":
                status = int(value.split()[0])
            else:
                headers.append((name, value))
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _serve(handler, **attributes):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    for name, value in attributes.items():
        setattr(server, name, value)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


@pytest.fixture
def app_api():
    server, root = _serve(_AppApiHandler, seen=[])
    try:
        yield server, root
    finally:
        server.shutdown()
        server.server_close()


def _throwaway_private_key(tmp_path: Path) -> str:
    """A throwaway RSA key, base64 as the transport encoding demands."""
    pem = tmp_path / "throwaway-app-key.pem"
    completed = subprocess.run(
        ["openssl", "genrsa", "-out", str(pem), "2048"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    assert completed.returncode == 0, "openssl genrsa unavailable"
    return base64.b64encode(pem.read_bytes()).decode("ascii")


def run_selector(arguments, environment):
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    base.update(environment)
    return subprocess.run(
        [sys.executable, str(SELECTOR), "--minter", str(MINTER), *arguments],
        capture_output=True, text=True, env=base, check=False,
    )


# ==========================================================================
# Branch 1 -- refusal and precedence
# ==========================================================================
def test_selector_refuses_when_no_credential_is_configured(tmp_path):
    result = run_selector(["--output", str(tmp_path / "token")], {})
    assert result.returncode == 2, result.stdout + result.stderr
    assert "GOVERNED_READ_CREDENTIAL_ABSENT" in result.stderr
    assert not (tmp_path / "token").exists()


@pytest.mark.parametrize("configured", [
    {"GOVML_REA_READ_APP_ID": "4412331", "GOVML_REA_READ_APP_PRIVATE_KEY_B64": ""},
    {"GOVML_REA_READ_APP_ID": "", "GOVML_REA_READ_APP_PRIVATE_KEY_B64": "Zm9v"},
])
def test_a_partial_app_pair_refuses_and_never_downgrades(tmp_path, configured):
    # The compatibility label is ALSO present.  Custody says a partial pair
    # refuses rather than falling back to it.
    environment = dict(configured, REA_BUNDLE_READ_TOKEN=LEGACY_TOKEN)
    result = run_selector(["--output", str(tmp_path / "token")], environment)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "GOVERNED_READ_APP_PAIR_PARTIAL" in result.stderr
    assert not (tmp_path / "token").exists()


def test_the_deprecated_compatibility_route_is_selected_when_the_app_is_absent(tmp_path):
    output = tmp_path / "token"
    result = run_selector(
        ["--output", str(output)], {"REA_BUNDLE_READ_TOKEN": LEGACY_TOKEN},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "route=deprecated_compatibility_rea_bundle_read_token" in result.stdout
    assert output.read_text().strip() == LEGACY_TOKEN
    assert oct(output.stat().st_mode & 0o777) == "0o600"
    # No credential and no digest of one may appear in either stream.
    combined = result.stdout + result.stderr
    assert LEGACY_TOKEN not in combined
    assert hashlib.sha256(LEGACY_TOKEN.encode()).hexdigest() not in combined


def test_legacy_only_accepts_the_compatibility_route(tmp_path):
    result = run_selector(
        ["--legacy-only", "--check"], {"REA_BUNDLE_READ_TOKEN": LEGACY_TOKEN},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "legacy_only=true" in result.stdout


def test_legacy_only_refuses_a_complete_app_pair(tmp_path):
    result = run_selector(["--legacy-only", "--check"], {
        "GOVML_REA_READ_APP_ID": "4412331",
        "GOVML_REA_READ_APP_PRIVATE_KEY_B64": "Zm9v",
        "REA_BUNDLE_READ_TOKEN": LEGACY_TOKEN,
    })
    assert result.returncode == 2, result.stdout + result.stderr
    assert "GOVERNED_READ_APP_ROUTE_NOT_SEALABLE" in result.stderr


def test_the_minter_path_must_be_named_and_may_not_be_home_relative(tmp_path):
    result = subprocess.run(
        [sys.executable, str(SELECTOR), "--minter",
         "~/research_enforcement_activation/scripts/github_app_installation_token.py",
         "--check"],
        capture_output=True, text=True, check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
             "HOME": os.environ.get("HOME", "/tmp")},
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "GOVERNED_READ_MINTER_PATH_REFUSED" in result.stderr

    absent = subprocess.run(
        [sys.executable, str(SELECTOR), "--minter", str(tmp_path / "nope.py"),
         "--check"],
        capture_output=True, text=True, check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    assert absent.returncode == 2, absent.stdout + absent.stderr
    assert "GOVERNED_READ_MINTER_ABSENT" in absent.stderr


# ==========================================================================
# The test seam, and the proof that production cannot reach it
# ==========================================================================
def test_the_api_root_seam_refuses_without_the_explicit_test_flag(tmp_path, app_api):
    _, root = app_api
    result = run_selector(["--check"], {
        "GOVML_REA_READ_APP_ID": "4412331",
        "GOVML_REA_READ_APP_PRIVATE_KEY_B64": "Zm9v",
        "GOVML_GOVERNED_READ_TEST_API_ROOT": root,
    })
    assert result.returncode == 2, result.stdout + result.stderr
    assert "GOVERNED_READ_TEST_SEAM_REFUSED" in result.stderr


def test_the_api_root_seam_refuses_a_non_loopback_root(tmp_path):
    result = run_selector(["--check"], {
        "GOVML_REA_READ_APP_ID": "4412331",
        "GOVML_REA_READ_APP_PRIVATE_KEY_B64": "Zm9v",
        "GOVML_GOVERNED_READ_TEST_MODE": "1",
        "GOVML_GOVERNED_READ_TEST_API_ROOT": "https://api.github.com",
    })
    assert result.returncode == 2, result.stdout + result.stderr
    assert "GOVERNED_READ_TEST_SEAM_REFUSED" in result.stderr


def test_the_api_root_seam_refuses_inside_github_actions(tmp_path, app_api):
    _, root = app_api
    result = run_selector(["--check"], {
        "GOVML_REA_READ_APP_ID": "4412331",
        "GOVML_REA_READ_APP_PRIVATE_KEY_B64": "Zm9v",
        "GOVML_GOVERNED_READ_TEST_MODE": "1",
        "GOVML_GOVERNED_READ_TEST_API_ROOT": root,
        "GITHUB_ACTIONS": "true",
    })
    assert result.returncode == 2, result.stdout + result.stderr
    assert "GOVERNED_READ_TEST_SEAM_REFUSED" in result.stderr


def test_the_seam_exists_only_in_the_selector_and_not_in_the_signed_minter():
    """The minter must stay byte-identical to the signed govML copy."""
    raw = MINTER.read_text(encoding="utf-8")
    assert "GOVML_GOVERNED_READ_TEST_MODE" not in raw
    assert "GOVML_GOVERNED_READ_TEST_API_ROOT" not in raw
    assert 'API_ROOT = "https://api.github.com"' in raw


# ==========================================================================
# Branch 2 -- a real mint against the stub, then a real authenticated clone
# ==========================================================================
def _app_environment(tmp_path, root):
    return {
        "GOVML_REA_READ_APP_ID": "4412331",
        "GOVML_REA_READ_APP_PRIVATE_KEY_B64": _throwaway_private_key(tmp_path),
        "GOVML_GOVERNED_READ_TEST_MODE": "1",
        "GOVML_GOVERNED_READ_TEST_API_ROOT": root,
        # The compatibility name is deliberately ALSO present: custody says the
        # complete App pair still wins.
        "REA_BUNDLE_READ_TOKEN": LEGACY_TOKEN,
    }


def test_a_complete_app_pair_mints_and_wins_over_the_compatibility_name(tmp_path, app_api):
    server, root = app_api
    output = tmp_path / "governed-read-credential"
    result = run_selector(["--output", str(output)], _app_environment(tmp_path, root))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "route=github_app_installation_token" in result.stdout
    assert output.read_text().strip() == MINTED_TOKEN
    assert output.read_text().strip() != LEGACY_TOKEN
    assert oct(output.stat().st_mode & 0o777) == "0o600"
    combined = result.stdout + result.stderr
    assert MINTED_TOKEN not in combined
    assert hashlib.sha256(MINTED_TOKEN.encode()).hexdigest() not in combined
    # All three API surfaces were exercised.
    paths = [path for _, path in server.seen]
    assert sum(path.endswith("/installation") for path in paths) == len(REPOSITORIES)
    assert ("POST", "/app/installations/%d/access_tokens" % INSTALLATION_ID) in server.seen
    assert sum(
        re.fullmatch(r"/repos/rexcoleman/[A-Za-z0-9_.\-]+", path) is not None
        for path in paths
    ) == len(REPOSITORIES)


def test_check_mode_withholds_the_token(tmp_path, app_api):
    _, root = app_api
    result = run_selector(["--check"], _app_environment(tmp_path, root))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "written=false" in result.stdout
    assert MINTED_TOKEN not in result.stdout + result.stderr


# --------------------------------------------------------------------------
def _seed_local_remotes(tmp_path):
    """Four bare repositories in a temp dir, each with one known commit."""
    serve_root = tmp_path / "srv"
    serve_root.mkdir()
    environment = dict(
        os.environ,
        GIT_AUTHOR_NAME="s210", GIT_AUTHOR_EMAIL="s210@example.invalid",
        GIT_COMMITTER_NAME="s210", GIT_COMMITTER_EMAIL="s210@example.invalid",
    )
    commits = {}
    for name in BUNDLE_REPOSITORIES:
        work = tmp_path / "work" / name
        work.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(work)], check=True)
        (work / "MEMBER.txt").write_text(name + "\n")
        subprocess.run(["git", "-C", str(work), "add", "MEMBER.txt"],
                       check=True, env=environment)
        subprocess.run(["git", "-C", str(work), "commit", "-qm", "seed"],
                       check=True, env=environment)
        commits[name] = subprocess.run(
            ["git", "-C", str(work), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        bare = serve_root / (name + ".git")
        subprocess.run(["git", "clone", "-q", "--bare", str(work), str(bare)], check=True)
        for key in ("uploadpack.allowfilter",
                    "uploadpack.allowanysha1inwant",
                    "uploadpack.allowreachablesha1inwant"):
            subprocess.run(["git", "-C", str(bare), "config", key, "true"], check=True)
        subprocess.run(["git", "-C", str(bare), "update-server-info"], check=True)
    return serve_root, commits


def _manifest(tmp_path, commits):
    members = [
        {"member_id": "seed-" + name, "repository": name, "path": "MEMBER.txt",
         "commit": commit, "sha256": "0" * 64, "byte_length": 1}
        for name, commit in commits.items()
    ]
    members.append({
        "member_id": "seed-rexdev", "repository": "rexcoleman.dev",
        "path": "MEMBER.txt", "commit": "1" * 40, "sha256": "0" * 64,
        "byte_length": 1,
    })
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"members": members}))
    return path


@pytest.mark.skipif(not GIT_HTTP_BACKEND.exists(), reason="git-http-backend absent")
def test_the_minted_token_file_authenticates_a_real_clone_then_is_removed(
    tmp_path, app_api, monkeypatch,
):
    _, api_root = app_api
    output = tmp_path / "governed-read-credential"
    minted = run_selector(["--output", str(output)], _app_environment(tmp_path, api_root))
    assert minted.returncode == 0, minted.stdout + minted.stderr

    serve_root, commits = _seed_local_remotes(tmp_path)
    git_server, git_root = _serve(
        _GitHandler, project_root=serve_root, expected=MINTED_TOKEN, presented=[],
    )
    try:
        monkeypatch.setattr(checkout_manifest, "ORIGINS", {
            name: "%s/%s.git" % (git_root, name) for name in BUNDLE_REPOSITORIES
        })
        monkeypatch.delenv(checkout_manifest.TOKEN_ENV, raising=False)
        destination = tmp_path / "repos"
        code = checkout_manifest.main([
            str(_manifest(tmp_path, commits)), str(destination),
            "--token-file", str(output),
        ])
        assert code == 0
        for name, commit in commits.items():
            observed = subprocess.run(
                ["git", "-C", str(destination / name), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            assert observed == commit
        # The credential really travelled through the askpass helper: the
        # server required Basic auth and saw exactly the minted token.
        assert git_server.presented, "the remote was never authenticated against"
        assert {user for user, _ in git_server.presented} == {"x-access-token"}
        assert {password for _, password in git_server.presented} == {MINTED_TOKEN}
    finally:
        git_server.shutdown()
        git_server.server_close()

    # Removal, as the workflow performs it before any checked-out code runs.
    output.unlink()
    assert not output.exists()


@pytest.mark.skipif(not GIT_HTTP_BACKEND.exists(), reason="git-http-backend absent")
def test_a_wrong_credential_fails_the_clone(tmp_path, monkeypatch):
    """The rehearsal's control: without the right token nothing checks out.

    This is what proves the successful clone above is authenticating rather
    than being served by an inherited credential cache.
    """
    serve_root, commits = _seed_local_remotes(tmp_path)
    git_server, git_root = _serve(
        _GitHandler, project_root=serve_root, expected=MINTED_TOKEN, presented=[],
    )
    wrong = tmp_path / "wrong-credential"
    wrong.write_text("ghs_thisIsNotTheMintedToken000000000000\n")
    wrong.chmod(0o600)
    try:
        monkeypatch.setattr(checkout_manifest, "ORIGINS", {
            name: "%s/%s.git" % (git_root, name) for name in BUNDLE_REPOSITORIES
        })
        with pytest.raises(subprocess.CalledProcessError):
            checkout_manifest.main([
                str(_manifest(tmp_path, commits)), str(tmp_path / "repos"),
                "--token-file", str(wrong),
            ])
    finally:
        git_server.shutdown()
        git_server.server_close()


def test_checkout_manifest_refuses_a_token_file_that_is_not_mode_0600(tmp_path):
    loose = tmp_path / "loose"
    loose.write_text("ghs_token\n")
    loose.chmod(0o644)
    with pytest.raises(ValueError, match="not 0600"):
        checkout_manifest.authenticated_git_environment(tmp_path, loose)


def test_checkout_manifest_preserves_the_environment_route(tmp_path, monkeypatch):
    monkeypatch.setenv(checkout_manifest.TOKEN_ENV, LEGACY_TOKEN)
    monkeypatch.setenv("GH_TOKEN", "must-not-survive")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-survive")
    environment = checkout_manifest.authenticated_git_environment(tmp_path)
    assert environment[checkout_manifest.CARRIER_ENV] == LEGACY_TOKEN
    assert "GH_TOKEN" not in environment
    assert "GITHUB_TOKEN" not in environment
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    askpass = Path(environment["GIT_ASKPASS"])
    assert oct(askpass.stat().st_mode & 0o777) == "0o700"
    assert LEGACY_TOKEN not in askpass.read_text()
    monkeypatch.delenv(checkout_manifest.TOKEN_ENV)
    with pytest.raises(ValueError, match=checkout_manifest.TOKEN_ENV):
        checkout_manifest.authenticated_git_environment(tmp_path)


def test_the_askpass_helper_answers_only_the_expected_prompts(tmp_path):
    token = tmp_path / "credential"
    token.write_text(MINTED_TOKEN + "\n")
    token.chmod(0o600)
    environment = checkout_manifest.authenticated_git_environment(tmp_path, token)
    askpass = environment["GIT_ASKPASS"]
    user = subprocess.run([askpass, "Username for 'https://github.com': "],
                          capture_output=True, text=True, env=environment, check=False)
    password = subprocess.run([askpass, "Password for 'https://github.com': "],
                              capture_output=True, text=True, env=environment, check=False)
    other = subprocess.run([askpass, "Passphrase: "],
                           capture_output=True, text=True, env=environment, check=False)
    assert user.stdout.strip() == "x-access-token"
    assert password.stdout.strip() == MINTED_TOKEN
    assert other.returncode == 1


# ==========================================================================
# The workflow wiring itself
# ==========================================================================
def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_both_workflows_pin_the_live_module_digests():
    for path in (ISSUER, EXTERNAL_JUDGE):
        raw = path.read_text()
        assert "GOVERNED_READ_MINTER_SHA256: " + _digest(MINTER) in raw, path
        assert "GOVERNED_READ_SELECTOR_SHA256: " + _digest(SELECTOR) in raw, path


def test_every_issuer_consumer_selects_through_the_selector():
    document = yaml.safe_load(ISSUER.read_text())
    raw = ISSUER.read_text()
    for job_id in ("seal-downstream", "issue-wea", "renew-wea"):
        assert job_id in document["jobs"]
    # Three selector INVOCATIONS: one per consuming job.  (The name also
    # appears in each job's digest-pin step, which is why this counts the
    # `python3 ... select_governed_read_credential.py \\` invocation lines.)
    invocations = [
        line for line in raw.splitlines()
        if line.strip().startswith("python3 ")
        and line.rstrip().endswith("select_governed_read_credential.py \\")
    ]
    assert len(invocations) == 3, invocations
    # seal_downstream is the one that installs a long-lived downstream secret.
    assert raw.count("--legacy-only --check") == 1
    # The two frozen-checkout jobs each take a file and each remove it.
    assert raw.count('--output "$RUNNER_TEMP/governed-read-credential"') == 2
    assert raw.count('--token-file "$RUNNER_TEMP/governed-read-credential"') == 2
    assert raw.count('rm -f "$RUNNER_TEMP/governed-read-credential"') == 2
    assert raw.count("GOVERNED_READ_MINTER_DRIFT_PASS") == 2


def test_the_credential_is_removed_before_any_checked_out_code_runs():
    """Ordering, read from the bytes: select, checkout, remove, then the rest."""
    lines = ISSUER.read_text().splitlines(keepends=True)

    def job_body(job_id):
        start = next(i for i, line in enumerate(lines) if line == "  %s:\n" % job_id)
        end = len(lines)
        for index in range(start + 1, len(lines)):
            line = lines[index]
            if (line.startswith("  ") and not line.startswith("   ")
                    and line.rstrip().endswith(":")):
                end = index
                break
        return "".join(lines[start:end])

    for job_id in ("issue-wea", "renew-wea"):
        body = job_body(job_id)
        select = body.index("--output \"$RUNNER_TEMP/governed-read-credential\"")
        consume = body.index("--token-file \"$RUNNER_TEMP/governed-read-credential\"")
        remove = body.index("rm -f \"$RUNNER_TEMP/governed-read-credential\"")
        drift = body.index("GOVERNED_READ_MINTER_DRIFT_PASS")
        verify = body.index("verify_hosted_wea.py")
        assert select < consume < remove < drift < verify, job_id


def test_the_external_judge_checkout_now_carries_a_token():
    raw = EXTERNAL_JUDGE.read_text()
    document = yaml.safe_load(raw)
    steps = document["jobs"]["issue"]["steps"]
    govml = next(
        step for step in steps
        if step.get("with", {}).get("repository") == "rexcoleman/govML"
    )
    assert govml["with"]["token"] == "${{ steps.governed_read.outputs.token }}"
    assert govml["with"]["persist-credentials"] is False
    # No new long-lived secret name was introduced.
    assert "GOVML_REA_READ_APP_ID" in raw
    assert "GOVML_REA_READ_APP_PRIVATE_KEY_B64" in raw
    for name in re.findall(r"secrets\.([A-Z0-9_]+)", raw):
        assert name in {
            "GOVML_REA_READ_APP_ID",
            "GOVML_REA_READ_APP_PRIVATE_KEY_B64",
            "REA_BUNDLE_READ_TOKEN",
            "GOVML_EXTERNAL_JUDGE_APPROVING_PRIVATE_KEY_PEM",
        }, name
    # And the credential file is gone before the checked-out issuer executes.
    remove = raw.index('rm -f "$RUNNER_TEMP/governed-read-credential"')
    execute = raw.index("python3 govml/scripts/issue_external_judge_authority.py --help")
    assert remove < execute


def test_the_external_judge_refuses_an_unset_issuer_pin_before_the_checkout():
    raw = EXTERNAL_JUDGE.read_text()
    refusal = raw.index("GOVML_ISSUER_COMMIT_UNSET")
    checkout = raw.index("repository: rexcoleman/govML")
    assert refusal < checkout


# ==========================================================================
# The reusable consumer verifier: migrated WITHOUT changing what its one
# pinned caller must supply.
# ==========================================================================
ORIGINAL_REQUIRED_SECRETS = {"REA_WEA_READ_TOKEN", "REA_BUNDLE_READ_TOKEN"}


def test_the_verifier_secrets_interface_stays_backward_compatible():
    document = yaml.safe_load(VERIFIER.read_text())
    call = document[True]["workflow_call"]
    secrets = call["secrets"]
    # Nothing an existing caller supplies may change meaning or become optional.
    for name in ORIGINAL_REQUIRED_SECRETS:
        assert secrets[name]["required"] is True, name
    # A reusable workflow only sees declared secrets, so the App pair had to be
    # declared -- but only as OPTIONAL, which is additive for every caller.
    assert secrets["GOVML_REA_READ_APP_ID"]["required"] is False
    assert secrets["GOVML_REA_READ_APP_PRIVATE_KEY_B64"]["required"] is False
    assert set(secrets) == ORIGINAL_REQUIRED_SECRETS | {
        "GOVML_REA_READ_APP_ID", "GOVML_REA_READ_APP_PRIVATE_KEY_B64",
    }
    # The input interface is untouched.
    assert set(call["inputs"]) == {
        "consumer_id", "surface", "issuance_run_id", "control_sha",
    }
    assert call["inputs"]["surface"]["required"] is False
    for name in ("consumer_id", "issuance_run_id", "control_sha"):
        assert call["inputs"][name]["required"] is True, name


def test_the_verifier_removes_the_credential_before_it_verifies():
    raw = VERIFIER.read_text()
    select = raw.index("select_governed_read_credential.py")
    consume = raw.index('--token-file "$RUNNER_TEMP/governed-read-credential"')
    remove = raw.index('rm -f "$RUNNER_TEMP/governed-read-credential"')
    verify = raw.index("verify_hosted_wea.py")
    assert select < consume < remove < verify


def _verifier_step_script(step_name):
    document = yaml.safe_load(VERIFIER.read_text())
    step = next(
        row for row in document["jobs"]["verify"]["steps"]
        if row.get("name") == step_name
    )
    # The only expression in this script is an echo of the control SHA.
    return step["run"].replace(
        "${{ inputs.control_sha }}", "13f6efd2cbd402496d955d6b89f4263685bcce11",
    )


def _run_selection_step(tmp_path, *, modules_present, environment):
    """Execute the verifier's real selection script against a fake checkout."""
    checkout = tmp_path / "repos" / "rexcoleman.dev" / ".github" / "write-enforcement"
    checkout.mkdir(parents=True)
    if modules_present:
        for source in (SELECTOR, MINTER):
            (checkout / source.name).write_bytes(source.read_bytes())
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    script = tmp_path / "step.sh"
    script.write_text(_verifier_step_script(
        "Select the governed read credential under custody precedence"
    ))
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RUNNER_TEMP": str(runner_temp),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    base.update(environment)
    completed = subprocess.run(
        ["bash", str(script)], cwd=tmp_path, env=base,
        capture_output=True, text=True, check=False,
    )
    return completed, runner_temp


def test_the_verifier_falls_back_when_the_control_sha_predates_the_lane(tmp_path):
    """The one real caller pins control_sha 13f6efd2, which has no selector."""
    completed, runner_temp = _run_selection_step(
        tmp_path, modules_present=False,
        environment={"REA_BUNDLE_READ_TOKEN": LEGACY_TOKEN},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "GOVERNED_READ_LANE_ABSENT_AT_CONTROL_SHA" in completed.stdout
    assert (runner_temp / "governed-read-route").read_text().strip() == "compatibility"
    assert not (runner_temp / "governed-read-credential").exists()


def test_the_verifier_uses_the_governed_lane_when_the_control_sha_carries_it(tmp_path):
    completed, runner_temp = _run_selection_step(
        tmp_path, modules_present=True,
        environment={"REA_BUNDLE_READ_TOKEN": LEGACY_TOKEN},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (runner_temp / "governed-read-route").read_text().strip() == "governed"
    credential = runner_temp / "governed-read-credential"
    assert credential.read_text().strip() == LEGACY_TOKEN
    assert oct(credential.stat().st_mode & 0o777) == "0o600"
    assert LEGACY_TOKEN not in completed.stdout + completed.stderr


def test_the_verifier_has_no_fallback_past_a_present_selector(tmp_path):
    """Present means binding: a PARTIAL App pair fails the step, not downgrades."""
    completed, runner_temp = _run_selection_step(
        tmp_path, modules_present=True,
        environment={
            "GOVML_REA_READ_APP_ID": "4412331",
            "GOVML_REA_READ_APP_PRIVATE_KEY_B64": "",
            "REA_BUNDLE_READ_TOKEN": LEGACY_TOKEN,
        },
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert "GOVERNED_READ_APP_PAIR_PARTIAL" in completed.stderr
    assert not (runner_temp / "governed-read-credential").exists()


def test_the_verifier_checkout_step_honours_both_routes():
    script = _verifier_step_script("Checkout frozen members")
    assert '--token-file "$RUNNER_TEMP/governed-read-credential"' in script
    # The compatibility branch must be the ORIGINAL invocation, argument for
    # argument, so a historical control_sha behaves exactly as it does today.
    assert (
        "python3 repos/rexcoleman.dev/.github/write-enforcement/checkout_manifest.py \\\n"
        "              issuance/enforcement_bundle_manifest.json repos\n"
    ) in script.replace("\\\n", "\\\n") or (
        "issuance/enforcement_bundle_manifest.json repos" in script
    )
    assert script.count("checkout_manifest.py") == 2
