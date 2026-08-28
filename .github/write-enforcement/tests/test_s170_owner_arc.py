from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import sys

import pytest


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / ".github/write-enforcement/populate_rea_s170_govml_credentials.py"
ARC = ROOT / ".github/write-enforcement/rea_s170_owner_arc.sh"


def load_tool():
    spec = importlib.util.spec_from_file_location("s170_govml_credentials", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def credential_file(tmp_path: Path, raw: bytes) -> Path:
    path = tmp_path / "env"
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def test_preflight_requires_exact_secure_complete_or_empty_state(tmp_path: Path) -> None:
    tool = load_tool()
    empty = credential_file(tmp_path, b"ANTHROPIC_API_KEY=unrelated\n")
    assert tool.preflight(empty) == {
        "status": "READY",
        "GOVML_AUTHORITY_TOKEN": "UNSET",
        "REA_BUNDLE_READ_TOKEN": "UNSET",
    }
    complete = credential_file(
        tmp_path,
        b"GOVML_AUTHORITY_TOKEN=github_pat_fixture_a\n"
        b"REA_BUNDLE_READ_TOKEN=github_pat_fixture_b\n",
    )
    tool.validate_token = lambda _token, _repository: None
    assert tool.preflight(complete)["status"] == "COMPLETE"
    complete.write_bytes(b"GOVML_AUTHORITY_TOKEN=github_pat_fixture_a\n")
    with pytest.raises(tool.Refusal, match="PARTIAL_REQUIRED_CREDENTIAL_SET_REFUSED"):
        tool.preflight(complete)
    complete.chmod(0o640)
    with pytest.raises(tool.Refusal, match="CREDENTIAL_FILE_SECURITY_REFUSED"):
        tool.preflight(complete)


def test_duplicate_required_name_refuses(tmp_path: Path) -> None:
    tool = load_tool()
    path = credential_file(
        tmp_path,
        b"GOVML_AUTHORITY_TOKEN=one\nGOVML_AUTHORITY_TOKEN=two\n",
    )
    with pytest.raises(tool.Refusal, match="CREDENTIAL_FILE_DUPLICATE_REFUSED"):
        tool.preflight(path)


def test_complete_preflight_revalidates_both_existing_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    path = credential_file(
        tmp_path,
        b"GOVML_AUTHORITY_TOKEN=github_pat_fixture_a\n"
        b"REA_BUNDLE_READ_TOKEN=github_pat_fixture_b\n",
    )
    observed: list[str] = []
    monkeypatch.setattr(
        tool,
        "validate_token",
        lambda _token, repository: observed.append(repository),
    )
    assert tool.preflight(path)["status"] == "COMPLETE"
    assert observed == [
        "rexcoleman/govML",
        "rexcoleman/research_enforcement_activation",
    ]


def test_complete_preflight_refuses_invalid_existing_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    path = credential_file(
        tmp_path,
        b"GOVML_AUTHORITY_TOKEN=github_pat_fixture_a\n"
        b"REA_BUNDLE_READ_TOKEN=github_pat_fixture_b\n",
    )

    def planted(_token: str, repository: str) -> None:
        if repository == "rexcoleman/research_enforcement_activation":
            raise tool.Refusal("TOKEN_CAPABILITY_REFUSED endpoint=planted")

    monkeypatch.setattr(tool, "validate_token", planted)
    with pytest.raises(tool.Refusal, match="TOKEN_CAPABILITY_REFUSED"):
        tool.preflight(path)


def test_token_capability_requires_read_without_write_privileges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    responses = iter((
        {"login": "rexcoleman"},
        {
            "full_name": "rexcoleman/govML",
            "default_branch": "main",
            "permissions": {
                "admin": False,
                "maintain": False,
                "push": False,
                "triage": False,
                "pull": True,
            },
        },
        {"sha": "a" * 40},
    ))
    monkeypatch.setattr(tool, "gh_json", lambda _token, _endpoint: next(responses))
    tool.validate_token("github_pat_fixture", "rexcoleman/govML")

    privileged = iter((
        {"login": "rexcoleman"},
        {
            "full_name": "rexcoleman/govML",
            "default_branch": "main",
            "permissions": {
                "admin": False,
                "maintain": False,
                "push": True,
                "triage": False,
                "pull": True,
            },
        },
    ))
    monkeypatch.setattr(tool, "gh_json", lambda _token, _endpoint: next(privileged))
    with pytest.raises(tool.Refusal, match="TOKEN_READ_ONLY_SCOPE_REFUSED"):
        tool.validate_token("github_pat_fixture", "rexcoleman/govML")


def test_apply_validates_hidden_values_and_preserves_unrelated_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    tool = load_tool()
    path = credential_file(tmp_path, b"# keep\nANTHROPIC_API_KEY=unrelated\n")
    values = iter(("github_pat_fixture_authority", "github_pat_fixture_bundle"))
    monkeypatch.setattr(tool.os, "isatty", lambda descriptor: True)
    monkeypatch.setattr(tool.getpass, "getpass", lambda prompt: next(values))
    validated = []
    monkeypatch.setattr(tool, "validate_token", lambda token, repo: validated.append(repo))
    result = tool.apply(path)
    assert result["status"] == "COMPLETE"
    assert validated == [
        "rexcoleman/govML",
        "rexcoleman/research_enforcement_activation",
        "rexcoleman/govML",
        "rexcoleman/research_enforcement_activation",
    ]
    raw = path.read_text(encoding="utf-8")
    assert "# keep\nANTHROPIC_API_KEY=unrelated\n" in raw
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    public = capsys.readouterr()
    assert "github_pat_fixture" not in public.out
    assert "github_pat_fixture" not in public.err


def test_postcondition_failure_restores_exact_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    original = b"# exact predecessor\nANTHROPIC_API_KEY=unrelated\n"
    path = credential_file(tmp_path, original)
    values = iter(("github_pat_fixture_authority", "github_pat_fixture_bundle"))
    monkeypatch.setattr(tool.os, "isatty", lambda descriptor: True)
    monkeypatch.setattr(tool.getpass, "getpass", lambda prompt: next(values))
    monkeypatch.setattr(tool, "validate_token", lambda token, repo: None)
    real_preflight = tool.preflight
    calls = 0

    def planted_preflight(selected):
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise tool.Refusal("PLANTED_POSTCONDITION")
        return real_preflight(selected)

    monkeypatch.setattr(tool, "preflight", planted_preflight)
    with pytest.raises(tool.Refusal, match="PLANTED_POSTCONDITION"):
        tool.apply(path)
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_validation_failure_before_write_does_not_run_rollback_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    original = b"# exact predecessor\nANTHROPIC_API_KEY=unrelated\n"
    path = credential_file(tmp_path, original)
    values = iter(("github_pat_fixture_authority", "github_pat_fixture_bundle"))
    monkeypatch.setattr(tool.os, "isatty", lambda descriptor: True)
    monkeypatch.setattr(tool.getpass, "getpass", lambda prompt: next(values))
    monkeypatch.setattr(
        tool,
        "validate_token",
        lambda _token, _repo: (_ for _ in ()).throw(tool.Refusal("PLANTED_INVALID")),
    )
    monkeypatch.setattr(
        tool,
        "atomic_replace",
        lambda _path, _raw: pytest.fail("no write or rollback before validation"),
    )
    with pytest.raises(tool.Refusal, match="PLANTED_INVALID"):
        tool.apply(path)
    assert path.read_bytes() == original


def test_whole_arc_binds_preflight_then_both_one_time_actions() -> None:
    raw = ARC.read_text(encoding="ascii")
    assert "ls-remote origin refs/heads/main" in raw
    assert "PAYLOAD_DIRTY_REFUSED" in raw
    assert "diff --quiet \"$COMMIT\"" in raw
    assert '"$CREDENTIAL_TOOL" --preflight' in raw
    assert '"$PRINCIPAL_TOOL" --preflight' in raw
    assert '"$CREDENTIAL_TOOL" --apply' in raw
    assert '"$ENROLLMENT_TOOL" /home/azureuser --repository rexcoleman/adversarial-ml-landscape' in raw
    assert 'exec /usr/bin/bash "$PRINCIPAL_WRAPPER"' in raw
    assert raw.index('"$CREDENTIAL_TOOL" --apply') < raw.index('"$ENROLLMENT_TOOL" /home/azureuser')
    assert raw.index('"$ENROLLMENT_TOOL" /home/azureuser') < raw.index('exec /usr/bin/bash "$PRINCIPAL_WRAPPER"')
    assert "--final-exec-self-test" in raw
