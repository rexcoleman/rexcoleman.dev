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


def test_preflight_reports_retired_for_complete_or_empty_legacy_state(tmp_path: Path) -> None:
    tool = load_tool()
    empty = credential_file(tmp_path, b"ANTHROPIC_API_KEY=unrelated\n")
    assert tool.preflight(empty) == {
        "status": "RETIRED",
        "GOVML_AUTHORITY_TOKEN": "UNSET",
        "REA_BUNDLE_READ_TOKEN": "UNSET",
    }
    complete = credential_file(
        tmp_path,
        b"GOVML_AUTHORITY_TOKEN=github_pat_fixture_a\n"
        b"REA_BUNDLE_READ_TOKEN=github_pat_fixture_b\n",
    )
    assert tool.preflight(complete) == {
        "status": "RETIRED",
        "GOVML_AUTHORITY_TOKEN": "SET",
        "REA_BUNDLE_READ_TOKEN": "SET",
    }
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


def test_apply_reports_retired_app_route_without_mutating_file(tmp_path: Path) -> None:
    tool = load_tool()
    original = b"# keep\nANTHROPIC_API_KEY=unrelated\n"
    path = credential_file(tmp_path, original)
    with pytest.raises(tool.Refusal, match="OWNER_PAT_ROUTE_RETIRED use=GOVML_REA_READ_APP"):
        tool.apply(path)
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_whole_arc_binds_preflight_then_both_one_time_actions() -> None:
    raw = ARC.read_text(encoding="ascii")
    assert "MOONSHOTS_REPOSITORY=/home/azureuser/moonshots_rea_s170" in raw
    assert "/home/azureuser/Moonshots_Career_Thesis_v2" not in raw
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
