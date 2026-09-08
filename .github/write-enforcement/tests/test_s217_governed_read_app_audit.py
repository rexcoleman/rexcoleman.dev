from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "workflows" / "s217-governed-read-app-audit.yml"


def test_s217_governed_read_app_audit_uses_hosted_issuer_environment() -> None:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = document["jobs"]["audit"]
    assert job["environment"] == "rea-write-enforcement-issuer"
    env = job["env"]
    assert env["GOVML_REA_READ_APP_ID"] == "${{ secrets.GOVML_REA_READ_APP_ID }}"
    assert (
        env["GOVML_REA_READ_APP_PRIVATE_KEY_B64"]
        == "${{ secrets.GOVML_REA_READ_APP_PRIVATE_KEY_B64 }}"
    )
    assert env["REA_SECRETS_WRITE_PAT"] == "${{ secrets.REA_SECRETS_WRITE_PAT }}"


def test_s217_governed_read_app_audit_emits_only_permission_facts() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "S217_APP_PERMISSION" in raw
    assert "S217_APP_TOKEN_PROBE" in raw
    assert "token=MASKED" in raw
    assert "::add-mask::" in raw
    assert "print(token)" not in raw
    assert "print(app_id, key)" not in raw
    assert "print(key)" not in raw
    assert "S217_REA_SECRET_SET" in raw
    assert "updatedAt=" in raw


def test_s217_governed_read_app_provisioning_targets_rea_only() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "if: ${{ inputs.provision_rea }}" in raw
    assert "GH_TOKEN: ${{ secrets.REA_SECRETS_WRITE_PAT }}" in raw
    assert raw.count("--repo rexcoleman/research_enforcement_activation") == 3
    assert "--repo rexcoleman/govML" not in raw
    assert "--repo rexcoleman/rexcoleman.dev" not in raw
