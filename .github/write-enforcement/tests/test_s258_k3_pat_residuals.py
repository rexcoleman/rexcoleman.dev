import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
RECORD = ROOT / ".github" / "write-enforcement" / "k3_pat_residuals.json"

LEGACY_SECRETS = {
    "REA_BUNDLE_READ_TOKEN",
    "REA_RULESET_READ_TOKEN",
    "REA_SECRETS_WRITE_PAT",
}
SECRET_REFERENCE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_-]*)")
REQUIRED_TEXT_FIELDS = {
    "reason",
    "why_app_installation_token_not_sufficient",
    "required_authority_to_retire",
    "safe_current_boundary",
}


def _legacy_consumers():
    consumers = set()
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        document = yaml.safe_load(path.read_text())
        for job_id, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            found = SECRET_REFERENCE.findall(json.dumps(job, default=str))
            for secret in sorted(set(found) & LEGACY_SECRETS):
                consumers.add((f".github/workflows/{path.name}", job_id, secret))
    return consumers


def _residual_consumers():
    record = json.loads(RECORD.read_text())
    assert record["schema_version"] == "rea.k3-pat-residuals.v1"
    rows = record["residuals"]
    assert rows
    consumers = set()
    for row in rows:
        assert row["classification"] == "K3_RESIDUAL"
        for field in REQUIRED_TEXT_FIELDS:
            assert isinstance(row.get(field), str), row
            assert row[field].strip(), row
        consumers.add((row["workflow"], row["job"], row["secret"]))
    return consumers


def test_every_remaining_legacy_pat_consumer_is_declared_k3_residual():
    assert _legacy_consumers() == _residual_consumers()
