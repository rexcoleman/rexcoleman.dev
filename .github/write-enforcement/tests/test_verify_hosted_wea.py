import argparse
import importlib.util
import json
from pathlib import Path

import pytest


TARGET = Path(__file__).resolve().parents[1] / "verify_hosted_wea.py"
SPEC = importlib.util.spec_from_file_location("verify_hosted_wea", TARGET)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def args(tmp_path):
    issuance = tmp_path / "issuance"
    issuance.mkdir()
    return argparse.Namespace(
        issuance=issuance, workspace=tmp_path / "workspace",
        consumer_id="newsletter-remote-check", surface="publication",
    )


@pytest.mark.parametrize("mode,reason,readable", [
    ("deleted", "WEA_MISSING", False),
    ("expired", "WEA_EXPIRED", True),
    ("corrupt", "WEA_CORRUPT", True),
    ("bundle-byte-changed", "WEA_WRONG_BUNDLE", True),
])
def test_r4_modes_emit_typed_refusal_with_digest_context(tmp_path, monkeypatch, capsys, mode, reason, readable):
    parsed = args(tmp_path)
    if readable:
        (parsed.issuance / "write_enforcement_attestation.json").write_bytes(
            b'{"state":"ENFORCING"}' if mode != "corrupt" else b'{"corrupt":'
        )

    def refuse(_args):
        if mode == "deleted":
            raise FileNotFoundError(
                2, "missing", str(parsed.issuance / "write_enforcement_attestation.json")
            )
        raise MODULE.HostedWEARefusal(reason, mode)

    monkeypatch.setattr(MODULE, "verify", refuse)
    raw_exit, report = MODULE.run(parsed)
    assert raw_exit == report["raw_exit"] == 3
    assert report["verdict"] == "REFUSE"
    assert report["reason_code"] == reason
    assert report["mutation_observed"] is False
    assert (report["state_digest"] is not None) is readable
    assert "PASS" not in json.dumps(report)
    assert "SKIP" not in json.dumps(report)
    assert "INERT" not in json.dumps(report)
