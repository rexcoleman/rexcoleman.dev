import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_member_population_is_complete_and_two_method_count():
    contract = load("member_contract")
    assert len(contract.EXPECTED_MEMBERS) == 204
    assert len(set(contract.EXPECTED_MEMBERS.values())) == 204
    literal = (TOOLS / "member_contract.py").read_text().count('("govML", "templates/build/enforcement/')
    semantic = sum(1 for repo, path in contract.EXPECTED_MEMBERS.values() if repo == "govML" and path.startswith("templates/build/enforcement/"))
    assert literal == semantic


def test_authenticated_immediate_predecessor_derives_epoch(tmp_path, monkeypatch):
    issue = load("issue_wea")
    private = tmp_path / "private.pem"; public = tmp_path / "public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private], check=True)
    subprocess.run(["openssl", "pkey", "-in", private, "-pubout", "-out", public], check=True)
    payload = {
        "schema_version": "rea.write.wea.live.v2", "purpose": "LIVE_ENFORCEMENT",
        "state": "ENFORCING", "authority_epoch": 8,
        "issuer": issue.ISSUER,
    }
    monkeypatch.setattr(issue, "openssl", lambda args: subprocess.run(["openssl", *args], check=True, capture_output=True))
    signed = issue.sign_payload(payload, private)
    predecessor = tmp_path / "predecessor.json"
    predecessor.write_bytes(issue.canonical(signed) + b"\n")
    raw, verified = issue.authenticated_predecessor(predecessor, public)
    assert verified["authority_epoch"] + 1 == 9
    value = json.loads(raw); value["authority_epoch"] = 9
    predecessor.write_bytes(issue.canonical(value) + b"\n")
    try:
        issue.authenticated_predecessor(predecessor, public)
    except issue.IssuerRefusal as exc:
        assert exc.reason_code == "PREDECESSOR_WEA_INVALID"
    else:
        raise AssertionError("tampered predecessor accepted")


def test_remote_reachability_exact_sha_and_unreachable(monkeypatch):
    builder = load("build_frozen_manifest")
    class Result:
        returncode = 0; stdout = "a" * 40 + "\n"; stderr = ""
    monkeypatch.setattr(builder.subprocess, "run", lambda *a, **k: Result())
    builder.verify_remote_reachability("govML", "a" * 40)
    try:
        builder.verify_remote_reachability("govML", "b" * 40)
    except ValueError as exc:
        assert "unreachable" in str(exc)
    else:
        raise AssertionError("mismatched authoritative SHA accepted")


def test_predecessor_preflight_is_before_owner_environment_and_digest_bound():
    workflow = (TOOLS.parent / "workflows/issue-write-enforcement-attestation.yml").read_text()
    preflight = workflow.index("preflight-predecessor:")
    issue = workflow.index("issue-wea:")
    environment = workflow.index("environment: rea-write-enforcement-issuer")
    assert preflight < issue < environment
    assert "needs: preflight-predecessor" in workflow
    assert "predecessor_wea_sha256" in workflow
    assert "PREDECESSOR_RUN_IDENTITY" not in workflow  # checks are executable, not a claim label
    assert "sha256sum predecessor/write_enforcement_attestation.json" in workflow
    assert "openssl pkeyutl -verify" in workflow
    assert "expired_fixture" not in workflow
    issuer = (TOOLS / "issue_wea.py").read_text()
    assert "dispatch_digest_mismatch" in issuer
    assert "expired_fixture" not in issuer
