import argparse
import sys
from pathlib import Path

import pytest

import issue_wea
import member_contract
import verify_hosted_wea


def fixture_public() -> bytes:
    return (
        b"-----BEGIN PUBLIC KEY-----\n"
        b"MCowBQYDK2VwAyEA9824s+OoFjo/YI0z3pNwJdA6Jw+dXMXs7SNGO484VbE=\n"
        b"-----END PUBLIC KEY-----\n"
    )


def test_staged_contract_is_exact_current_successor_plus_one():
    historical = member_contract.EXPECTED_MEMBERS
    production = member_contract.successor_members()
    staged = member_contract.staged_nonproduction_members()
    assert len(historical) == 244
    assert len(production) == 257
    assert len(staged) == 258
    assert set(staged) - set(production) == {
        "staged-nonproduction-trusted-public-key"
    }
    assert all(staged[key] == value for key, value in production.items())
    assert set(member_contract.SUCCESSOR_ADDITIONAL_MEMBERS) <= set(staged)


def test_staged_issuer_refuses_historical_population_before_member_reads(tmp_path):
    historical_staged = dict(member_contract.EXPECTED_MEMBERS)
    historical_staged.update(
        member_contract.STAGED_NONPRODUCTION_ADDITIONAL_MEMBERS
    )
    manifest = {
        "members": [
            {
                "member_id": member_id,
                "repository": repository,
                "path": path,
            }
            for member_id, (repository, path) in historical_staged.items()
        ]
    }

    with pytest.raises(
        issue_wea.IssuerRefusal,
        match="BUNDLE_MEMBER_SET_MISMATCH",
    ):
        issue_wea.verify_members(
            manifest,
            tmp_path / "absent-workspace",
            staged_nonproduction=True,
        )


def test_trust_domains_refuse_crossed_and_arbitrary_keys():
    staged_public = fixture_public()
    production_public = b"production-public"
    loaded = {
        "trusted-public-key": production_public,
        "newsletter-trusted-public-key": production_public,
        "staged-nonproduction-trusted-public-key": staged_public,
    }
    issue_wea.verify_trust_roots(
        loaded, staged_public, staged_nonproduction=True
    )
    with pytest.raises(issue_wea.IssuerRefusal):
        issue_wea.verify_trust_roots(
            loaded, b"arbitrary", staged_nonproduction=True
        )
    with pytest.raises(issue_wea.IssuerRefusal):
        issue_wea.verify_trust_roots(
            loaded, staged_public, staged_nonproduction=False
        )
    crossed = dict(loaded)
    crossed["trusted-public-key"] = staged_public
    with pytest.raises(issue_wea.IssuerRefusal):
        issue_wea.verify_trust_roots(
            crossed, staged_public, staged_nonproduction=True
        )


def test_staged_issuer_refuses_github_actions_before_artifact_reads(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(sys, "argv", [
        "issue_wea.py",
        "--manifest", str(tmp_path / "missing-manifest"),
        "--workspace", str(tmp_path / "workspace"),
        "--ruleset-json", str(tmp_path / "ruleset"),
        "--private-key", str(tmp_path / "private"),
        "--output", str(tmp_path / "output"),
        "--predecessor-wea-sha256", "0" * 64,
        "--staged-nonproduction",
    ])
    with pytest.raises(
        issue_wea.IssuerRefusal, match="STAGED_NONPRODUCTION_HOSTED_REFUSED"
    ):
        issue_wea.main()


def test_staged_hosted_verifier_refuses_non_tmp_roots():
    args = argparse.Namespace(
        issuance=Path("/var/lib/rea/staged"),
        workspace=Path("/var/lib/rea/workspace"),
        consumer_id="s132-negative",
        surface="report",
        staged_nonproduction=True,
    )
    with pytest.raises(
        verify_hosted_wea.HostedWEARefusal,
        match="STAGED_NONPRODUCTION_TMP_REQUIRED",
    ):
        verify_hosted_wea.verify(args)
