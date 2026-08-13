from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "provision_downstream_bundle_secret.py"
WORKFLOW = ROOT.parent / "workflows" / "issue-write-enforcement-attestation.yml"
SPEC = importlib.util.spec_from_file_location("sealed_bundle_transfer", TOOL)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
TARGET = "rexcoleman/cycle_10_autonomous_cycle_apparatus_build"


def frozen_manifest(tmp_path):
    commits = {
        logical: ("%x" % (index + 1)) * 40
        for index, logical in enumerate(tool.LOGICAL_REPOSITORIES)
    }
    value = {"authority_generation": 5, "members": [
        {"repository": logical, "commit": commit}
        for logical, commit in commits.items()
    ]}
    value["manifest_digest"] = hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    path = tmp_path / "manifest.json"
    path.write_bytes(tool.canonical(value))
    return path, commits


def key():
    raw = bytes(range(32))
    return base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()


def successful_api(commits, calls):
    def fake(token, path):
        calls.append((token, path))
        commit = path.rsplit("/", 1)[1]
        assert commit in commits.values()
        return {"sha": commit, "tree": {"sha": "a" * 40}}
    return fake


def environment(secret="planted-source-secret"):
    return {
        tool.SOURCE_ENV: secret,
        "GITHUB_RUN_ID": "12345",
        "GITHUB_REF": "refs/tags/rea-wea-generation-5-abcdef123456",
        "GITHUB_SHA": "a" * 40,
    }


def seal_packet(tmp_path, monkeypatch, secret="planted-source-secret"):
    manifest, commits = frozen_manifest(tmp_path)
    calls = []
    monkeypatch.setattr(tool, "api", successful_api(commits, calls))
    public, digest = key()
    output = tmp_path / "sealed.json"
    rc = tool.main([
        "seal", "--manifest", str(manifest), "--key-id", "789",
        "--target-repository", TARGET,
        "--public-key-b64", public, "--public-key-sha256", digest,
        "--output", str(output),
    ], environment(secret))
    return rc, output, manifest, calls, digest


def verify_argv(output, manifest, digest, ciphertext):
    return [
        "verify", "--packet", str(output), "--manifest", str(manifest),
        "--target-repository", TARGET,
        "--key-id", "789", "--public-key-sha256", digest,
        "--ciphertext-sha256", ciphertext, "--run-id", "12345",
        "--workflow-ref", "refs/tags/rea-wea-generation-5-abcdef123456",
        "--workflow-sha", "a" * 40,
    ]


def test_seals_after_all_five_reads_and_never_outputs_secret(tmp_path, monkeypatch, capsys):
    rc, output, _manifest, calls, _digest = seal_packet(tmp_path, monkeypatch)
    assert rc == 0 and output.stat().st_mode & 0o777 == 0o600
    assert len(calls) == 5
    packet = json.loads(output.read_bytes())
    assert set(packet) == tool.PACKET_KEYS
    assert packet["workflow_run_id"] == 12345
    assert packet["target_repository"] == TARGET
    assert packet["source_commits"] == {
        logical: ("%x" % (index + 1)) * 40
        for index, logical in enumerate(tool.LOGICAL_REPOSITORIES)
    }
    assert "planted-source-secret" not in output.read_text()
    assert "planted-source-secret" not in capsys.readouterr().out
    assert len(base64.b64decode(packet["ciphertext_b64"])) > tool.SEALED_OVERHEAD


def test_exact_packet_verifies(tmp_path, monkeypatch):
    rc, output, manifest, _calls, digest = seal_packet(tmp_path, monkeypatch)
    assert rc == 0
    packet = json.loads(output.read_bytes())
    assert tool.main(verify_argv(
        output, manifest, digest, packet["ciphertext_sha256"],
    )) == 0


def test_key_drift_refuses(tmp_path, monkeypatch):
    rc, output, manifest, _calls, digest = seal_packet(tmp_path, monkeypatch)
    assert rc == 0
    packet = json.loads(output.read_bytes())
    argv = verify_argv(output, manifest, "f" * 64, packet["ciphertext_sha256"])
    assert tool.main(argv) == 3


def test_ciphertext_substitution_refuses(tmp_path, monkeypatch):
    rc, output, manifest, _calls, digest = seal_packet(tmp_path, monkeypatch)
    assert rc == 0
    packet = json.loads(output.read_bytes())
    packet["ciphertext_b64"] = base64.b64encode(b"x" * 80).decode()
    output.write_bytes(tool.canonical(packet))
    assert tool.main(verify_argv(
        output, manifest, digest, packet["ciphertext_sha256"],
    )) == 3


def test_wrong_public_key_digest_refuses_before_reads(tmp_path, monkeypatch):
    manifest, _commits = frozen_manifest(tmp_path)
    reads = []
    monkeypatch.setattr(tool, "api", lambda *args: reads.append(args))
    public, _digest = key()
    assert tool.main([
        "seal", "--manifest", str(manifest), "--key-id", "789",
        "--target-repository", TARGET,
        "--public-key-b64", public, "--public-key-sha256", "f" * 64,
        "--output", str(tmp_path / "out"),
    ], environment()) == 3
    assert reads == []


def test_git_read_refusal_prevents_packet(tmp_path, monkeypatch):
    manifest, _commits = frozen_manifest(tmp_path)
    output = tmp_path / "out"
    monkeypatch.setattr(tool, "api", lambda *_args: (_ for _ in ()).throw(
        tool.Refusal(tool.GIT_READ_REFUSED, "status=403")
    ))
    public, digest = key()
    assert tool.main([
        "seal", "--manifest", str(manifest), "--key-id", "789",
        "--target-repository", TARGET,
        "--public-key-b64", public, "--public-key-sha256", digest,
        "--output", str(output),
    ], environment()) == 3
    assert not output.exists()


def test_absent_source_refuses(tmp_path, monkeypatch):
    manifest, commits = frozen_manifest(tmp_path)
    reads = []
    monkeypatch.setattr(tool, "api", successful_api(commits, reads))
    public, digest = key()
    assert tool.main([
        "seal", "--manifest", str(manifest), "--key-id", "789",
        "--target-repository", TARGET,
        "--public-key-b64", public, "--public-key-sha256", digest,
        "--output", str(tmp_path / "out"),
    ], {}) == 3
    assert reads == []


def test_writer_bypass_is_structurally_absent():
    raw = TOOL.read_text(encoding="utf-8")
    assert "REA_SECRETS_WRITE_PAT" not in raw
    assert "secret set" not in raw
    assert "encrypted_value" not in raw
    assert "subprocess" not in raw


def test_workflow_has_two_phase_sealed_transfer_without_writer_credential():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "seal_downstream" in raw
    assert "preflight-sealed-transfer:" in raw
    assert "authenticated-sealed-bundle-${{ github.run_id }}" in raw
    assert "REA_SECRETS_WRITE_PAT" not in raw
    assert "encrypted_value" not in raw
    assert raw.count("provision_downstream_bundle_secret.py verify") == 2
    assert "downstream_repository:" in raw
    assert raw.count('--target-repository "$DOWNSTREAM_REPOSITORY"') == 3
    assert raw.count("DOWNSTREAM_REPOSITORY: ${{ inputs.downstream_repository }}") == 4


def test_secret_safe_refusal(tmp_path, monkeypatch, capsys):
    manifest, commits = frozen_manifest(tmp_path)
    secret = "never-print-source"
    monkeypatch.setattr(tool, "api", successful_api(commits, []))
    public, digest = key()
    monkeypatch.setattr(tool, "seal_bytes", lambda *_args: (_ for _ in ()).throw(
        tool.Refusal(tool.SODIUM_REFUSED, secret)
    ))
    assert tool.main([
        "seal", "--manifest", str(manifest), "--key-id", "789",
        "--target-repository", TARGET,
        "--public-key-b64", public, "--public-key-sha256", digest,
        "--output", str(tmp_path / "out"),
    ], environment(secret)) == 3
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert secret not in combined


def test_unregistered_or_substituted_target_refuses(tmp_path, monkeypatch):
    rc, output, manifest, _calls, digest = seal_packet(tmp_path, monkeypatch)
    assert rc == 0
    packet = json.loads(output.read_bytes())
    wrong = verify_argv(output, manifest, digest, packet["ciphertext_sha256"])
    wrong[wrong.index("--target-repository") + 1] = (
        "rexcoleman/unregistered-target"
    )
    assert tool.main(wrong) == 3
    public, public_digest = key()
    assert tool.main([
        "seal", "--manifest", str(manifest), "--key-id", "789",
        "--target-repository", "rexcoleman/unregistered-target",
        "--public-key-b64", public, "--public-key-sha256", public_digest,
        "--output", str(tmp_path / "wrong-target"),
    ], environment()) == 3
