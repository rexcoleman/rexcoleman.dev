from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "provision_downstream_bundle_secret.py"
SPEC = importlib.util.spec_from_file_location("protected_bundle_transfer", TOOL)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def frozen_manifest(tmp_path):
    commits = {
        logical: str(index + 1) * 40
        for index, logical in enumerate(tool.LOGICAL_REPOSITORIES)
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"members": [
        {"repository": logical, "commit": commit}
        for logical, commit in commits.items()
    ]}), encoding="utf-8")
    return path, commits


def successful_api(commits, calls):
    def fake(token, path, raw=False):
        calls.append((token, path, raw))
        if "/git/commits/" in path:
            commit = path.rsplit("/", 1)[1]
            assert commit in commits.values()
            return {"sha": commit, "tree": {"sha": "a" * 40}}
        raise AssertionError("unexpected API path %s" % path)

    return fake


def test_validates_all_reads_before_stdin_write_and_postcheck(tmp_path, monkeypatch, capsys):
    manifest, commits = frozen_manifest(tmp_path)
    calls = []
    gh_calls = []
    source = "planted-source-secret"
    writer = "planted-writer-secret"
    monkeypatch.setattr(tool, "api", successful_api(commits, calls))

    def fake_gh(argv, token, stdin_value="", source_secret=""):
        gh_calls.append((list(argv), token, stdin_value, source_secret, len(calls)))
        if argv[1:3] == ["secret", "set"]:
            return 0, "", ""
        return 0, json.dumps([{
            "name": tool.SECRET_NAME,
            "updatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        }]), ""

    monkeypatch.setattr(tool, "run_gh", fake_gh)
    rc = tool.main(
        ["--manifest", str(manifest)],
        {tool.SOURCE_ENV: source, tool.WRITE_ENV: writer},
    )
    assert rc == 0
    assert len([path for _token, path, _raw in calls if "/git/commits/" in path]) == 5
    assert all("/actions/" not in path for _token, path, _raw in calls)
    assert gh_calls[0][2] == source
    assert gh_calls[0][1] == writer
    assert gh_calls[0][4] == 5
    output = capsys.readouterr().out
    assert source not in output and writer not in output
    assert "post_name_check=pass" in output


def test_git_refusal_prevents_write(tmp_path, monkeypatch):
    manifest, _commits = frozen_manifest(tmp_path)
    writes = []
    monkeypatch.setattr(
        tool, "api",
        lambda *_a, **_k: (_ for _ in ()).throw(
            tool.Refusal(tool.GIT_READ_REFUSED, "status=403")
        ),
    )
    monkeypatch.setattr(tool, "run_gh", lambda *a, **k: writes.append(a))
    assert tool.main(
        ["--manifest", str(manifest)],
        {tool.SOURCE_ENV: "source", tool.WRITE_ENV: "writer"},
    ) == 3
    assert writes == []


def test_absent_or_identical_credentials_refuse_before_reads(tmp_path, monkeypatch):
    manifest, _commits = frozen_manifest(tmp_path)
    reads = []
    monkeypatch.setattr(tool, "api", lambda *a, **k: reads.append(a))
    argv = ["--manifest", str(manifest)]
    assert tool.main(argv, {}) == 3
    assert tool.main(argv, {tool.SOURCE_ENV: "source"}) == 3
    assert tool.main(argv, {tool.SOURCE_ENV: "same", tool.WRITE_ENV: "same"}) == 3
    assert reads == []


def test_postcheck_failure_is_typed_and_secret_safe(tmp_path, monkeypatch, capsys):
    manifest, commits = frozen_manifest(tmp_path)
    source = "never-print-source"
    writer = "never-print-writer"
    monkeypatch.setattr(tool, "api", successful_api(commits, []))

    def fake_gh(argv, token, stdin_value="", source_secret=""):
        if argv[1:3] == ["secret", "set"]:
            return 0, "", ""
        return 0, "[]", ""

    monkeypatch.setattr(tool, "run_gh", fake_gh)
    assert tool.main(
        ["--manifest", str(manifest)],
        {tool.SOURCE_ENV: source, tool.WRITE_ENV: writer},
    ) == 3
    output = capsys.readouterr()
    combined = output.out + output.err
    assert "SECRET_POSTCHECK_REFUSED" in combined
    assert source not in combined and writer not in combined
