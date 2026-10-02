import importlib.util
import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / ".github/write-enforcement/non_expiring_birth_e2e.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "non_expiring_birth_e2e_under_test",
        SOURCE,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_push_project_passes_candidate_env_to_git_commit(monkeypatch, tmp_path):
    module = load_module()
    observed = []

    def fake_run(argv, *, cwd=None, env=None, timeout=300):
        observed.append({
            "argv": list(argv),
            "env": dict(env or {}),
            "timeout": timeout,
        })
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(module, "run", fake_run)
    candidate_env = {
        "REA_NON_EXPIRING_PACKET_ROOT": str(tmp_path / "packet"),
        "REA_NON_EXPIRING_TEST_TRUST_ROOT": "1",
        "REA_NON_EXPIRING_CANDIDATE_REHEARSAL": "1",
    }

    module.push_project(tmp_path / "project", str(tmp_path / "remote.git"), env=candidate_env)

    commit = [
        row for row in observed
        if row["argv"][:5] == [
            "git", "-C", str(tmp_path / "project"), "commit", "-m"
        ]
    ]
    assert len(commit) == 1
    assert commit[0]["env"] == {
        **candidate_env,
        "REA_BIRTH_LOCAL_SCRATCH_PUSH": "1",
    }
    assert commit[0]["timeout"] == 120


def test_push_project_does_not_mark_github_remote_as_local_scratch(monkeypatch, tmp_path):
    module = load_module()
    observed = []

    def fake_run(argv, *, cwd=None, env=None, timeout=300):
        observed.append({"argv": list(argv), "env": dict(env or {})})
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(module, "run", fake_run)

    module.push_project(tmp_path / "project", "rexcoleman/rehearsal", env={})

    assert all(
        row["env"].get("REA_BIRTH_LOCAL_SCRATCH_PUSH") is None
        for row in observed
    )


def test_birth_loop_pushes_with_gate_env():
    text = SOURCE.read_text(encoding="utf-8")

    assert "push_project(project, repo, env=gate_env(packet_root, source_roots))" in text
    assert "env.update(source_env(source_roots))" in text


def test_issue_test_packet_carries_source_manifest_sidecar(monkeypatch, tmp_path):
    module = load_module()
    site = tmp_path / "site"
    manifest = site / ".github/write-enforcement/frozen_bundle_manifest.generation-5.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"manifest_digest":"' + "a" * 64 + '"}\n', encoding="utf-8")
    (site / ".github/write-enforcement").mkdir(parents=True, exist_ok=True)
    (site / ".github/write-enforcement/non_expiring_enforcement.py").write_text(
        "# fixture\n",
        encoding="utf-8",
    )

    def fake_write_test_key(private_key, public_key):
        private_key.parent.mkdir(parents=True, exist_ok=True)
        private_key.write_text("private\n", encoding="ascii")
        public_key.write_text("public\n", encoding="ascii")

    def fake_run(argv, *, cwd=None, env=None, timeout=300):
        if "issue" in argv:
            output = Path(argv[argv.index("--output") + 1])
            output.mkdir(parents=True)
        if "verify" in argv:
            packet_root = Path(argv[argv.index("--packet-root") + 1])
            assert not (packet_root / "source_manifest.json").exists()
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(module, "write_test_key", fake_write_test_key)
    monkeypatch.setattr(module, "materialize_clean_site_root", lambda args, scratch: (site, manifest))
    monkeypatch.setattr(module, "run", fake_run)
    args = argparse.Namespace(
        site_root=site,
        site_root_head="b" * 40,
    )

    packet, clean_site_root = module.issue_test_packet(args, tmp_path / "scratch")

    assert clean_site_root == site
    assert (packet / "source_manifest.json").read_bytes() == manifest.read_bytes()


def test_source_env_exports_every_signed_source_root(tmp_path):
    module = load_module()
    roots = {
        "research_enforcement_activation": tmp_path / "rea",
        "Moonshots_Career_Thesis_v2": tmp_path / "moonshots",
        "govML": tmp_path / "govml",
        "newsletter": tmp_path / "newsletter",
        "rexcoleman.dev": tmp_path / "rex",
    }

    assert module.source_env(roots) == {
        "REA_ENFORCEMENT_SOURCE_ROOT": str(tmp_path / "rea"),
        "MOONSHOTS_HOME": str(tmp_path / "moonshots"),
        "GOVML_OBJECT_REPO": str(tmp_path / "govml"),
        "NEWSLETTER_SOURCE_ROOT": str(tmp_path / "newsletter"),
        "REX_SITE_SOURCE_ROOT": str(tmp_path / "rex"),
    }
