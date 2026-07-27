from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import rex_hybrid_mount as mount


class FakeStore:
    fail_outcome = False
    events: list[tuple[str, str]] = []

    def record_outcome(self, _nonce, **value):
        if self.fail_outcome:
            raise OSError("persist")
        self.events.append(("outcome", value["status"]))


def context(tmp_path: Path) -> mount.RexHybridContext:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    return mount.RexHybridContext(
        repo_root=repo,
        state_root=tmp_path / "state",
        base_context=SimpleNamespace(),
        production=False,
        fixture_root=tmp_path,
    )


def install_authority(monkeypatch):
    FakeStore.fail_outcome = False
    FakeStore.events = []
    calls = []

    def authority(**kwargs):
        calls.append(kwargs)
        return (
            None,
            None,
            FakeStore(),
            {"attempt_nonce": "attempt-1", "capability_id": "cap-1"},
            {"payload": {"capability_id": "cap-1"}},
            {
                "schema_version": "fixture-lineage",
                "candidate_sha256": hashlib.sha256(kwargs["candidate"]).hexdigest(),
            },
            {"wea": {"state_digest": "state", "authority_generation": 4}},
        )

    monkeypatch.setattr(mount, "_authority", authority)
    return calls


def consume_bundle(monkeypatch, tmp_path, route, slug, members):
    calls = install_authority(monkeypatch)
    ctx = context(tmp_path)
    candidate = mount.build_bundle(route, slug, members)
    receipt = mount._consume_bundle(
        route_id=route,
        candidate=candidate,
        effect_plan=mount.bundle_plan(route, candidate),
        target=mount.bundle_target(route, candidate),
        context=ctx,
    )
    return ctx, candidate, receipt, calls


def test_public_production_api_has_no_callback_command_or_context():
    parameters = inspect.signature(mount.consume_exact_bundle).parameters
    assert set(parameters) == {"route_id", "candidate", "effect_plan", "target"}
    assert "effect_callback" not in Path(mount.__file__).read_text()
    public = (
        mount.build_bundle,
        mount.bundle_target,
        mount.bundle_plan,
        mount.consume_exact_bundle,
        mount.build_branch_push_subject,
        mount.branch_push_plan,
        mount.push_pr_branch,
        mount.record_protected_main_merge,
        mount.build_deploy_subject,
        mount.deploy_plan,
        mount.consume_deploy,
    )
    for function in public:
        assert not (
            {"callback", "effect_callback", "command", "destination", "context"}
            & set(inspect.signature(function).parameters)
        ), function.__name__


def test_blg08_writes_exact_bundle_manifest_and_exact_image_set(
    monkeypatch, tmp_path
):
    ctx = context(tmp_path)
    stale = ctx.repo_root / "static/images/post/stale.png"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")
    calls = install_authority(monkeypatch)
    candidate = mount.build_bundle(
        "BLG-08",
        "post",
        [
            ("content/posts/post.md", b"exact post\n"),
            ("static/images/post/figure.png", b"exact image"),
        ],
    )
    target = mount.bundle_target("BLG-08", candidate)
    receipt = mount._consume_bundle(
        route_id="BLG-08",
        candidate=candidate,
        effect_plan=mount.bundle_plan("BLG-08", candidate),
        target=target,
        context=ctx,
    )
    assert not stale.exists()
    assert (ctx.repo_root / "content/posts/post.md").read_bytes() == b"exact post\n"
    assert (
        ctx.repo_root / "static/images/post/figure.png"
    ).read_bytes() == b"exact image"
    observed_images = {
        path.relative_to(ctx.repo_root).as_posix()
        for path in (ctx.repo_root / "static/images/post").rglob("*")
        if path.is_file()
    }
    assert observed_images == {"static/images/post/figure.png"}
    manifests = [
        row for row in target["members"]
        if row["path"].startswith(".rea/c3/hybrid-subject-manifests/")
    ]
    assert len(manifests) == 1
    assert (ctx.repo_root / manifests[0]["path"]).is_file()
    assert Path(receipt["local_effect_evidence_path"]).is_relative_to(ctx.state_root)
    assert receipt["server_acceptance"] == "NOT_ESTABLISHED"
    assert calls[0]["target"] == target


def test_bundle_receipt_failure_restores_every_byte_and_created_directory(
    monkeypatch, tmp_path
):
    ctx = context(tmp_path)
    post = ctx.repo_root / "content/posts/post.md"
    stale = ctx.repo_root / "static/images/post/stale.png"
    post.parent.mkdir(parents=True)
    stale.parent.mkdir(parents=True)
    post.write_bytes(b"before post")
    stale.write_bytes(b"before stale")
    install_authority(monkeypatch)
    FakeStore.fail_outcome = True
    candidate = mount.build_bundle(
        "BLG-08",
        "post",
        [
            ("content/posts/post.md", b"replacement"),
            ("static/images/post/new/deep.png", b"new"),
        ],
    )
    with pytest.raises(mount.RexHybridRefusal, match="ROLLBACK_COMPLETE"):
        mount._consume_bundle(
            route_id="BLG-08",
            candidate=candidate,
            effect_plan=mount.bundle_plan("BLG-08", candidate),
            target=mount.bundle_target("BLG-08", candidate),
            context=ctx,
        )
    assert post.read_bytes() == b"before post"
    assert stale.read_bytes() == b"before stale"
    assert not (ctx.repo_root / "static/images/post/new").exists()
    assert not (ctx.repo_root / ".rea").exists()
    assert not (ctx.state_root / "local-effect-evidence").exists()


def test_dst02_writes_exact_three_cross_posts(monkeypatch, tmp_path):
    members = [
        ("cross-posts/post_devto.md", b"dev"),
        ("cross-posts/post_linkedin.txt", b"linkedin"),
        ("cross-posts/post_reddit.md", b"reddit"),
    ]
    ctx, _candidate, receipt, _calls = consume_bundle(
        monkeypatch, tmp_path, "DST-02", "post", members
    )
    for relative, raw in members:
        assert (ctx.repo_root / relative).read_bytes() == raw
    assert receipt["route_id"] == "DST-02"


def test_arbitrary_member_and_symlink_refuse_before_authority(
    monkeypatch, tmp_path
):
    calls = install_authority(monkeypatch)
    with pytest.raises(mount.RexHybridRefusal, match="ARBITRARY_SINK_REFUSED"):
        mount.build_bundle(
            "BLG-08", "post", [("content/about.md", b"wrong sink")]
        )
    ctx = context(tmp_path / "second")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    parent = ctx.repo_root / "content"
    parent.mkdir()
    (parent / "posts").symlink_to(outside)
    candidate = mount.build_bundle(
        "BLG-08", "post", [("content/posts/post.md", b"exact")]
    )
    with pytest.raises(mount.RexHybridRefusal, match="ARBITRARY_SINK_REFUSED"):
        mount._consume_bundle(
            route_id="BLG-08",
            candidate=candidate,
            effect_plan=mount.bundle_plan("BLG-08", candidate),
            target=mount.bundle_target("BLG-08", candidate),
            context=ctx,
        )
    assert calls == []
    assert outside.read_bytes() == b"outside"


def test_target_and_plan_mutations_refuse_before_authority(monkeypatch, tmp_path):
    calls = install_authority(monkeypatch)
    ctx = context(tmp_path)
    candidate = mount.build_bundle(
        "DST-02",
        "post",
        [
            ("cross-posts/post_devto.md", b"dev"),
            ("cross-posts/post_linkedin.txt", b"linkedin"),
            ("cross-posts/post_reddit.md", b"reddit"),
        ],
    )
    target = mount.bundle_target("DST-02", candidate)
    target["slug"] = "other"
    with pytest.raises(mount.RexHybridRefusal, match="PLAN_TARGET_MISMATCH"):
        mount._consume_bundle(
            route_id="DST-02",
            candidate=candidate,
            effect_plan=mount.bundle_plan("DST-02", candidate),
            target=target,
            context=ctx,
        )
    assert calls == []


def test_branch_push_source_never_claims_registered_main_effect():
    source = inspect.getsource(mount._consume_branch_push)
    assert "_authority(" not in source
    assert "deploy_push_main" not in source
    assert '"PRE_MAIN_BOUNDARY"' in source
    assert '"main_effect_established": False' in source


def test_post_merge_detector_cannot_mint_authorization():
    source = inspect.getsource(mount.record_protected_main_merge)
    assert "_authority(" not in source
    assert "PROTECTED_MAIN_TRANSITION_DETECTED" in source
    assert '"server_acceptance": "NOT_ESTABLISHED"' in source
    assert '"main_effect_established": False' in source
    assert "PROTECTED_MAIN_EFFECT_ESTABLISHED" not in source


def test_installed_provider_binding_has_no_checkout_or_caller_override():
    source = Path(mount.__file__).read_text()
    assert "research_enforcement_activation" not in source
    assert "MOONSHOTS_MOUNT" not in source
    assert mount.INSTALLED_VERIFY_ONLY_PROVIDER == (
        Path.home()
        / ".local/libexec/rea_enforcement/hybrid_capability_provider"
    )
    provider_block = source.split(
        "INSTALLED_VERIFY_ONLY_PROVIDER =", 1
    )[1].split("CANONICAL_REPO =", 1)[0]
    assert "environ" not in provider_block
    assert "getenv(" not in provider_block


def test_provider_absence_refuses_before_bundle_mutation(monkeypatch, tmp_path):
    monkeypatch.setattr(
        mount,
        "INSTALLED_VERIFY_ONLY_PROVIDER",
        tmp_path / "missing-provider",
    )
    ctx = context(tmp_path)
    candidate = mount.build_bundle(
        "BLG-08", "post", [("content/posts/post.md", b"exact")]
    )
    with pytest.raises(
        mount.RexHybridRefusal, match="TRUSTED_CAPABILITY_ISSUER_UNAVAILABLE"
    ):
        mount._consume_bundle(
            route_id="BLG-08",
            candidate=candidate,
            effect_plan=mount.bundle_plan("BLG-08", candidate),
            target=mount.bundle_target("BLG-08", candidate),
            context=ctx,
        )
    assert not (ctx.repo_root / "content/posts/post.md").exists()
    assert not (ctx.repo_root / ".rea").exists()


def test_authority_consumes_closed_installed_provider_response(
    monkeypatch, tmp_path
):
    provider = tmp_path / "hybrid_capability_provider"
    provider.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    provider.chmod(0o700)
    monkeypatch.setattr(mount, "INSTALLED_VERIFY_ONLY_PROVIDER", provider)
    captured = []

    def fake_run(command, **kwargs):
        request = json.loads(kwargs["input"])
        captured.append((command, request))
        binding = {
            key: request[key]
            for key in (
                "route_id",
                "surface",
                "destination",
                "requested_effect",
                "candidate_sha256",
                "candidate_byte_length",
                "target_sha256",
                "plan_sha256",
                "preimage_sha256",
                "wea",
            )
        }
        response = {
            "schema_version": "rea.write.registry-verification-response.v1",
            "authorization": {"artifact_class": "public-only"},
            "decision": {
                "verdict": "ADMIT",
                "verification_id": "registry-verification-" + "a" * 64,
                "request_binding": binding,
            },
        }
        return SimpleNamespace(
            returncode=0,
            stdout=mount._canonical(response),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    ctx = context(tmp_path)
    result = mount._authority(
        context=ctx,
        route_id="BLG-08",
        candidate=b"exact",
        destination="bundle://fixed",
        requested_effect="atomic_write",
        target={"fixed": True},
        plan_sha256="b" * 64,
        preimage_sha256=None,
    )

    assert captured[0][0] == [str(provider)]
    assert captured[0][1]["schema_version"] == (
        "rea.c3.hybrid.capability-request.v2"
    )
    assert captured[0][1]["candidate_b64"] == "ZXhhY3Q="
    assert result[4] == {"artifact_class": "public-only"}
    assert result[5]["verdict"] == "ADMIT"
    assert result[3]["capability_id"].startswith("registry-verification-")


def test_authorization_transport_explicitly_excludes_server_and_spend_proof(
    monkeypatch, tmp_path
):
    captured = []

    def fake_input(_repo, arguments, raw, *, environment=None):
        del environment
        captured.append((arguments, raw))
        if arguments[0] == "hash-object":
            return "a" * 40
        if arguments[0] == "mktree":
            return "b" * 40
        if arguments[0] == "commit-tree":
            return "c" * 40
        raise AssertionError(arguments)

    calls = []

    def fake_git(_repo, *arguments):
        calls.append(arguments)
        if arguments[:2] == ("ls-remote", "--heads"):
            if sum(1 for call in calls if call[:2] == ("ls-remote", "--heads")) == 1:
                return ""
            return (
                f"{'c' * 40}\t"
                f"refs/heads/rea-c3-admission/{'d' * 40}"
            )
        return ""

    monkeypatch.setattr(mount, "_git_input", fake_input)
    monkeypatch.setattr(mount, "_git", fake_git)
    evidence = mount._canonical({
        "schema_version": mount.LOCAL_EFFECT_SCHEMA,
        "server_acceptance": "NOT_ESTABLISHED",
    }) + b"\n"
    result = mount._push_admission_transport(
        tmp_path, "d" * 40, [evidence]
    )
    transport_raw = captured[0][1]
    transport = json.loads(transport_raw)
    assert transport["semantic_boundary"] == "AUTHORIZATION_TRANSPORT_ONLY"
    assert transport["server_effect_established"] is False
    assert transport["durable_spend_proof_included"] is False
    assert result["transport_sha256"] == hashlib.sha256(transport_raw).hexdigest()
    assert result["reused_existing_ref"] is False


def authorization_transport(head_sha: str, evidence: bytes) -> bytes:
    return mount._canonical({
        "schema_version": mount.TRANSPORT_SCHEMA,
        "repository": mount.REPOSITORY,
        "head_sha": head_sha,
        "semantic_boundary": "AUTHORIZATION_TRANSPORT_ONLY",
        "server_effect_established": False,
        "durable_spend_proof_included": False,
        "receipts": [json.loads(evidence)],
    }) + b"\n"


def test_authorization_transport_reuses_exact_existing_remote_ref(
    monkeypatch, tmp_path
):
    head = "d" * 40
    commit = "c" * 40
    tree = "b" * 40
    reference = f"refs/heads/rea-c3-admission/{head}"
    evidence = mount._canonical({
        "schema_version": mount.LOCAL_EFFECT_SCHEMA,
        "server_acceptance": "NOT_ESTABLISHED",
    }) + b"\n"
    transport = authorization_transport(head, evidence)
    blob = hashlib.sha1(
        b"blob " + str(len(transport)).encode() + b"\0" + transport
    ).hexdigest()

    def fake_git(_repo, *arguments):
        if arguments[:2] == ("ls-remote", "--heads"):
            return f"{commit}\t{reference}"
        if arguments[:3] == ("fetch", "--no-tags", "origin"):
            return ""
        if arguments == ("rev-parse", "FETCH_HEAD"):
            return commit
        if arguments == ("rev-parse", f"{commit}^{{tree}}"):
            return tree
        if arguments == ("ls-tree", "-r", "--full-tree", commit):
            return f"100644 blob {blob}\tadmission-transport.json"
        raise AssertionError(arguments)

    monkeypatch.setattr(mount, "_git", fake_git)
    monkeypatch.setattr(
        mount, "_git_bytes",
        lambda _repo, *arguments: (
            transport
            if arguments == ("show", f"{commit}:admission-transport.json")
            else (_ for _ in ()).throw(AssertionError(arguments))
        ),
    )
    monkeypatch.setattr(
        mount,
        "_git_input",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("must not create a new commit")
        ),
    )
    result = mount._push_admission_transport(tmp_path, head, [evidence])
    assert result["reused_existing_ref"] is True
    assert result["transport_commit_sha"] == commit
    assert result["transport_tree_sha"] == tree
    assert result["transport_sha256"] == hashlib.sha256(transport).hexdigest()


def test_authorization_transport_existing_mismatch_refuses(
    monkeypatch, tmp_path
):
    head = "d" * 40
    commit = "c" * 40
    reference = f"refs/heads/rea-c3-admission/{head}"
    evidence = mount._canonical({
        "schema_version": mount.LOCAL_EFFECT_SCHEMA,
        "server_acceptance": "NOT_ESTABLISHED",
    }) + b"\n"

    def fake_git(_repo, *arguments):
        if arguments[:2] == ("ls-remote", "--heads"):
            return f"{commit}\t{reference}"
        if arguments[:3] == ("fetch", "--no-tags", "origin"):
            return ""
        if arguments == ("rev-parse", "FETCH_HEAD"):
            return commit
        raise AssertionError(arguments)

    monkeypatch.setattr(mount, "_git", fake_git)
    monkeypatch.setattr(mount, "_git_bytes", lambda *_args: b"wrong\n")
    with pytest.raises(
        mount.RexHybridRefusal, match="ref_content_mismatch"
    ):
        mount._push_admission_transport(tmp_path, head, [evidence])


def deploy_receipt(run_id=77, nonce="attempt-1234567890", sha="a" * 40):
    return {
        "schema_version": mount.DEPLOY_RECEIPT_SCHEMA,
        "repository": mount.REPOSITORY,
        "run_id": run_id,
        "run_attempt": 1,
        "target_sha": sha,
        "checked_out_sha": sha,
        "deployed_sha": sha,
        "dispatch_nonce": nonce,
        "page_url": "https://rexcoleman.dev/",
        "deployment_status": "success",
    }


def run_deploy_probe(monkeypatch, tmp_path, *, app_slug="github-actions", log_run=77):
    sha = "a" * 40
    nonce = "attempt-1234567890"

    def fake_run(command, **_kwargs):
        if command[:3] == ["gh", "run", "download"]:
            directory = Path(command[command.index("--dir") + 1])
            (directory / "deploy-receipt.json").write_text(
                json.dumps(deploy_receipt(sha=sha, nonce=nonce),
                           sort_keys=True, separators=(",", ":")) + "\n"
            )
        return SimpleNamespace(stdout="")

    def fake_gh(*arguments):
        joined = " ".join(arguments)
        if arguments[:2] == ("run", "list"):
            return [{
                "databaseId": 77,
                "headSha": sha,
                "status": "completed",
                "conclusion": "success",
                "url": "https://github.test/run/77",
            }]
        if "actions/runs/77" in joined:
            return {
                "id": 77, "head_sha": sha, "event": "workflow_dispatch",
                "status": "completed", "conclusion": "success",
                "html_url": "https://github.test/run/77",
            }
        if "/deployments?" in joined:
            return [{
                "id": 91,
                "sha": sha,
                "ref": "main",
                "environment": "github-pages",
                "creator": {"login": "rexcoleman"},
                "performed_via_github_app": {
                    "slug": app_slug, "id": 15368,
                },
            }]
        if "/deployments/91/statuses" in joined:
            return [{
                "id": 92,
                "state": "success",
                "log_url": (
                    f"https://github.com/rex/actions/runs/{log_run}/job/3"
                ),
                "environment_url": "https://rexcoleman.dev/",
            }]
        raise AssertionError(arguments)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(mount, "_gh_json", fake_gh)
    return mount._dispatch_and_wait(
        commit_sha=sha, dispatch_nonce=nonce, timeout_seconds=1
    )


def test_deploy_requires_independent_run_and_pages_deployment(monkeypatch, tmp_path):
    result = run_deploy_probe(monkeypatch, tmp_path)
    assert result["github_run_evidence"]["head_sha"] == "a" * 40
    assert result["github_deployment_evidence"] == {
        "deployment_id": 91,
        "deployment_sha": "a" * 40,
        "deployment_ref": "main",
        "deployment_environment": "github-pages",
        "status_id": 92,
        "status_state": "success",
        "status_log_url": "https://github.com/rex/actions/runs/77/job/3",
        "environment_url": "https://rexcoleman.dev/",
    }


@pytest.mark.parametrize(
    ("app_slug", "log_run"),
    [("wrong-app", 77), ("github-actions", 88)],
)
def test_deploy_wrong_app_or_wrong_run_refuses(
    monkeypatch, tmp_path, app_slug, log_run
):
    ticks = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(mount.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(mount.time, "sleep", lambda _seconds: None)
    with pytest.raises(mount.RexHybridRefusal, match="DEPLOY_RECEIPT_UNAVAILABLE"):
        run_deploy_probe(
            monkeypatch, tmp_path, app_slug=app_slug, log_run=log_run
        )


def test_deploy_workflow_has_only_immutable_action_pins():
    raw = (ROOT / ".github/workflows/deploy.yml").read_text()
    uses = re.findall(r"^\s*uses:\s*([^#\s]+)", raw, re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses)
    assert "deployment_id" not in raw
    assert "target_sha" in raw
    assert "dispatch_nonce" in raw
    assert "persist-credentials: false" in raw
    assert "hugo-version: '0.147.6'" in raw
    assert "hugo-version: 'latest'" not in raw


def test_publish_script_is_pr_only_and_no_direct_copy_or_main_push():
    raw = (ROOT / "publish.sh").read_text()
    assert "git push origin main" not in raw
    assert 'python3 "$SITE_DIR/scripts/rex_release.py" push' in raw
    assert "PRE_MAIN_BOUNDARY" in raw
    assert 'cp -r "${IMG_SRC}/"* "$IMG_DEST/"' not in raw


def test_cross_post_callsite_passes_exact_data_only_bundle(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "cross_post_under_test", ROOT / "cross-post.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    post = tmp_path / "example-post.md"
    post.write_text(
        "---\ntitle: \"Example\"\ntags: [security]\n---\n\n"
        "## Finding\n\nA measured result reached 42% in the bounded sample.\n"
    )
    captured = []
    monkeypatch.setattr(
        module,
        "consume_exact_bundle",
        lambda **kwargs: captured.append(kwargs) or {"verdict": "EFFECT_COMMITTED"},
    )
    monkeypatch.setattr(sys, "argv", ["cross-post.py", str(post)])
    assert module.main() == 0
    assert len(captured) == 1
    call = captured[0]
    assert call["route_id"] == "DST-02"
    assert call["target"] == mount.bundle_target("DST-02", call["candidate"])
    artifact_paths = {
        row["path"] for row in call["target"]["members"]
        if not row["path"].startswith(".rea/")
    }
    assert artifact_paths == {
        "cross-posts/example-post_devto.md",
        "cross-posts/example-post_linkedin.txt",
        "cross-posts/example-post_reddit.md",
    }
    source = (ROOT / "cross-post.py").read_text()
    assert "runtime_mount" not in source
    assert "effect_callback" not in source


def test_deploy_subject_hashes_workflow_from_claimed_main_commit(
    monkeypatch, tmp_path
):
    main_sha = "a" * 40
    tree_sha = "b" * 40
    main = {
        "schema_version": mount.EFFECT_SCHEMA,
        "verdict": "PROTECTED_MAIN_TRANSITION_DETECTED",
        "route_id": "BLG-09",
        "repository": mount.REPOSITORY,
        "pr_number": 45,
        "pr_url": "https://github.test/pr/45",
        "pr_head_sha": "c" * 40,
        "main_commit_sha": main_sha,
        "main_tree_sha": tree_sha,
        "current_origin_main_sha": main_sha,
        "merged_at": "2026-07-27T00:00:00Z",
        "pre_main_receipt_sha256": "d" * 64,
        "merge_head_ancestor": True,
        "merge_main_ancestor_of_current": True,
        "main_transition_detected": True,
        "server_acceptance": "NOT_ESTABLISHED",
        "main_effect_established": False,
    }
    receipt = tmp_path / "main.json"
    receipt.write_bytes(mount._canonical(main) + b"\n")
    observed = []
    workflow = b"name: exact workflow\n"

    def fake_git_bytes(repo, *arguments):
        observed.append((repo, arguments))
        return workflow

    monkeypatch.setattr(mount, "CANONICAL_REPO", tmp_path / "repo")
    monkeypatch.setattr(mount, "_git_bytes", fake_git_bytes)
    subject = json.loads(mount.build_deploy_subject(receipt))
    assert subject["workflow_sha256"] == hashlib.sha256(workflow).hexdigest()
    assert observed == [
        (
            tmp_path / "repo",
            ("show", f"{main_sha}:.github/workflows/deploy.yml"),
        )
    ]
