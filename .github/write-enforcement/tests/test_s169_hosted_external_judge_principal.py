from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / ".github/write-enforcement/setup_external_judge_hosted_principal.py"
WORKFLOW = ROOT / ".github/workflows/issue-external-judge-authority.yml"
OWNER_ROW = ROOT / ".github/write-enforcement/rea_s169_external_judge_principal_owner_row.txt"
WRAPPER = ROOT / ".github/write-enforcement/setup_external_judge_hosted_principal.sh"


def load_tool():
    spec = importlib.util.spec_from_file_location("s169_hosted_principal_setup", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def empty_state() -> dict:
    return {"environment": None, "variables": {}, "secrets": set()}


def test_workflow_is_protected_machine_invoked_exact_byte_signing() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in raw
    assert "request_b64:" in raw and "request_sha256:" in raw
    assert "environment: govml-external-judge-approver" in raw
    assert "group: govml-external-judge-approver" in raw
    assert "cancel-in-progress: false" in raw
    assert "permissions:\n  contents: read" in raw
    assert "persist-credentials: false" in raw
    assert "approve-request-hosted" in raw
    assert "GOVML_EXTERNAL_JUDGE_APPROVING_PRIVATE_KEY_PEM" in raw
    assert "GOVML_EXTERNAL_JUDGE_ISSUER_COMMIT" in raw
    assert "GOVML_EXTERNAL_JUDGE_ISSUER_SHA256" in raw
    assert '[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]' in raw
    assert "base64.b64decode" in raw and "validate=True" in raw
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in raw
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in raw
    for forbidden in (
        "pull-requests: write",
        "contents: write",
        "environment_url",
        "required_reviewers",
        "issue_external_judge_authority.py approve-request ",
    ):
        assert forbidden not in raw


def test_owner_row_is_one_ascii_line_and_drives_whole_setup() -> None:
    raw = OWNER_ROW.read_bytes()
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1
    assert all(32 <= byte <= 126 or byte == 10 for byte in raw)
    assert b";" not in raw and b"&&" not in raw and b"|" not in raw
    assert raw == (
        b"bash /home/azureuser/rexcoleman.dev/.github/write-enforcement/"
        b"setup_external_judge_hosted_principal.sh\n"
    )
    wrapper = WRAPPER.read_text(encoding="ascii")
    assert "exec /usr/bin/python3 \"$TOOL\" --apply" in wrapper
    assert "CHECKED_TOOL_ABSENT" in wrapper
    assert "ls-remote origin refs/heads/main" in wrapper
    assert "REX_PAYLOAD_DIRTY_REFUSED" in wrapper
    assert "diff --quiet \"$COMMIT\"" in wrapper


def test_setup_self_test_and_fixed_one_time_contract() -> None:
    tool = load_tool()
    assert all(tool.self_test().values())
    source = TOOL.read_text(encoding="utf-8")
    assert "PER_ISSUANCE_HUMAN_REVIEW_REFUSED" in source
    assert "--use-device-code" in source
    assert "--web" in source
    assert "az\", \"vm\", \"run-command\", \"invoke" in source
    assert "gh\", \"secret\", \"set" in source
    assert "input_text=private" in source
    assert "private_raw = \"\"" in source
    assert "per_issuance_human_steps\": 0" in source
    assert "payload_binding()" in source
    assert "ln \\\"$stage\\\"" in source
    assert "PENDING_PUBLIC_KEY_MISMATCH_REFUSED" in source
    assert "PENDING_REMOTE_STATE_DRIFT_REFUSED" in source


def test_root_install_and_removal_scripts_are_no_clobber_and_digest_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    scripts = []
    monkeypatch.setattr(tool, "azure_root_script", scripts.append)
    raw = b"public-key-fixture\n"
    expected_sha = tool.sha256(raw)
    tool.install_public_key(raw, predecessor=False)
    tool.remove_public_key(expected_sha)
    install, remove = scripts
    target = str(tool.PUBLIC_KEY_PATH)
    assert f"test ! -e {target}" in install
    assert f"test ! -L {target}" in install
    assert f'ln "$stage" {target}' in install
    assert f'install -o root -g root -m 0644 "$stage" {target}' not in install
    assert f"test -f {target}" in remove
    assert f"test ! -L {target}" in remove
    assert f"= {expected_sha}" in remove
    assert f"rm -- {target}" in remove
    assert "rm -f" not in remove


def test_root_predecessor_transition_is_digest_bound_atomic_and_restorable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    scripts = []
    monkeypatch.setattr(tool, "azure_root_script", scripts.append)
    new_raw = b"replacement-public-key\n"
    new_sha = tool.sha256(new_raw)
    tool.install_public_key(new_raw, predecessor=True)
    tool.restore_predecessor(new_sha)
    replace, restore = scripts
    target = str(tool.PUBLIC_KEY_PATH)
    backup = str(tool.PREDECESSOR_BACKUP_PATH)
    assert tool.PREDECESSOR_SHA256 in replace
    assert f"ln {target} {backup}" in replace
    assert f'mv -T "$stage" {target}' in replace
    assert tool.PREDECESSOR_SHA256 in restore
    assert f"mv -T {backup} {target}" in restore


def install_fake_transition(monkeypatch: pytest.MonkeyPatch, tool, failure: str | None = None):
    remote = empty_state()
    local = {"present": False}
    backup = {"present": False}
    events = []
    binding = ("a" * 40, "b" * 64)
    monkeypatch.setattr(tool, "ensure_host", lambda: events.append("host"))
    monkeypatch.setattr(tool, "ensure_owner_tty", lambda: events.append("tty"))
    monkeypatch.setattr(
        tool, "payload_binding",
        lambda: events.append("payload") or ("f" * 40, {"payload": "1" * 64}),
    )
    monkeypatch.setattr(tool, "gh_login", lambda: events.append("gh-login"))
    monkeypatch.setattr(tool, "refresh_govml", lambda: events.append("refresh"))
    monkeypatch.setattr(tool, "issuer_binding", lambda: binding)
    monkeypatch.setattr(tool, "remote_state", lambda: remote.copy() | {
        "variables": dict(remote["variables"]), "secrets": set(remote["secrets"]),
    })
    monkeypatch.setattr(tool, "local_public_state", lambda: dict(local))
    monkeypatch.setattr(tool, "predecessor_backup_state", lambda: dict(backup))

    def configure_environment(**values):
        events.append("configure")
        tracker = values["tracker"]
        tracker.update({"started": True, "environment_id": 169})
        public_sha = values["public_sha256"]
        remote["environment"] = {"id": 169, "protection_rules": []}
        remote["variables"] = {
            tool.STATE_VARIABLE: f"pending:{public_sha}",
            tool.PUBLIC_SHA_VARIABLE: public_sha,
            tool.ISSUER_COMMIT_VARIABLE: binding[0],
            tool.ISSUER_SHA_VARIABLE: binding[1],
        }
        remote["secrets"] = {tool.SECRET_NAME}

    def install_public(raw, *, predecessor):
        events.append("install")
        if failure == "target-appeared":
            local.update({
                "present": True, "valid": True, "sha256": "9" * 64,
                "uid": 0, "gid": 0, "mode": 0o644,
            })
            raise tool.SetupRefusal("PLANTED_POST_PREFLIGHT_TARGET_APPEARANCE")
        if failure == "install":
            raise tool.SetupRefusal("PLANTED_INSTALL_FAILURE")
        if predecessor:
            backup.clear(); backup.update(local)
        local.update({
            "present": True,
            "valid": True,
            "sha256": tool.sha256(raw),
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
        })

    def mark_complete(public_sha):
        events.append("mark")
        if failure == "mark":
            raise tool.SetupRefusal("PLANTED_MARK_FAILURE")
        remote["variables"][tool.STATE_VARIABLE] = f"complete:{public_sha}"

    def remove_public(expected_sha):
        events.append("remove-public")
        assert expected_sha == local["sha256"]
        local.clear(); local.update({"present": False})

    def restore_public(expected_sha):
        events.append("restore-predecessor")
        assert expected_sha == local["sha256"]
        local.clear(); local.update(backup)
        backup.clear(); backup.update({"present": False})

    def remove_backup(expected_sha):
        events.append("remove-backup")
        assert expected_sha == local["sha256"]
        backup.clear(); backup.update({"present": False})

    def delete_environment(expected_sha, expected_binding):
        events.append("delete-environment")
        assert expected_binding == binding
        assert expected_sha == remote["variables"][tool.PUBLIC_SHA_VARIABLE]
        remote.clear(); remote.update(empty_state())

    def delete_partial_environment(*, public_sha256, binding, environment_id):
        assert environment_id == 169
        delete_environment(public_sha256, binding)

    monkeypatch.setattr(tool, "configure_environment", configure_environment)
    monkeypatch.setattr(tool, "install_public_key", install_public)
    monkeypatch.setattr(tool, "mark_complete", mark_complete)
    monkeypatch.setattr(tool, "remove_public_key", remove_public)
    monkeypatch.setattr(tool, "restore_predecessor", restore_public)
    monkeypatch.setattr(tool, "remove_predecessor_backup", remove_backup)
    monkeypatch.setattr(tool, "delete_pending_environment", delete_environment)
    monkeypatch.setattr(tool, "delete_partial_environment", delete_partial_environment)

    def checked_preflight():
        state = tool.remote_state()
        observed = tool.local_public_state()
        if tool.completed_state(state, observed, binding):
            status = "COMPLETE"
        elif state["environment"] is None and (
            not observed.get("present") or tool.exact_predecessor(observed)
        ):
            status = "READY_FOR_ONE_TIME_SETUP"
        elif str(state["variables"].get(tool.STATE_VARIABLE, "")).startswith("pending:"):
            status = "RECOVERY_REQUIRED"
        else:
            status = "REFUSED"
        if failure == "final" and status == "COMPLETE":
            status = "REFUSED"
        return {"status": status}

    monkeypatch.setattr(tool, "preflight", checked_preflight)
    return remote, local, backup, events


def test_one_time_transition_completes_without_persisting_private_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    remote, local, _backup, events = install_fake_transition(monkeypatch, tool)
    assert tool.apply() == {"status": "COMPLETE"}
    assert events == [
        "host", "tty", "payload", "gh-login", "refresh",
        "configure", "install", "mark",
    ]
    assert remote["secrets"] == {tool.SECRET_NAME}
    assert local["uid"] == 0 and local["gid"] == 0 and local["mode"] == 0o644
    assert remote["variables"][tool.STATE_VARIABLE].startswith("complete:")


def test_measured_production_predecessor_transitions_in_same_one_time_arc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    remote, local, backup, events = install_fake_transition(monkeypatch, tool)
    local.update({
        "present": True,
        "valid": False,
        "sha256": tool.PREDECESSOR_SHA256,
        "uid": tool.PREDECESSOR_UID,
        "gid": tool.PREDECESSOR_GID,
        "mode": tool.PREDECESSOR_MODE,
    })
    assert tool.apply() == {"status": "COMPLETE"}
    assert events[-4:] == ["configure", "install", "mark", "remove-backup"]
    assert local["valid"] is True and local["uid"] == 0 and local["gid"] == 0
    assert backup == {"present": False}
    assert remote["variables"][tool.STATE_VARIABLE].startswith("complete:")


def test_measured_predecessor_is_restored_exactly_on_later_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    remote, local, backup, events = install_fake_transition(
        monkeypatch, tool, failure="mark",
    )
    predecessor = {
        "present": True,
        "valid": False,
        "sha256": tool.PREDECESSOR_SHA256,
        "uid": tool.PREDECESSOR_UID,
        "gid": tool.PREDECESSOR_GID,
        "mode": tool.PREDECESSOR_MODE,
    }
    local.update(predecessor)
    with pytest.raises(tool.SetupRefusal, match="PLANTED_MARK_FAILURE"):
        tool.apply()
    assert local == predecessor
    assert backup == {"present": False}
    assert remote == empty_state()
    assert events[-4:] == ["install", "mark", "delete-environment", "restore-predecessor"]


def test_final_postcheck_failure_after_marker_keeps_exact_complete_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    remote, local, backup, events = install_fake_transition(
        monkeypatch, tool, failure="final",
    )
    with pytest.raises(tool.SetupRefusal, match="FINAL_POSTSTATE_REFUSED"):
        tool.apply()
    binding = ("a" * 40, "b" * 64)
    assert tool.completed_state(remote, local, binding, backup)
    assert "delete-environment" not in events
    assert "remove-public" not in events


def test_post_preflight_target_appearance_never_overwrites_unrelated_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    remote, local, _backup, events = install_fake_transition(
        monkeypatch, tool, failure="target-appeared",
    )
    with pytest.raises(tool.SetupRefusal, match="TARGET_APPEARANCE"):
        tool.apply()
    assert local == {
        "present": True, "valid": True, "sha256": "9" * 64,
        "uid": 0, "gid": 0, "mode": 0o644,
    }
    assert "remove-public" not in events
    assert remote == empty_state()


@pytest.mark.parametrize(
    ("failure", "expected_tail"),
    [
        ("install", ["configure", "install", "delete-environment"]),
        ("mark", ["install", "mark", "delete-environment", "remove-public"]),
    ],
)
def test_transition_failures_run_recovery(
    monkeypatch: pytest.MonkeyPatch, failure: str, expected_tail: list[str],
) -> None:
    tool = load_tool()
    remote, local, _backup, events = install_fake_transition(monkeypatch, tool, failure=failure)
    with pytest.raises(tool.SetupRefusal, match="PLANTED"):
        tool.apply()
    assert events[-len(expected_tail):] == expected_tail
    assert remote == empty_state()
    assert local == {"present": False}


def test_pending_interruption_is_recovered_before_fresh_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    remote, local, _backup, events = install_fake_transition(monkeypatch, tool)
    remote.update({
        "environment": {"protection_rules": []},
        "variables": {
            tool.STATE_VARIABLE: "pending:" + "c" * 64,
            tool.PUBLIC_SHA_VARIABLE: "c" * 64,
            tool.ISSUER_COMMIT_VARIABLE: "a" * 40,
            tool.ISSUER_SHA_VARIABLE: "b" * 64,
        },
        "secrets": {tool.SECRET_NAME},
    })
    local.update({"present": True, "valid": True, "sha256": "c" * 64})
    assert tool.apply() == {"status": "COMPLETE"}
    assert events[:7] == [
        "host", "tty", "payload", "gh-login", "refresh",
        "delete-environment", "remove-public",
    ]
    assert events[7:] == ["configure", "install", "mark"]
    assert remote["variables"][tool.STATE_VARIABLE].startswith("complete:")


def test_pending_mismatched_public_key_hard_refuses_without_recovery_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    remote, local, _backup, events = install_fake_transition(monkeypatch, tool)
    remote.update({
        "environment": {"protection_rules": []},
        "variables": {
            tool.STATE_VARIABLE: "pending:" + "c" * 64,
            tool.PUBLIC_SHA_VARIABLE: "c" * 64,
            tool.ISSUER_COMMIT_VARIABLE: "a" * 40,
            tool.ISSUER_SHA_VARIABLE: "b" * 64,
        },
        "secrets": {tool.SECRET_NAME},
    })
    local.update({
        "present": True, "valid": True, "sha256": "9" * 64,
        "uid": 0, "gid": 0, "mode": 0o644,
    })
    before_remote = {
        "environment": dict(remote["environment"]),
        "variables": dict(remote["variables"]),
        "secrets": set(remote["secrets"]),
    }
    before_local = dict(local)
    with pytest.raises(tool.SetupRefusal, match="PENDING_PUBLIC_KEY_MISMATCH_REFUSED"):
        tool.apply()
    assert remote == before_remote
    assert local == before_local
    assert "remove-public" not in events
    assert "delete-environment" not in events
    assert "configure" not in events


def test_remote_pending_state_drift_refuses_delete_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    public_sha = "c" * 64
    binding = ("a" * 40, "b" * 64)
    exact = {
        "environment": {"protection_rules": []},
        "variables": {
            tool.STATE_VARIABLE: f"pending:{public_sha}",
            tool.PUBLIC_SHA_VARIABLE: public_sha,
            tool.ISSUER_COMMIT_VARIABLE: binding[0],
            tool.ISSUER_SHA_VARIABLE: binding[1],
        },
        "secrets": {tool.SECRET_NAME},
    }
    drift = {
        "environment": {"protection_rules": []},
        "variables": dict(exact["variables"]) | {tool.STATE_VARIABLE: "complete:" + public_sha},
        "secrets": {tool.SECRET_NAME},
    }
    rows = iter([exact, drift])
    calls = []
    monkeypatch.setattr(tool, "remote_state", lambda: next(rows))
    monkeypatch.setattr(tool, "command", lambda arguments, **kwargs: calls.append(arguments))
    with pytest.raises(tool.SetupRefusal, match="PENDING_REMOTE_STATE_DRIFT_REFUSED"):
        tool.delete_pending_environment(public_sha, binding)
    assert calls == []


@pytest.mark.parametrize("boundary", range(6))
def test_each_partial_configuration_boundary_is_attributed_and_rolled_back(
    monkeypatch: pytest.MonkeyPatch, boundary: int,
) -> None:
    tool = load_tool()
    public_sha = "c" * 64
    binding = ("a" * 40, "b" * 64)
    values = tool.partial_values(
        public_sha256=public_sha,
        issuer_commit=binding[0], issuer_sha256=binding[1],
    )
    remote = empty_state()
    mutations = []

    def snapshot():
        return {
            "environment": None if remote["environment"] is None else dict(remote["environment"]),
            "variables": dict(remote["variables"]),
            "secrets": set(remote["secrets"]),
        }

    monkeypatch.setattr(tool, "remote_state", snapshot)

    def fake_command(arguments, **kwargs):
        if "PUT" in arguments:
            remote["environment"] = {"id": 169, "protection_rules": []}
            mutations.append("put")
            return SimpleNamespace(returncode=0, stdout='{"id":169}', stderr="")
        if arguments[:3] == ["gh", "variable", "set"]:
            position = len(remote["variables"]) + 1
            name = arguments[3]
            remote["variables"][name] = dict(values)[name]
            mutations.append(f"variable-{position}")
            if boundary == position:
                raise tool.SetupRefusal(f"PLANTED_CONFIG_BOUNDARY_{boundary}")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if arguments[:3] == ["gh", "secret", "set"]:
            remote["secrets"].add(tool.SECRET_NAME)
            mutations.append("secret")
            if boundary == 5:
                raise tool.SetupRefusal("PLANTED_CONFIG_BOUNDARY_5")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "DELETE" in arguments:
            mutations.append("delete")
            remote.clear(); remote.update(empty_state())
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr(tool, "command", fake_command)
    tracker = {"started": False, "environment_id": None}
    if boundary == 0:
        # A malformed response after a successful PUT cannot be attributed to
        # an environment id and therefore must not be guessed at or deleted.
        def malformed_put(arguments, **kwargs):
            result = fake_command(arguments, **kwargs)
            if "PUT" in arguments:
                result.stdout = "{}"
            return result
        monkeypatch.setattr(tool, "command", malformed_put)
        with pytest.raises(tool.SetupRefusal, match="CREATED_ENVIRONMENT_ID_REFUSED"):
            tool.configure_environment(
                private="private", public_sha256=public_sha,
                issuer_commit=binding[0], issuer_sha256=binding[1], tracker=tracker,
            )
        assert tracker == {"started": True, "environment_id": None}
        assert mutations == ["put"]
        assert remote["environment"] == {"id": 169, "protection_rules": []}
        return

    with pytest.raises(tool.SetupRefusal, match="PLANTED_CONFIG_BOUNDARY"):
        tool.configure_environment(
            private="private", public_sha256=public_sha,
            issuer_commit=binding[0], issuer_sha256=binding[1], tracker=tracker,
        )
    tool.delete_partial_environment(
        public_sha256=public_sha, binding=binding, environment_id=169,
    )
    assert remote == empty_state()
    assert mutations[-1] == "delete"


def test_concurrent_environment_appearance_is_never_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    rows = iter([
        empty_state(),
        {
            "environment": {"id": 999, "protection_rules": []},
            "variables": {"FOREIGN": "state"},
            "secrets": set(),
        },
    ])
    deletes = []
    monkeypatch.setattr(tool, "remote_state", lambda: next(rows))
    monkeypatch.setattr(
        tool, "command",
        lambda arguments, **kwargs: (
            SimpleNamespace(returncode=0, stdout='{"id":169}', stderr="")
            if "PUT" in arguments else deletes.append(arguments)
        ),
    )
    tracker = {"started": False, "environment_id": None}
    with pytest.raises(tool.SetupRefusal, match="CONCURRENT_ENVIRONMENT_APPEARANCE_REFUSED"):
        tool.configure_environment(
            private="private", public_sha256="c" * 64,
            issuer_commit="a" * 40, issuer_sha256="b" * 64, tracker=tracker,
        )
    assert deletes == []


@pytest.mark.parametrize("failed_kind", ["variable", "secret"])
def test_unreadable_environment_rows_fail_closed_without_delete(
    monkeypatch: pytest.MonkeyPatch, failed_kind: str,
) -> None:
    tool = load_tool()
    calls = []

    def fake_command(arguments, **kwargs):
        calls.append(arguments)
        if arguments[:3] == ["gh", "api", "--method"]:
            assert "DELETE" not in arguments
            return SimpleNamespace(
                returncode=0,
                stdout='{"id":169,"protection_rules":[]}', stderr="",
            )
        if arguments[:2] == ["gh", failed_kind]:
            return SimpleNamespace(returncode=1, stdout="", stderr="denied")
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(tool, "command", fake_command)
    with pytest.raises(tool.SetupRefusal, match=f"GITHUB_{failed_kind.upper()}_LIST_REFUSED"):
        tool.delete_partial_environment(
            public_sha256="c" * 64,
            binding=("a" * 40, "b" * 64), environment_id=169,
        )
    assert not any("DELETE" in arguments for arguments in calls)


def test_local_payload_drift_refuses_before_github_or_azure_mutators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = load_tool()
    _remote, _local, _backup, events = install_fake_transition(monkeypatch, tool)

    def refuse_payload():
        events.append("payload-refused")
        raise tool.SetupRefusal("REX_PAYLOAD_DIRTY_REFUSED")

    monkeypatch.setattr(tool, "payload_binding", refuse_payload)
    with pytest.raises(tool.SetupRefusal, match="REX_PAYLOAD_DIRTY_REFUSED"):
        tool.apply()
    assert events == ["host", "tty", "payload-refused"]
