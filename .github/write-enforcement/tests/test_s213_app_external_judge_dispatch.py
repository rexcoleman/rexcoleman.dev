import base64
import hashlib
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / ".github/write-enforcement/dispatch_external_judge_as_app.py"
WORKFLOW = ROOT / ".github/workflows/dispatch-external-judge-authority-as-app.yml"
SPEC = importlib.util.spec_from_file_location("s213_app_dispatch", TOOL)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def test_dispatch_attempts_the_exact_govml_workflow(monkeypatch, capsys):
    request = b'{"schema":"test"}\n'
    encoded = base64.b64encode(request).decode("ascii")
    digest = hashlib.sha256(request).hexdigest()
    monkeypatch.setattr(tool, "_credentials", lambda: ("123", b"throwaway-key"))
    monkeypatch.setattr(tool, "_jwt", lambda app_id, key: "jwt")
    calls = []

    def fake(method, path, bearer, payload=None):
        calls.append((method, path, bearer, payload))
        if path.endswith("/installation"):
            return 200, b'{"id":77}'
        if path.endswith("/access_tokens"):
            return 201, b'{"token":"abcdefghijklmnopqrstuvwxyz","repositories":[{"name":"govML"}]}'
        return 204, b""

    monkeypatch.setattr(tool, "_request", fake)
    tool.dispatch(encoded, digest)
    assert calls[-1][0:3] == (
        "POST",
        "/repos/rexcoleman/govML/actions/workflows/issue-external-judge-authority.yml/dispatches",
        "abcdefghijklmnopqrstuvwxyz",
    )
    assert calls[-1][3] == {
        "ref": "main",
        "inputs": {"request_b64": encoded, "request_sha256": digest},
    }
    assert "APP_DISPATCH_ACCEPTED" in capsys.readouterr().out


def test_real_403_is_preserved_as_the_permission_refusal(monkeypatch):
    request = b'{"schema":"test"}\n'
    encoded = base64.b64encode(request).decode("ascii")
    digest = hashlib.sha256(request).hexdigest()
    monkeypatch.setattr(tool, "_credentials", lambda: ("123", b"throwaway-key"))
    monkeypatch.setattr(tool, "_jwt", lambda app_id, key: "jwt")

    def fake(method, path, bearer, payload=None):
        if path.endswith("/installation"):
            return 200, b'{"id":77}'
        if path.endswith("/access_tokens"):
            return 201, b'{"token":"abcdefghijklmnopqrstuvwxyz","repositories":[{"name":"govML"}]}'
        return 403, b'{"message":"Resource not accessible by integration"}'

    monkeypatch.setattr(tool, "_request", fake)
    try:
        tool.dispatch(encoded, digest)
    except tool.Refusal as exc:
        assert str(exc) == "APP_DISPATCH_HTTP_403_RESOURCE_NOT_ACCESSIBLE_BY_INTEGRATION"
    else:
        raise AssertionError("403 did not refuse")


def test_workflow_never_receives_the_approving_private_key():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "environment: govml-external-judge-approver" in raw
    assert "GOVML_REA_READ_APP_ID" in raw
    assert "GOVML_REA_READ_APP_PRIVATE_KEY_B64" in raw
    assert "GOVML_EXTERNAL_JUDGE_APPROVING_PRIVATE_KEY_PEM" not in raw
    assert "persist-credentials: false" in raw
