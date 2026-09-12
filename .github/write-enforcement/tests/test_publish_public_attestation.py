from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pytest
from pathlib import Path
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "publish_public_attestation.py"
SPEC = importlib.util.spec_from_file_location("publish_public_attestation", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def packet(tmp_path, run_id=77, predecessor_sha=None):
    root = tmp_path / "issuance"
    root.mkdir()
    predecessor = b"predecessor\n"
    if predecessor_sha is None:
        predecessor_sha = sha(predecessor)
    for name in sorted(tool.EXPECTED_FILES - {
        "SHA256SUMS", "issuance_receipt.json",
        "enforcement_bundle_manifest.json",
        "predecessor_write_enforcement_attestation.json",
    }):
        (root / name).write_bytes(("fixture-%s\n" % name).encode("ascii"))
    (root / "predecessor_write_enforcement_attestation.json").write_bytes(predecessor)
    (root / "enforcement_bundle_manifest.json").write_text(
        json.dumps({"authority_generation": 5}), encoding="ascii"
    )
    key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    (root / "trusted_wea_public.pem").write_bytes(public)
    payload={k: "c"*64 for k in tool.history.LIVE_FIELDS-{"signature"}}
    payload.update(schema_version="rea.write.wea.live.v2",purpose="LIVE_ENFORCEMENT",state="ENFORCING",issuer=tool.history.ISSUER,authority_epoch=7,predecessor_wea_digest=predecessor_sha)
    payload.update(issued_at="2020-01-01T00:00:00Z",not_before="2020-01-01T00:00:00Z",expires_at="2020-01-02T00:00:00Z")
    signed_digest=sha(tool.history.canonical(payload))
    payload["signature"]={"algorithm":"ed25519","signed_digest":signed_digest,"value":base64.b64encode(key.sign(bytes.fromhex(signed_digest))).decode()}
    (root / "write_enforcement_attestation.json").write_bytes(tool.history.canonical(payload))
    wea_sha = sha((root / "write_enforcement_attestation.json").read_bytes())
    (root / "issuance_receipt.json").write_text(json.dumps({
        "workflow_run_id": run_id,
        "workflow_repository": tool.REPOSITORY,
        "event": "workflow_dispatch",
        "workflow_ref": "refs/tags/rea-wea-generation-5-fixture",
        "workflow_sha": "a" * 40,
        "wea_sha256": wea_sha,
    }), encoding="ascii")
    claims = []
    for name in sorted(tool.EXPECTED_FILES - {"SHA256SUMS"}):
        claims.append("%s  %s" % (sha((root / name).read_bytes()), name))
    (root / "SHA256SUMS").write_text("\n".join(claims) + "\n", encoding="ascii")
    return root, predecessor_sha


def args(root, run_id=77, predecessor_sha=None):
    return SimpleNamespace(
        issuance=str(root), run_id=run_id, trusted_public_key=str(root / "trusted_wea_public.pem"),
        workflow_ref="refs/tags/rea-wea-generation-5-fixture",
        workflow_sha="a" * 40,
        genesis_predecessor_wea_sha256=predecessor_sha,
    )


def test_packet_validation_binds_exact_public_set_receipt_and_predecessor(tmp_path):
    root, predecessor_sha = packet(tmp_path)
    receipt, files = tool.validate_packet(
        root, 77, "refs/tags/rea-wea-generation-5-fixture", "a" * 40,
        predecessor_sha,
    )
    assert receipt["workflow_run_id"] == 77
    assert set(files) == tool.EXPECTED_FILES
    (root / "unexpected").write_text("bad\n", encoding="ascii")
    try:
        tool.validate_packet(root, 77, "refs/tags/rea-wea-generation-5-fixture",
                             "a" * 40, predecessor_sha)
    except tool.Refusal as exc:
        assert "PUBLIC_PACKET_FILE_SET_REFUSED" in str(exc)
    else:
        raise AssertionError("extra packet member accepted")


def test_contents_api_line_wrapped_base64_is_strictly_decoded(monkeypatch):
    raw = b"public pointer bytes\n"
    encoded = base64.b64encode(raw).decode("ascii")
    wrapped = encoded[:8] + "\n" + encoded[8:16] + "\r\n" + encoded[16:]
    monkeypatch.setattr(tool, "gh_api", lambda *_args, **_kwargs: {
        "type": "file", "path": tool.POINTER, "content": wrapped,
    })
    assert tool.content_bytes(tool.POINTER, "a" * 40) == raw
    monkeypatch.setattr(tool, "gh_api", lambda *_args, **_kwargs: {
        "type": "file", "path": tool.POINTER, "content": encoded + "!",
    })
    try:
        tool.content_bytes(tool.POINTER, "a" * 40)
    except tool.Refusal as exc:
        assert str(exc) == "PUBLIC_CONTENT_MALFORMED path=%s" % tool.POINTER
    else:
        raise AssertionError("invalid base64 alphabet admitted")


@pytest.mark.parametrize('budget_plant', ['none', 'before_objects', 'before_ref'])
def test_genesis_publish_is_unique_path_pointer_and_nonforced_ref(tmp_path, monkeypatch, budget_plant):
    from test_durable_attestation_history import budget_fixture
    budget = budget_fixture(monkeypatch, tool.history, 'issue-wea', 950 if budget_plant=='before_objects' else 0)
    root, predecessor_sha = packet(tmp_path)
    objects = {}
    calls = []
    counter = [0]

    def fake_api(path, method="GET", body=None, allow_not_found=False):
        calls.append((path, method, body))
        if "/git/matching-refs/" in path:
            return []
        if path.endswith("/git/commits/" + "a" * 40):
            return {"tree": {"sha": "e" * 40}}
        counter[0] += 1
        digest = ("%040x" % counter[0])[-40:]
        if path.endswith("/git/blobs"):
            return {"sha": digest}
        if path.endswith("/git/trees"):
            objects["tree"] = body
            return {"sha": digest}
        if path.endswith("/git/commits"):
            objects["packet_commit"] = digest
            return {"sha": digest}
        if path.endswith("/git/tags"):
            objects["tag"] = digest
            if budget_plant == 'before_ref':
                budget.jobs[0]['started_at'] = (tool.history.datetime.now(tool.history.timezone.utc)
                    - tool.history.timedelta(seconds=950)).strftime('%Y-%m-%dT%H:%M:%SZ')
            return {"sha": digest}
        if path.endswith("/git/refs"):
            objects["head"] = body["sha"]
            return {"ref": body["ref"], "object": {"sha": body["sha"]}}
        if "/git/ref/tags/" in path:
            return {"object": {"type": "tag", "sha": objects["tag"]}}
        raise AssertionError(path)

    monkeypatch.setattr(tool, "gh_api", fake_api)
    monkeypatch.setattr(tool, "successful_packet_tags", lambda rows, trusted_key: [])
    pointer_holder = {}

    def fake_content(path, commit):
        assert path == tool.POINTER and commit == objects["packet_commit"]
        pointer_entry = [row for row in objects["tree"]["tree"] if row["path"] == tool.POINTER][0]
        assert pointer_entry["mode"] == "100644"
        files = {name: sha((root / name).read_bytes()) for name in tool.EXPECTED_FILES}
        pointer_holder.update({
            "schema_version": tool.SCHEMA, "repository": tool.REPOSITORY,
            "workflow_run_id": 77,
            "packet_tag": tool.TAG_PREFIX + "77",
            "workflow_ref": "refs/tags/rea-wea-generation-5-fixture",
            "workflow_sha": "a" * 40,
            "packet_path": "%s/packets/77" % tool.PUBLIC_ROOT,
            "files": dict(sorted(files.items())),
        })
        return json.dumps(pointer_holder).encode("utf-8")

    monkeypatch.setattr(tool, "content_bytes", fake_content)
    if budget_plant != 'none':
        with pytest.raises(tool.history.Refusal, match='publication_budget_insufficient'):
            tool.publish(args(root, predecessor_sha=predecessor_sha))
        assert not any(path.endswith('/git/refs') and method=='POST' for path,method,_ in calls)
        if budget_plant == 'before_objects':
            assert not any(method=='POST' for _,method,_ in calls)
        return
    assert len(tool.publish(args(root, predecessor_sha=predecessor_sha))) == 40
    tree_paths = {row["path"] for row in objects["tree"]["tree"]}
    assert tree_paths == {tool.POINTER} | {
        "%s/packets/77/%s" % (tool.PUBLIC_ROOT, name)
        for name in tool.EXPECTED_FILES
    }
    assert not any(method == "PATCH" for _path, method, _body in calls)
    assert any(body and body.get("ref") == "refs/tags/%s77" % tool.TAG_PREFIX
               for _path, _method, body in calls if isinstance(body, dict))


def test_existing_branch_requires_monotonic_run_and_exact_predecessor(tmp_path, monkeypatch):
    root, predecessor_sha = packet(tmp_path, run_id=78)
    head = "b" * 40
    prior = {
        "schema_version": tool.SCHEMA, "repository": tool.REPOSITORY,
        "workflow_run_id": 77, "workflow_ref": "refs/tags/old",
        "workflow_sha": "c" * 40,
        "packet_path": "%s/packets/77" % tool.PUBLIC_ROOT,
        "files": {name: "d" * 64 for name in tool.EXPECTED_FILES},
    }
    prior["files"]["write_enforcement_attestation.json"] = "e" * 64
    monkeypatch.setattr(tool, "packet_tags", lambda: [(77, head)])
    monkeypatch.setattr(tool, "successful_packet_tags", lambda _rows, trusted_key: [(77, head, prior)])
    monkeypatch.setattr(tool, "gh_api", lambda *_a, **_k: (_ for _ in ()).throw(
        AssertionError("API reached after chain mismatch")
    ))
    try:
        tool.publish(args(root, run_id=78, predecessor_sha=predecessor_sha))
    except tool.Refusal as exc:
        assert "PUBLIC_PREDECESSOR_CHAIN_REFUSED" in str(exc)
    else:
        raise AssertionError("wrong predecessor chain accepted")


def test_publisher_uses_only_durable_success_rows(monkeypatch):
    prior={"workflow_run_id":78,"files":{"write_enforcement_attestation.json":"a"*64}}
    rows=[{"record":{"run_id":77,"packet_commit":"b"*40,"conclusion":"failure"},"packet":{"pointer":{}}},
          {"record":{"run_id":78,"packet_commit":"c"*40,"conclusion":"success"},"packet":{"pointer":prior}}]
    monkeypatch.setattr(tool.history,"GitObjects",lambda: object())
    monkeypatch.setattr(tool.history,"scan",lambda api,key: rows)
    monkeypatch.setattr(tool,"gh_api",lambda *a,**kw: (_ for _ in ()).throw(AssertionError("retention API reached")))
    assert tool.successful_packet_tags([(77,"b"*40),(78,"c"*40)],b'key')==[(78,"c"*40,prior)]


def test_publisher_refuses_unfinalized_tail(monkeypatch):
    monkeypatch.setattr(tool.history,"GitObjects",lambda: object())
    def unknown(api,key): raise tool.history.Refusal('unfinalized_packet_run_77')
    monkeypatch.setattr(tool.history,"scan",unknown)
    import pytest
    with pytest.raises(tool.history.Refusal,match='unfinalized'):
        tool.successful_packet_tags([(77,"b"*40)],b'key')


def test_main_absent_job_token_refuses_before_api(tmp_path, monkeypatch, capsys):
    root, predecessor_sha = packet(tmp_path)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(tool, "gh_api", lambda *_a, **_k: (_ for _ in ()).throw(
        AssertionError("API reached")
    ))
    rc = tool.main([
        "--trusted-public-key", str(root / "trusted_wea_public.pem"),
        "--issuance", str(root), "--run-id", "77",
        "--workflow-ref", "refs/tags/rea-wea-generation-5-fixture",
        "--workflow-sha", "a" * 40,
        "--genesis-predecessor-wea-sha256", predecessor_sha,
    ])
    assert rc == 3
    assert "PUBLIC_PUBLISH_INPUT_REFUSED" in capsys.readouterr().err


def test_actual_publisher_child_carries_only_scoped_github_identity(monkeypatch):
    for name in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','REA_APP_PRIVATE_KEY_B64','REA_APP_ID','SSH_AUTH_SOCK','GITHUB_TOKEN'):
        monkeypatch.setenv(name,'fixture-unrelated-custody')
    monkeypatch.setenv('GH_TOKEN','fixture-scoped-token')
    calls=[]
    def child(argv,**kwargs):
        calls.append((argv,kwargs))
        return SimpleNamespace(returncode=0,stdout='{"sha":"fixture"}',stderr='')
    monkeypatch.setattr(tool.subprocess,'run',child)
    tool.gh_api('repos/'+tool.REPOSITORY+'/git/refs',method='POST',body={'ref':'fixture'})
    _,kwargs=calls[0]
    assert kwargs.get('timeout') is None
    assert kwargs['env']['GH_TOKEN']=='fixture-scoped-token'
    assert not any(name in kwargs['env'] for name in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','REA_APP_PRIVATE_KEY_B64','REA_APP_ID','SSH_AUTH_SOCK','GITHUB_TOKEN'))
