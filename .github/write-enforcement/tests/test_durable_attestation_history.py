"""Actual signer/reader transitions with deterministic synthetic public packets."""
import base64
import copy
import importlib.util
from pathlib import Path
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

spec=importlib.util.spec_from_file_location('history',Path(__file__).resolve().parents[1]/'durable_attestation_history.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)

class Memory:
    def __init__(self):
        self.packet_refs={}; self.history_refs={}; self.contents={};self.runs={}
        self.calls=[]; self.kill=None;self.member_cache={}
    def refs(self,prefix):
        return copy.deepcopy(self.packet_refs if prefix==h.PACKET_PREFIX else self.history_refs)
    def content(self,commit,path):
        self.calls.append(('content',commit,path));return self.contents[commit,path]
    def api(self,path):
        self.calls.append(('api',path))
        assert '/artifacts' not in path and not path.startswith('check')
        return self.runs[int(path.split('/')[-1])]
    def publish(self,run,raw,parent):
        if self.kill==run:
            self.kill=None;raise RuntimeError('planted interrupted finalizer')
        commit=('%040x'% (run+1000));self.history_refs[run]={'commit':commit,'tag':h.HISTORY_PREFIX+str(run),'tag_object':'e'*40}
        self.contents[commit,h.CERT_PATH]=raw


def signed(payload,key):
    dg=h.digest(h.canonical(payload))
    return {'payload':payload,'signature':{'algorithm':'ed25519','signed_digest':dg,'value':base64.b64encode(key.sign(bytes.fromhex(dg))).decode()}}

def wea(key,public,epoch,pred,manifest='b'*64):
    p={k:'c'*64 for k in h.LIVE_FIELDS-{'signature'}}
    p.update(schema_version='rea.write.wea.live.v2',purpose='LIVE_ENFORCEMENT',state='ENFORCING',authority_epoch=epoch,
             issuer=h.ISSUER,predecessor_wea_digest=pred,enforcement_bundle_manifest_digest=manifest,
             trusted_key_id='rea-wea-ed25519-'+h.digest(public)[:16],claim_policy_digest=h.digest(b'policy'))
    issued=h.datetime(2020,1,1,tzinfo=h.timezone.utc)+h.timedelta(hours=epoch)
    p.update(issued_at=issued.strftime('%Y-%m-%dT%H:%M:%SZ'),not_before=issued.strftime('%Y-%m-%dT%H:%M:%SZ'),expires_at=(issued+h.timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ'))
    env=signed(p,key);return h.canonical(dict(p,signature=env['signature']))+b'\n'


def add(api,key,public,run,predecessor,conclusion='success'):
    epoch=h.object_value(predecessor)['authority_epoch']+1
    commit='%040x'%run;ref='refs/tags/rea-wea-generation-5-123456abcdef';workflow=b'fixture workflow'
    files={'claim_policy.json':b'policy','claim_registry.json':b'registry','hybrid_capability_provider':b'provider','runtime_mount.py':b'runtime','trusted_wea_public.pem':public,'predecessor_write_enforcement_attestation.json':predecessor}
    mapping={'claim-policy':'claim_policy.json','claim-registry':'claim_registry.json','hybrid-capability-provider':'hybrid_capability_provider','route-runtime-mount':'runtime_mount.py','trusted-public-key':'trusted_wea_public.pem'}
    members=[{'member_id':m,'repository':'govML','commit':'d'*40,'path':n,'sha256':h.digest(files[n]),'byte_length':len(files[n])} for m,n in mapping.items()]
    members.append({'member_id':'remote-issuer-workflow','repository':'rexcoleman.dev','commit':commit,'path':'.github/workflows/issue-write-enforcement-attestation.yml','sha256':h.digest(workflow),'byte_length':len(workflow)})
    manifest={'schema_version':'rea.write.enforcement-bundle-manifest.v1','authority_generation':5,'members':members}
    manifest['manifest_digest']=h.digest(h.canonical(manifest))
    files['enforcement_bundle_manifest.json']=h.canonical(manifest)
    files['write_enforcement_attestation.json']=wea(key,public,epoch,h.digest(predecessor),manifest['manifest_digest'])
    receipt={'schema_version':'rea.write.remote-issuance-receipt.v1','workflow_run_id':run,'workflow_run_attempt':1,'workflow_repository':h.REPOSITORY,'issuer':h.ISSUER,'event':'workflow_dispatch','wea_sha256':h.digest(files['write_enforcement_attestation.json']),'manifest_sha256':manifest['manifest_digest'],'workflow_ref':ref,'workflow_sha':commit,'workflow_blob_sha256':h.digest(workflow)}
    files['issuance_receipt.json']=h.canonical(receipt)
    hybrid={'schema_version':'rea.write.hybrid-capability-authority.v1','purpose':'VERIFY_ONLY_CURRENT_REGISTRY','issuer':h.ISSUER,'authority_epoch':epoch,'wea_sha256':receipt['wea_sha256'],'enforcement_bundle_manifest_digest':manifest['manifest_digest'],'claim_registry_sha256':h.digest(files['claim_registry.json']),'claim_policy_sha256':h.digest(files['claim_policy.json']),'provider_sha256':h.digest(files['hybrid_capability_provider']),'runtime_mount_sha256':h.digest(files['runtime_mount.py'])}
    files['hybrid_capability_authority.json']=h.canonical(signed(hybrid,key))
    files['SHA256SUMS']=''.join(h.digest(v)+'  '+n+'\n' for n,v in sorted(files.items())).encode()
    packetpath='rea-write-enforcement-packets/packets/'+str(run)
    pointer={'schema_version':'rea.write.public-attestation-pointer.v1','repository':h.REPOSITORY,'workflow_run_id':run,'packet_tag':h.PACKET_PREFIX+str(run),'packet_path':packetpath,'workflow_ref':ref,'workflow_sha':commit,'files':{n:h.digest(v) for n,v in files.items()}}
    api.packet_refs[run]={'tag':pointer['packet_tag'],'commit':commit,'tag_object':'a'*40}
    api.contents[commit,h.POINTER]=h.canonical(pointer)
    api.contents[commit,members[-1]['path']]=workflow
    api.contents.update({(commit,packetpath+'/'+n):v for n,v in files.items()})
    api.runs[run]={'id':run,'event':'workflow_dispatch','name':'Issue write enforcement attestation','path':members[-1]['path'],'head_sha':commit,'head_branch':ref[len('refs/tags/'):],'run_attempt':1,'status':'completed','conclusion':conclusion}
    return files['write_enforcement_attestation.json']

@pytest.fixture
def fixture():
    key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    api=Memory();pred=wea(key,public,5,'0'*64)
    add(api,key,public,10,pred,'failure')
    first=add(api,key,public,11,pred);add(api,key,public,12,first)
    return api,key,public


def test_backfill_failed_then_success_and_survive_all_retention(fixture):
    api,key,public=fixture
    rows=h.scan(api,public,key)
    assert [r['record']['conclusion'] for r in rows]==['failure','success','success']
    frozen=copy.deepcopy(api.contents)
    api.runs.clear();api.calls.clear();result,files=h.resolve(api,public)
    assert result['run_id']==12 and result['epoch']==7 and len(files)==11
    assert not any(c[0]=='api' for c in api.calls)
    h.scan(api,public,key)
    assert api.contents==frozen


def test_unknown_tail_never_falls_back(fixture):
    api,key,public=fixture;last=api.packet_refs.pop(12);h.scan(api,public,key);api.packet_refs[12]=last
    with pytest.raises(h.Refusal,match='unfinalized_packet_run_12'):h.resolve(api,public)

@pytest.mark.parametrize('field,value',[('status','in_progress'),('conclusion',None),('head_sha','b'*40),('run_attempt',2),('name','Seal only'),('event','schedule')])
def test_unverifiable_run_never_certifies(fixture,field,value):
    api,key,public=fixture;api.runs[10][field]=value
    with pytest.raises(h.Refusal,match='completed_run_identity'):h.scan(api,public,key)
    assert not api.history_refs


def test_missing_run_metadata_refuses_backfill(fixture):
    api,key,public=fixture;api.runs.clear()
    with pytest.raises(KeyError):h.scan(api,public,key)
    assert not api.history_refs


def test_wrong_root_and_forged_disposition(fixture):
    api,key,public=fixture;h.scan(api,public,key)
    with pytest.raises(h.Refusal):h.resolve(api,Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    path=(api.history_refs[10]['commit'],h.CERT_PATH);cert=h.object_value(api.contents[path]);cert['payload']['conclusion']='success';api.contents[path]=h.canonical(cert)
    with pytest.raises(h.Refusal,match='signature'):h.resolve(api,public)


def test_interrupted_finalization_resumes_exact_prefix(fixture):
    api,key,public=fixture;api.kill=11
    with pytest.raises(RuntimeError):h.scan(api,public,key)
    first=api.contents[api.history_refs[10]['commit'],h.CERT_PATH]
    with pytest.raises(h.Refusal,match='unfinalized'):h.resolve(api,public)
    h.scan(api,public,key)
    assert first==api.contents[api.history_refs[10]['commit'],h.CERT_PATH]
    assert h.resolve(api,public)[0]['run_id']==12


def test_replayed_certificate_refuses(fixture):
    api,key,public=fixture;h.scan(api,public,key)
    api.contents[api.history_refs[12]['commit'],h.CERT_PATH]=api.contents[api.history_refs[11]['commit'],h.CERT_PATH]
    with pytest.raises(h.Refusal,match='record_binding'):h.resolve(api,public)


def test_packet_member_corruption_refuses_before_signing(fixture):
    api,key,public=fixture
    path=(api.packet_refs[10]['commit'],'rea-write-enforcement-packets/packets/10/runtime_mount.py')
    api.contents[path]+=b'forged'
    with pytest.raises(h.Refusal,match='packet_member_digest'):h.scan(api,public,key)
    assert not api.history_refs


def test_git_object_publication_atomic_and_idempotent(tmp_path,monkeypatch):
    import subprocess
    klass=h.GitObjects
    remote=tmp_path/'remote.git';local=tmp_path/'local.git';reader=tmp_path/'reader.git'
    for path in (remote,local,reader):
        subprocess.run(['git','init','--bare',str(path)],check=True,capture_output=True)
    store=klass(local);observed=klass(reader)
    for obj in (store,observed):obj.git(['remote','add','origin',str(remote)])
    tree=store.git(['mktree'],b'').strip().decode()
    parent=store.git(['commit-tree',tree],b'fixture parent\n').strip().decode()
    first=b'fixture certificate one\n';second=b'fixture certificate two\n'
    store.publish(1,first,parent);store.publish(2,second,parent)
    # Reader is constructed after remote publication by production flush().
    def fresh():
        observed.refresh();return observed
    monkeypatch.setattr(h,'GitObjects',fresh)
    monkeypatch.setenv('GH_TOKEN','fixture-token-not-a-credential')
    store.flush()
    refs=observed.refs(h.HISTORY_PREFIX)
    assert set(refs)=={1,2}
    assert observed.content(refs[1]['commit'],h.CERT_PATH)==first
    before=store.refs(h.HISTORY_PREFIX)
    store.publish(1,first,parent);store.flush()
    assert store.refs(h.HISTORY_PREFIX)==before
    with pytest.raises(h.Refusal,match='history_conflict'):store.publish(1,b'changed',parent)


def test_git_failed_push_does_not_self_certify_local_refs(tmp_path,monkeypatch):
    import subprocess
    klass=h.GitObjects
    paths=[tmp_path/n for n in ('remote.git','local.git','reader.git')]
    for path in paths:subprocess.run(['git','init','--bare',str(path)],check=True,capture_output=True)
    store=klass(paths[1]);reader=klass(paths[2]);store.git(['remote','add','origin',str(paths[0])])
    tree=store.git(['mktree'],b'').strip().decode();parent=store.git(['commit-tree',tree],b'fixture\n').strip().decode()
    store.publish(1,b'certificate',parent)
    monkeypatch.setattr(h,'GitObjects',lambda:reader)
    monkeypatch.delenv('GH_TOKEN',raising=False)
    with pytest.raises(h.Refusal,match='publication_poststate'):store.flush()
    assert reader.refs(h.HISTORY_PREFIX)=={}


@pytest.mark.parametrize('route', ['public_git', 'push_git', 'metadata_api', 'scheduler'])
def test_actual_transport_children_exclude_unrelated_custody(tmp_path, monkeypatch, route):
    import subprocess
    import renewal_history_scheduler as scheduler
    unrelated = ('ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GEMINI_API_KEY',
                 'GOVML_REA_READ_APP_PRIVATE_KEY_B64', 'GOVML_REA_READ_APP_ID',
                 'WEA_KEY_B64', 'SSH_AUTH_SOCK', 'GIT_SSH_COMMAND', 'GIT_DIR',
                 'GIT_WORK_TREE', 'GIT_CONFIG_VALUE_9', 'GITHUB_TOKEN')
    for name in unrelated:
        monkeypatch.setenv(name, 'fixture-unrelated')
    monkeypatch.setenv('GH_TOKEN', 'fixture-scoped-token')
    monkeypatch.setenv('GIT_CONFIG_COUNT', '10')
    calls = []
    def child(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0,
            stdout='{}' if kwargs.get('text') else b'{}', stderr=b'')
    monkeypatch.setattr(subprocess, 'run', child)
    if route in ('public_git', 'push_git'):
        h.GitObjects(tmp_path).git(['fixture'], push=route == 'push_git')
    elif route == 'metadata_api':
        h.GitHub().api('fixture')
    else:
        monkeypatch.setattr(scheduler, 'history', h)
        scheduler.command(['gh', 'run', 'list'])
    argv, kwargs = calls[0]
    env = kwargs['env']
    assert all(name not in env for name in unrelated)
    assert 'fixture-scoped-token' not in ' '.join(argv)
    if route == 'push_git':
        assert 'GH_TOKEN' not in env and kwargs['timeout'] is None
        assert env['GIT_CONFIG_COUNT'] == '3'
        assert env['GIT_CONFIG_VALUE_2'] == 'AUTHORIZATION: basic ' + base64.b64encode(
            b'x-access-token:fixture-scoped-token').decode()
    elif route == 'public_git':
        assert 'GH_TOKEN' not in env and env['GIT_CONFIG_COUNT'] == '2'
    else:
        assert env['GH_TOKEN'] == 'fixture-scoped-token'


def test_124_row_backfill_metadata_request_budget_and_retention_free_warm_read():
    import time
    key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    api=Memory();pred=wea(key,public,21,'0'*64)
    add(api,key,public,100,pred,'failure')
    for run in range(101,224):pred=add(api,key,public,run,pred)
    start=time.monotonic();rows=h.scan(api,public,key);cold=time.monotonic()-start
    metadata=[c for c in api.calls if c[0]=='api']
    assert len(rows)==124 and len(metadata)==124
    api.runs.clear();api.calls.clear();start=time.monotonic();result,_=h.resolve(api,public);warm=time.monotonic()-start
    assert result['history_rows']==124 and result['run_id']==223
    assert not [c for c in api.calls if c[0]=='api']
    print('124_ROW_COUNTS metadata_get_cold=124 metadata_get_warm=0 artifacts_get=0 checks_get=0 statuses_get=0 cold_fixture_seconds=%.6f warm_fixture_seconds=%.6f'%(cold,warm))


def test_124_packet_actual_git_transport_roundtrip(tmp_path,monkeypatch):
    """Actual objects/tags, metadata backfill, atomic push, fresh independent read."""
    import subprocess
    import time
    klass=h.GitObjects
    remote=tmp_path/'remote.git';writer=tmp_path/'writer.git';readerpath=tmp_path/'reader.git'
    for path in (remote,writer,readerpath):subprocess.run(['git','init','--bare',str(path)],check=True,capture_output=True)
    store=klass(writer);store.git(['remote','add','origin',str(remote)])
    public_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public=public_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    blobs={}
    def git_tree(files):
        tree={}
        for path,raw in files.items():
            if raw not in blobs:blobs[raw]=store.git(['hash-object','-w','--stdin'],raw).strip().decode()
            parts=path.split('/');node=tree
            for part in parts[:-1]:node=node.setdefault(part,{})
            node[parts[-1]]=blobs[raw]
        def emit(node):
            lines=[]
            for name,value in sorted(node.items()):
                lines.append(('040000 tree '+emit(value) if isinstance(value,dict) else '100644 blob '+value)+'\t'+name+'\n')
            return store.git(['mktree'],''.join(lines).encode()).strip().decode()
        return emit(tree)
    workflowpath='.github/workflows/issue-write-enforcement-attestation.yml'
    workflow=b'fixture workflow';base=store.git(['commit-tree',git_tree({workflowpath:workflow})],b'fixture source\n').strip().decode()
    memory=Memory();pred=wea(public_key,public,21,'0'*64)
    for run in range(100,224):
        current=add(memory,public_key,public,run,pred,'failure' if run==100 else 'success')
        if run!=100:pred=current
        fake='%040x'%run;prefix='rea-write-enforcement-packets/packets/'+str(run)
        files={name:memory.contents[fake,prefix+'/'+name] for name in h.FILES}
        receipt=h.object_value(files['issuance_receipt.json']);receipt['workflow_sha']=base;files['issuance_receipt.json']=h.canonical(receipt)
        files['SHA256SUMS']=''.join(h.digest(v)+'  '+n+'\n' for n,v in sorted(files.items()) if n!='SHA256SUMS').encode()
        pointer=h.object_value(memory.contents[fake,h.POINTER]);pointer['workflow_sha']=base;pointer['files']={n:h.digest(v) for n,v in files.items()}
        tree=git_tree(dict({prefix+'/'+n:v for n,v in files.items()},**{h.POINTER:h.canonical(pointer),workflowpath:workflow}))
        commit=store.git(['commit-tree',tree,'-p',base],('fixture packet '+str(run)+'\n').encode()).strip().decode()
        store.git(['tag','-a',h.PACKET_PREFIX+str(run),commit,'-m','fixture packet'])
        memory.runs[run]['head_sha']=base
    store.git(['push','origin','--tags'])
    metadata=[]
    def metadata_api(path,*args,**kwargs):
        assert path.startswith('actions/runs/') and '/artifacts' not in path
        metadata.append(path);return memory.runs[int(path.split('/')[-1])]
    store.api=metadata_api
    def fresh():
        obj=klass(readerpath)
        if not (readerpath/'config').read_text().find('[remote "origin"]')>=0:obj.git(['remote','add','origin',str(remote)])
        obj.refresh();return obj
    monkeypatch.setattr(h,'GitObjects',fresh);monkeypatch.setenv('GH_TOKEN','fixture-token-not-a-credential')
    start=time.monotonic();h.scan(store,public,public_key);store.flush();cold=time.monotonic()-start
    assert len(metadata)==124
    reader=fresh();reader.api=lambda *a,**k: (_ for _ in ()).throw(AssertionError('retained API reached'))
    start=time.monotonic();result,_=h.resolve(reader,public);warm=time.monotonic()-start
    assert result['run_id']==223 and result['history_rows']==124
    assert len(reader.refs(h.HISTORY_PREFIX))==124
    print('124_REAL_GIT metadata_get_cold=124 metadata_get_warm=0 certificate_atomic_pushes=1 cold_local_seconds=%.6f warm_local_seconds=%.6f'%(cold,warm))


@pytest.mark.parametrize('plant',['missing','changed'])
def test_repeated_digest_does_not_hide_broken_later_packet_path(fixture,plant):
    api,key,public=fixture
    target=(api.packet_refs[12]['commit'],'rea-write-enforcement-packets/packets/12/claim_policy.json')
    if plant=='missing':del api.contents[target]
    else:api.contents[target]=b'changed despite repeated prior digest'
    with pytest.raises((h.Refusal,KeyError)):
        h.scan(api,public,key)


@pytest.mark.parametrize('ref',['refs/tags/rea-wea-generation-packet-123','refs/tags/rea-wea-generation-history-123','refs/tags/rea-wea-generation-5-bad','refs/heads/main'])
def test_finalizer_refuses_wrong_tag_class_before_network_or_private_read(tmp_path,monkeypatch,fixture,ref):
    api,key,public=fixture
    path=tmp_path/'public.pem';path.write_bytes(public)
    monkeypatch.setenv('GITHUB_ACTIONS','true');monkeypatch.setenv('GITHUB_REPOSITORY',h.REPOSITORY)
    monkeypatch.setenv('GITHUB_EVENT_NAME','workflow_dispatch');monkeypatch.setenv('GITHUB_REF',ref)
    monkeypatch.setattr(h,'GitObjects',lambda: (_ for _ in ()).throw(AssertionError('network reached')))
    assert h.main(['finalize','--trusted-public-key',str(path),'--private-key',str(tmp_path/'absent-private.pem')])==3


def test_finalizer_exact_generation_fixture_control(tmp_path,monkeypatch,fixture):
    api,key,public=fixture
    publicpath=tmp_path/'public.pem';publicpath.write_bytes(public)
    privatepath=tmp_path/'fixture-private.pem';privatepath.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    monkeypatch.setenv('GITHUB_ACTIONS','true');monkeypatch.setenv('GITHUB_REPOSITORY',h.REPOSITORY)
    monkeypatch.setenv('GITHUB_EVENT_NAME','workflow_dispatch');monkeypatch.setenv('GITHUB_REF','refs/tags/rea-wea-generation-5-123456abcdef')
    monkeypatch.setattr(h,'GitObjects',lambda:api);api.flush=lambda:None
    assert h.main(['finalize','--trusted-public-key',str(publicpath),'--private-key',str(privatepath)])==0
    assert len(api.history_refs)==3


def test_actual_historical_source_identities_are_exact_reader_only():
    import json
    rows=json.loads((Path(__file__).parent/'fixtures/legacy_packet_source_identities.json').read_text())
    for row in rows:
        receipt=row['receipt']
        assert h.packet_source_identity(receipt)
        assert h.GENERATION_REF.fullmatch(receipt['workflow_ref']) is None
        for field in ('workflow_run_id','workflow_ref','workflow_sha','workflow_blob_sha256'):
            planted=copy.deepcopy(receipt)
            planted[field]=planted[field]+1 if type(planted[field]) is int else planted[field][:-1]+('0' if planted[field][-1]!='0' else '1')
            assert not h.packet_source_identity(planted), field
