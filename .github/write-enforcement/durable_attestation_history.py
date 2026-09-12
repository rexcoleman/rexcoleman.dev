#!/usr/bin/env python3
"""Authenticated durable WEA history, independent of Actions retention.

Packets remain the existing eleven public files. A separate protected annotated
history tag carries a signed disposition of a COMPLETED prior issuer run. The
caller supplies the independently installed/source-pinned public key; a packet
never chooses its trust anchor. Only finalize reads recent Actions metadata or a
private signing key, and it must run in the existing protected issuer workflow.
Resolution needs only Contents read and authenticated durable certificates.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey

REPOSITORY = 'rexcoleman/rexcoleman.dev'
ISSUER = 'https://github.com/' + REPOSITORY + '/actions/workflows/issue-write-enforcement-attestation.yml'
PACKET_PREFIX = 'rea-wea-generation-packet-'
HISTORY_PREFIX = 'rea-wea-generation-history-'
POINTER = 'rea-write-enforcement-packets/latest.json'
CERT_PATH = 'rea-write-enforcement-history/record.json'
SCHEMA = 'rea.write.durable-success-history.v1'
FILES = frozenset({'SHA256SUMS','claim_policy.json','claim_registry.json',
    'enforcement_bundle_manifest.json','hybrid_capability_authority.json',
    'hybrid_capability_provider','issuance_receipt.json',
    'predecessor_write_enforcement_attestation.json','runtime_mount.py',
    'trusted_wea_public.pem','write_enforcement_attestation.json'})
FAILURES = frozenset({'action_required','cancelled','failure','skipped','stale','startup_failure','timed_out'})
HEX40 = re.compile(r'^[0-9a-f]{40}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
ZERO = '0' * 64
LIVE_FIELDS = frozenset({'schema_version','purpose','state','authority_epoch',
    'predecessor_wea_digest','issued_at','not_before','expires_at',
    'publishing_capability_scope','required_surfaces','enforcement_bundle_manifest_digest',
    'claim_policy_digest','coverage_registry_digest','coverage_registry_generation','issuer',
    'issuer_source_digest','renewal_policy_digest','issuance_receipt_digest','trusted_key_id','signature'})
GENERATION_REF = re.compile(r'^refs/tags/rea-wea-generation-[0-9]+-[0-9a-f]{12}$')
# Exact already-issued public identities, never permission to finalize on a
# short or approximate tag. These still undergo every signature/source check.
LEGACY_PACKET_IDENTITIES = {
    31662529486: ('refs/tags/rea-wea-generation-5-3dc657d323d', '3dc657d323d01d500bc8780793bb96deb16c54f4', 'c8e863ddadbe5baa47681b12b4d4699c4ad1f7586a614dec1a3ba89dabcae517'),
    31664577666: ('refs/tags/rea-wea-generation-5-cddbc791778', 'cddbc791778343d80d07364a1c18a9b6eeeff5ed', 'c8e863ddadbe5baa47681b12b4d4699c4ad1f7586a614dec1a3ba89dabcae517'),
    31666283250: ('refs/tags/rea-wea-generation-5-c3a5efb9f9b', 'c3a5efb9f9b9cf3a1d3747045547f4bbd19bafd3', 'c8e863ddadbe5baa47681b12b4d4699c4ad1f7586a614dec1a3ba89dabcae517'),
    31667567829: ('refs/tags/rea-wea-generation-5-6c1da59148a', '6c1da59148a22ee198e75fe79cd8009d13bafcda', 'c8e863ddadbe5baa47681b12b4d4699c4ad1f7586a614dec1a3ba89dabcae517'),
}

def packet_source_identity(receipt):
    if GENERATION_REF.fullmatch(str(receipt.get('workflow_ref'))):
        return True
    expected = LEGACY_PACKET_IDENTITIES.get(receipt.get('workflow_run_id'))
    return expected is not None and expected == tuple(receipt.get(k) for k in
        ('workflow_ref', 'workflow_sha', 'workflow_blob_sha256'))


class Refusal(RuntimeError):
    reason_code = 'DURABLE_SUCCESS_AUTHENTICATION_REFUSED'

def transport_environment(*, github=False):
    """Child runtime only; unrelated custody and ambient Git/SSH controls stop here."""
    env = {name: os.environ[name] for name in ('HOME', 'PATH', 'LANG', 'LC_ALL', 'TZ')
           if name in os.environ}
    env.setdefault('PATH', '/usr/local/bin:/usr/bin:/bin')
    if github and os.environ.get('GH_TOKEN'):
        env['GH_TOKEN'] = os.environ['GH_TOKEN']
    return env

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def object_value(raw):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise Refusal('malformed_json') from None
    if not isinstance(value, dict):
        raise Refusal('object_required')
    return value

def key_from(raw):
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError):
        raise Refusal('trusted_key_invalid') from None
    if not isinstance(key, Ed25519PublicKey):
        raise Refusal('trusted_key_not_ed25519')
    return key

def signature_check(payload, signature, key):
    if (not isinstance(signature, dict)
            or set(signature) != {'algorithm','signed_digest','value'}
            or signature.get('algorithm') != 'ed25519'
            or signature.get('signed_digest') != digest(canonical(payload))):
        raise Refusal('signature_shape_or_digest')
    try:
        sig = base64.b64decode(signature['value'], validate=True)
        if len(sig) != 64 or base64.b64encode(sig).decode() != signature['value']:
            raise ValueError('encoding')
        key.verify(sig, bytes.fromhex(signature['signed_digest']))
    except Exception:
        raise Refusal('signature_invalid') from None

def authenticate_wea(raw, key):
    value = object_value(raw)
    payload = {k:v for k,v in value.items() if k != 'signature'}
    signature_check(payload, value.get('signature'), key)
    if (set(value) != LIVE_FIELDS or value.get('schema_version') != 'rea.write.wea.live.v2'
            or value.get('purpose') != 'LIVE_ENFORCEMENT'
            or value.get('issuer') != ISSUER or value.get('state') != 'ENFORCING'
            or type(value.get('authority_epoch')) is not int or value['authority_epoch'] < 1
            or not HEX64.fullmatch(str(value.get('predecessor_wea_digest')))):
        raise Refusal('wea_identity')
    try:
        issued = datetime.strptime(value['issued_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        expires = datetime.strptime(value['expires_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if value['not_before'] != value['issued_at'] or expires-issued != timedelta(hours=24):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise Refusal('wea_lifetime_contract') from None
    return value

def publication_admission(kind, api=None):
    """Admit a write using actual Actions job age, never a client kill timer.

    These reserves are operational allowances, not network latency guarantees.
    The signed workflow at this run's exact commit supplies the outer deadline.
    Missing/ambiguous timing refuses before publication; remote reconciliation
    remains necessary even after admission (cancellation and crashes can occur).
    """
    expected = {'history': ({'history-finalize'}, 900),
                'packet': ({'issue-wea', 'renew-wea'}, 300)}
    if kind not in expected:
        raise Refusal('publication_budget_kind')
    jobs_allowed, reserve = expected[kind]
    job = os.environ.get('GITHUB_JOB', '')
    run = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    commit = os.environ.get('GITHUB_SHA', '')
    ref = os.environ.get('GITHUB_REF', '')
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY
            or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or job not in jobs_allowed or not re.fullmatch(r'[1-9][0-9]*', run)
            or not re.fullmatch(r'[1-9][0-9]*', attempt)
            or HEX40.fullmatch(commit) is None or GENERATION_REF.fullmatch(ref) is None):
        raise Refusal('publication_budget_hosted_identity')
    api = api or GitHub()
    metadata = api.api('actions/runs/' + run)
    if (not isinstance(metadata, dict) or type(metadata.get('id')) is not int
            or type(metadata.get('run_attempt')) is not int
            or metadata.get('id') != int(run) or metadata.get('run_attempt') != int(attempt)
            or metadata.get('head_sha') != commit or metadata.get('head_branch') != ref[len('refs/tags/'):]
            or metadata.get('event') != 'workflow_dispatch' or metadata.get('status') != 'in_progress'
            or 'conclusion' not in metadata or metadata['conclusion'] is not None
            or metadata.get('path') != '.github/workflows/issue-write-enforcement-attestation.yml'):
        raise Refusal('publication_budget_run_identity')
    # Read the declared timeout from the actual immutable workflow, not an
    # ambient timeout variable, a new process start time or a copied constant.
    workflow = api.content(commit, '.github/workflows/issue-write-enforcement-attestation.yml').decode('utf-8')
    sections = list(re.finditer(r'^  ([a-zA-Z0-9_-]+):\s*$', workflow, re.M))
    selected = [i for i, section in enumerate(sections) if section.group(1) == job]
    if len(selected) != 1:
        raise Refusal('publication_budget_workflow_job')
    i = selected[0]
    block = workflow[sections[i].end():sections[i+1].start() if i+1 < len(sections) else len(workflow)]
    limits = re.findall(r'^    timeout-minutes: ([1-9][0-9]*)\s*$', block, re.M)
    # Only literal unnamed jobs are supported by this registered workflow.
    if len(limits) != 1 or re.search(r'^    name:', block, re.M):
        raise Refusal('publication_budget_declared_timeout')
    total = int(limits[0]) * 60
    rows = []
    page = 1
    while True:
        result = api.api('actions/runs/%s/attempts/%s/jobs?per_page=100&page=%s' % (run, attempt, page))
        if not isinstance(result, dict):
            raise Refusal('publication_budget_jobs_shape')
        current = result.get('jobs')
        count = result.get('total_count')
        if (not isinstance(current, list) or not all(isinstance(row, dict) for row in current)
                or type(count) is not int or count < 1):
            raise Refusal('publication_budget_jobs_shape')
        rows.extend(current)
        if len(rows) == count:
            break
        if not current or len(rows) > count:
            raise Refusal('publication_budget_jobs_population')
        page += 1
    selected = [row for row in rows if row.get('name') == job]
    if len(selected) != 1:
        raise Refusal('publication_budget_job_ambiguous')
    current = selected[0]
    if (type(current.get('id')) is not int or current['id'] < 1
            or type(current.get('run_id')) is not int or current.get('run_id') != int(run)
            or current.get('head_sha') != commit or current.get('status') != 'in_progress'
            or 'conclusion' not in current or current['conclusion'] is not None
            or ('run_attempt' in current and (type(current['run_attempt']) is not int
                                             or current['run_attempt'] != int(attempt)))):
        raise Refusal('publication_budget_job_identity')
    try:
        started = datetime.strptime(current['started_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        raise Refusal('publication_budget_job_started_at') from None
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    remaining = total - elapsed
    if elapsed < 0 or remaining < reserve:
        raise Refusal('publication_budget_insufficient')
    result = {'status': 'PUBLICATION_BUDGET_ADMITTED', 'budget_kind': 'operational_reserve',
            'job': job, 'job_id': current['id'], 'run_id': int(run), 'attempt': int(attempt),
            'workflow_sha': commit,
            'declared_seconds': total, 'elapsed_seconds': elapsed,
            'remaining_seconds': remaining, 'reserve_seconds': reserve}
    print(json.dumps(result, sort_keys=True), file=sys.stderr)
    return result

class GitHub:
    """Exact repository API; no credential values in argv or diagnostics."""
    def __init__(self):
        self.immutable_cache = {}
        self.member_cache = {}

    def api(self, path, method='GET', body=None, missing=False):
        immutable = method == 'GET' and (path.startswith('git/tags/') or path.startswith('contents/'))
        if immutable and path in self.immutable_cache:
            return self.immutable_cache[path]
        argv = ['gh','api','repos/' + REPOSITORY + '/' + path]
        if method != 'GET':
            argv += ['--method',method,'--input','-']
        result = subprocess.run(argv, input=canonical(body) if body is not None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                                env=transport_environment(github=True))
        if result.returncode:
            if missing and b'HTTP 404' in result.stderr:
                return None
            raise Refusal('github_api_exit_' + str(result.returncode))
        try:
            value = json.loads(result.stdout)
            if immutable:
                self.immutable_cache[path] = value
            return value
        except ValueError:
            raise Refusal('github_api_json') from None

    def refs(self, prefix):
        rows = self.api('git/matching-refs/tags/' + prefix)
        if not isinstance(rows, list):
            raise Refusal('refs_shape')
        out = {}
        for row in rows:
            name = row.get('ref','') if isinstance(row,dict) else ''
            suffix = name[len('refs/tags/' + prefix):] if name.startswith('refs/tags/' + prefix) else ''
            if not suffix.isdigit() or int(suffix) < 1 or name != 'refs/tags/' + prefix + suffix:
                raise Refusal('ref_name')
            oid = row.get('object',{})
            if oid.get('type') != 'tag' or not HEX40.fullmatch(str(oid.get('sha'))):
                raise Refusal('annotated_tag_required')
            tag = self.api('git/tags/' + oid['sha'])
            target = tag.get('object',{})
            if (tag.get('tag') != prefix + suffix or target.get('type') != 'commit'
                    or not HEX40.fullmatch(str(target.get('sha')))):
                raise Refusal('tag_target')
            run = int(suffix)
            if run in out:
                raise Refusal('duplicate_run')
            out[run] = {'tag':prefix + suffix,'tag_object':oid['sha'],'commit':target['sha']}
        return out

    def content(self, commit, path):
        if not HEX40.fullmatch(commit) or path.startswith('/') or '..' in Path(path).parts:
            raise Refusal('content_path')
        value = self.api('contents/' + path + '?ref=' + commit)
        if (not isinstance(value,dict) or value.get('type') != 'file'
                or value.get('path') != path or value.get('encoding') != 'base64'):
            raise Refusal('content_shape')
        try:
            raw = base64.b64decode(''.join(value['content'].split()), validate=True)
        except (KeyError,TypeError,ValueError):
            raise Refusal('content_encoding') from None
        return raw

    def publish(self, run_id, raw, parent):
        """Create immutable record; rerun verifies equality rather than overwriting."""
        refs = self.refs(HISTORY_PREFIX)
        if run_id in refs:
            if self.content(refs[run_id]['commit'], CERT_PATH) != raw:
                raise Refusal('history_conflict')
            return refs[run_id]
        blob = self.api('git/blobs','POST',{'content':base64.b64encode(raw).decode(),'encoding':'base64'})
        tree = self.api('git/trees','POST',{'tree':[{'path':CERT_PATH,'mode':'100644','type':'blob','sha':blob['sha']}]})
        commit = self.api('git/commits','POST',{'message':'Durable WEA run disposition ' + str(run_id),
                                              'tree':tree['sha'],'parents':[parent]})
        tag_name = HISTORY_PREFIX + str(run_id)
        tag = self.api('git/tags','POST',{'tag':tag_name,'message':tag_name,'object':commit['sha'],'type':'commit'})
        try:
            self.api('git/refs','POST',{'ref':'refs/tags/' + tag_name,'sha':tag['sha']})
        except Refusal:
            # A concurrent idempotent writer or interrupted response is settled
            # by exact bytes. Conflicting immutable state never gets rewritten.
            observed = self.refs(HISTORY_PREFIX).get(run_id)
            if observed is None or self.content(observed['commit'], CERT_PATH) != raw:
                raise
        observed = self.refs(HISTORY_PREFIX).get(run_id)
        if observed is None or self.content(observed['commit'], CERT_PATH) != raw:
            raise Refusal('history_publication_poststate')
        return observed

class GitObjects(GitHub):
    """One public Git fetch, local immutable reads, one atomic certificate push.

    Only finalization calls Actions metadata. The protected GITHUB_TOKEN reaches
    git via child-only environment configuration, never command arguments. The
    temporary object store has no executable checkout, credential helper or hooks.
    """
    def __init__(self, repository=None):
        super().__init__()
        import tempfile
        self.temporary = tempfile.TemporaryDirectory(prefix='wea-history-') if repository is None else None
        self.repository = Path(self.temporary.name) if self.temporary else Path(repository)
        self.pending = []
        if self.temporary:
            self.git(['init','--bare',str(self.repository)],outside=True)
            self.git(['remote','add','origin','https://github.com/'+REPOSITORY+'.git'])
            self.refresh()

    def git(self,argv,raw=None,*,outside=False,push=False):
        env=transport_environment()
        # No ambient agent/key/credential helper is needed for public reads.
        env.update(GIT_TERMINAL_PROMPT='0',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',
                   GIT_AUTHOR_NAME='WEA durable history',GIT_AUTHOR_EMAIL='wea-history@users.noreply.github.com',
                   GIT_COMMITTER_NAME='WEA durable history',GIT_COMMITTER_EMAIL='wea-history@users.noreply.github.com')
        env['GIT_CONFIG_COUNT']='2'
        env['GIT_CONFIG_KEY_0']='credential.helper';env['GIT_CONFIG_VALUE_0']=''
        env['GIT_CONFIG_KEY_1']='core.hooksPath';env['GIT_CONFIG_VALUE_1']='/dev/null'
        if push:
            token=os.environ.get('GH_TOKEN','')
            if not token:
                raise Refusal('history_push_token_unavailable')
            env['GIT_CONFIG_COUNT']='3'
            env['GIT_CONFIG_KEY_2']='http.https://github.com/.extraheader'
            env['GIT_CONFIG_VALUE_2']='AUTHORIZATION: basic '+base64.b64encode(('x-access-token:'+token).encode()).decode()
        argv=['git']+([] if outside else ['--git-dir',str(self.repository)])+argv
        cp=subprocess.run(argv,input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=None if push else 900)
        if cp.returncode:
            raise Refusal('history_git_exit_'+str(cp.returncode))
        return cp.stdout

    def refresh(self):
        self.git(['fetch','--no-tags','origin',
                  '+refs/tags/'+PACKET_PREFIX+'*:refs/tags/'+PACKET_PREFIX+'*',
                  '+refs/tags/'+HISTORY_PREFIX+'*:refs/tags/'+HISTORY_PREFIX+'*'])

    def verify_population(self, packets):
        remote=self.git(['ls-remote','--refs','origin','refs/tags/'+PACKET_PREFIX+'*']).decode('ascii').splitlines()
        observed={}
        for line in remote:
            oid,ref=line.split('\t')
            observed[ref]=oid
        expected={'refs/tags/'+row['tag']:row['tag_object'] for row in packets.values()}
        if observed!=expected:
            raise Refusal('packet_history_changed_during_resolution')

    def refs(self,prefix):
        rows=self.git(['for-each-ref','--format=%(refname) %(objecttype) %(objectname) %(*objectname)',
                       'refs/tags/'+prefix+'*']).decode('ascii').splitlines()
        out={}
        for line in rows:
            fields=line.split()
            if len(fields)!=4 or fields[1]!='tag':
                raise Refusal('annotated_tag_required')
            name,_,oid,commit=fields
            suffix=name[len('refs/tags/'+prefix):]
            if not suffix.isdigit() or int(suffix)<1 or str(int(suffix))!=suffix:
                raise Refusal('ref_name')
            tag=self.git(['cat-file','tag',oid]).split(b'\n\n',1)[0].decode('utf-8').splitlines()
            if tag[:3]!=['object '+commit,'type commit','tag '+prefix+suffix]:
                raise Refusal('tag_target')
            out[int(suffix)]={'tag':prefix+suffix,'tag_object':oid,'commit':commit}
        return out

    def content(self,commit,path):
        if not HEX40.fullmatch(commit) or not path or Path(path).is_absolute() or '..' in Path(path).parts:
            raise Refusal('content_path')
        key=(commit,path)
        if key not in self.immutable_cache:
            row=self.git(['ls-tree',commit,'--',path]).decode().strip().split(None,3)
            if len(row)!=4 or row[0] not in {'100644','100755'} or row[1]!='blob' or row[3]!=path:
                raise Refusal('content_shape')
            blob_key=('blob',row[2])
            if blob_key not in self.immutable_cache:
                self.immutable_cache[blob_key]=self.git(['cat-file','blob',row[2]])
            self.immutable_cache[key]=self.immutable_cache[blob_key]
        return self.immutable_cache[key]

    def publish(self,run_id,raw,parent):
        existing=self.refs(HISTORY_PREFIX).get(run_id)
        if existing is not None:
            if self.content(existing['commit'],CERT_PATH)!=raw:
                raise Refusal('history_conflict')
            return existing
        blob=self.git(['hash-object','-w','--stdin'],raw).strip().decode('ascii')
        subtree=self.git(['mktree'],('100644 blob '+blob+'\trecord.json\n').encode()).strip().decode('ascii')
        tree=self.git(['mktree'],('040000 tree '+subtree+'\trea-write-enforcement-history\n').encode()).strip().decode('ascii')
        commit=self.git(['commit-tree',tree,'-p',parent],('Durable WEA run disposition '+str(run_id)+'\n').encode()).strip().decode('ascii')
        tag=HISTORY_PREFIX+str(run_id)
        self.git(['tag','-a',tag,commit,'-m',tag])
        self.pending.append((run_id,raw))
        return self.refs(HISTORY_PREFIX)[run_id]

    def flush(self):
        if not self.pending:
            return
        pending=list(self.pending)
        publication_admission('history')
        # No force and all-or-nothing publication: no half-created remote chain.
        try:
            self.git(['push','--atomic','origin']+['refs/tags/'+HISTORY_PREFIX+str(run) for run,_ in pending],push=True)
        except Refusal:
            # A lost response or concurrent identical signer is resolved from
            # remote bytes. A partial/conflicting poststate remains a refusal.
            pass
        # Fresh store prevents local unpushed refs from proving their own write.
        observed=GitObjects()
        refs=observed.refs(HISTORY_PREFIX)
        for run,raw in pending:
            if run not in refs or observed.content(refs[run]['commit'],CERT_PATH)!=raw:
                raise Refusal('history_publication_poststate')
        self.pending=[]


def packet(api, run_id, ref, trusted_key):
    pointer_raw = api.content(ref['commit'], POINTER)
    pointer = object_value(pointer_raw)
    path = 'rea-write-enforcement-packets/packets/' + str(run_id)
    files = pointer.get('files')
    if (pointer.get('schema_version') != 'rea.write.public-attestation-pointer.v1'
            or pointer.get('repository') != REPOSITORY
            or type(pointer.get('workflow_run_id')) is not int
            or pointer.get('workflow_run_id') != run_id or pointer.get('packet_tag') != ref['tag']
            or pointer.get('packet_path') != path or not isinstance(files,dict)
            or set(files) != FILES or any(not HEX64.fullmatch(str(v)) for v in files.values())):
        raise Refusal('packet_pointer')
    # Every commit/path is checked even when another packet claimed identical
    # bytes. Transport may deduplicate immutable blobs only AFTER path identity.
    raw = {name: api.content(ref['commit'], path + '/' + name) for name in sorted(FILES)}
    if any(digest(raw[name]) != files[name] for name in FILES):
        raise Refusal('packet_member_digest')
    if raw['trusted_wea_public.pem'] != trusted_key:
        raise Refusal('packet_chose_wrong_key')
    key = key_from(trusted_key)
    wea = authenticate_wea(raw['write_enforcement_attestation.json'],key)
    predecessor = authenticate_wea(raw['predecessor_write_enforcement_attestation.json'],key)
    if (wea['predecessor_wea_digest'] != digest(raw['predecessor_write_enforcement_attestation.json'])
            or wea['authority_epoch'] != predecessor['authority_epoch'] + 1
            or wea['issued_at'] <= predecessor['issued_at']):
        raise Refusal('packet_predecessor')
    manifest = object_value(raw['enforcement_bundle_manifest.json'])
    if (manifest.get('manifest_digest') != digest(canonical({k:v for k,v in manifest.items() if k!='manifest_digest'}))
            or wea.get('enforcement_bundle_manifest_digest') != manifest['manifest_digest']):
        raise Refusal('packet_manifest')
    receipt = object_value(raw['issuance_receipt.json'])
    if (type(receipt.get('workflow_run_id')) is not int or receipt.get('workflow_run_id') != run_id or receipt.get('workflow_repository') != REPOSITORY
            or receipt.get('issuer') != ISSUER or receipt.get('event') != 'workflow_dispatch'
            or receipt.get('wea_sha256') != digest(raw['write_enforcement_attestation.json'])
            or receipt.get('manifest_sha256') != manifest['manifest_digest']
            or receipt.get('workflow_ref') != pointer.get('workflow_ref')
            or receipt.get('workflow_sha') != pointer.get('workflow_sha')
            or type(receipt.get('workflow_run_attempt')) is not int or receipt['workflow_run_attempt'] < 1):
        raise Refusal('packet_receipt')
    if (not packet_source_identity(receipt)
            or not HEX40.fullmatch(str(receipt.get('workflow_sha')))
            or not HEX64.fullmatch(str(receipt.get('workflow_blob_sha256')))
            or wea.get('trusted_key_id') != 'rea-wea-ed25519-'+digest(trusted_key)[:16]
            or wea.get('claim_policy_digest') != digest(raw['claim_policy.json'])):
        raise Refusal('packet_source_identity')
    members = manifest.get('members')
    if not isinstance(members,list) or not members:
        raise Refusal('manifest_members')
    by_id = {}
    for row in members:
        if (not isinstance(row,dict) or set(row)!={'member_id','repository','commit','path','sha256','byte_length'}
                or not isinstance(row['member_id'],str) or row['member_id'] in by_id
                or not HEX40.fullmatch(str(row['commit'])) or not HEX64.fullmatch(str(row['sha256']))
                or type(row['byte_length']) is not int or row['byte_length']<0
                or not isinstance(row['path'],str) or Path(row['path']).is_absolute()
                or '..' in Path(row['path']).parts):
            raise Refusal('manifest_member_shape')
        by_id[row['member_id']]=row
    for member,name in {'claim-policy':'claim_policy.json','claim-registry':'claim_registry.json',
            'hybrid-capability-provider':'hybrid_capability_provider','route-runtime-mount':'runtime_mount.py',
            'trusted-public-key':'trusted_wea_public.pem'}.items():
        if (member not in by_id or by_id[member]['sha256']!=digest(raw[name])
                or by_id[member]['byte_length']!=len(raw[name])):
            raise Refusal('manifest_packet_member_binding')
    workflow=by_id.get('remote-issuer-workflow',{})
    if (workflow.get('repository')!='rexcoleman.dev'
            or workflow.get('path')!='.github/workflows/issue-write-enforcement-attestation.yml'
            or workflow.get('sha256')!=receipt['workflow_blob_sha256']):
        raise Refusal('manifest_workflow_binding')
    workflow_raw=api.content(receipt['workflow_sha'],workflow['path'])
    if digest(workflow_raw)!=workflow['sha256'] or len(workflow_raw)!=workflow['byte_length']:
        raise Refusal('issuer_workflow_bytes')
    hybrid=object_value(raw['hybrid_capability_authority.json'])
    if set(hybrid)!={'payload','signature'} or not isinstance(hybrid['payload'],dict):
        raise Refusal('hybrid_shape')
    hp=hybrid['payload']; signature_check(hp,hybrid['signature'],key)
    expected={'schema_version':'rea.write.hybrid-capability-authority.v1',
        'purpose':'VERIFY_ONLY_CURRENT_REGISTRY','issuer':ISSUER,'authority_epoch':wea['authority_epoch'],
        'wea_sha256':digest(raw['write_enforcement_attestation.json']),
        'enforcement_bundle_manifest_digest':manifest['manifest_digest'],
        'claim_registry_sha256':digest(raw['claim_registry.json']),
        'claim_policy_sha256':digest(raw['claim_policy.json']),
        'provider_sha256':digest(raw['hybrid_capability_provider']),
        'runtime_mount_sha256':digest(raw['runtime_mount.py'])}
    if any(hp.get(k)!=v for k,v in expected.items()):
        raise Refusal('hybrid_packet_binding')
    checks = {}
    try:
        for line in raw['SHA256SUMS'].decode('ascii').splitlines():
            value,name = line.split('  ')
            if name in checks or not HEX64.fullmatch(value):
                raise ValueError()
            checks[name] = value
    except (ValueError,UnicodeDecodeError):
        raise Refusal('packet_checksums') from None
    if set(checks) != FILES-{'SHA256SUMS'} or any(digest(raw[n]) != d for n,d in checks.items()):
        raise Refusal('packet_checksums')
    return {'run_id':run_id,'ref':ref,'pointer':pointer,'pointer_sha256':digest(pointer_raw),
            'files':raw,'wea':wea,'receipt':receipt}

RECORD_FIELDS = frozenset({'schema_version','purpose','repository','issuer','run_id','run_attempt',
    'event','workflow_ref','workflow_sha','workflow_blob_sha256','conclusion','packet_tag',
    'packet_tag_object','packet_commit','packet_path','pointer_sha256','files','wea_sha256',
    'epoch','predecessor_wea_sha256','previous_record_sha256','trusted_key_id'})

def record_payload(item, conclusion, previous, trusted_key):
    r=item['receipt']; w=item['wea']; p=item['pointer']; ref=item['ref']
    return {'schema_version':SCHEMA,'purpose':'COMPLETED_ISSUER_RUN_DISPOSITION',
        'repository':REPOSITORY,'issuer':ISSUER,'run_id':item['run_id'],
        'run_attempt':r['workflow_run_attempt'],'event':r['event'],'workflow_ref':r['workflow_ref'],
        'workflow_sha':r['workflow_sha'],'workflow_blob_sha256':r['workflow_blob_sha256'],
        'conclusion':conclusion,'packet_tag':ref['tag'],'packet_tag_object':ref['tag_object'],
        'packet_commit':ref['commit'],'packet_path':p['packet_path'],
        'pointer_sha256':item['pointer_sha256'],'files':p['files'],
        'wea_sha256':digest(item['files']['write_enforcement_attestation.json']),
        'epoch':w['authority_epoch'],'predecessor_wea_sha256':w['predecessor_wea_digest'],
        'previous_record_sha256':previous,'trusted_key_id':'rea-wea-ed25519-'+digest(trusted_key)[:16]}

def verify_record(raw, item, previous, trusted_key):
    value=object_value(raw)
    if set(value) != {'payload','signature'} or not isinstance(value['payload'],dict):
        raise Refusal('record_shape')
    payload=value['payload']; conclusion=payload.get('conclusion')
    if set(payload)!=RECORD_FIELDS or conclusion not in FAILURES|{'success'}:
        raise Refusal('record_fields')
    signature_check(payload,value['signature'],key_from(trusted_key))
    if payload != record_payload(item,conclusion,previous,trusted_key):
        raise Refusal('record_binding')
    return payload

def completed_run(api,item):
    run=api.api('actions/runs/'+str(item['run_id']))
    receipt=item['receipt']
    if (not isinstance(run,dict) or run.get('id')!=item['run_id']
            or run.get('event')!='workflow_dispatch'
            or run.get('name')!='Issue write enforcement attestation'
            or run.get('path')!='.github/workflows/issue-write-enforcement-attestation.yml'
            or run.get('head_sha')!=receipt['workflow_sha']
            or run.get('head_branch')!=receipt['workflow_ref'][len('refs/tags/'):]
            or run.get('run_attempt')!=receipt['workflow_run_attempt']
            or run.get('status')!='completed' or run.get('conclusion') not in FAILURES|{'success'}):
        raise Refusal('completed_run_identity_or_outcome')
    return run['conclusion']

def scan(api,trusted_key,private_key=None,*,finalizer_ref_only=False):
    """Resolve all immutable dispositions. Unknown tails never select older head."""
    key_from(trusted_key)
    packets=api.refs(PACKET_PREFIX); records=api.refs(HISTORY_PREFIX)
    if not packets or set(records)-set(packets):
        raise Refusal('history_population')
    previous=ZERO; last_success=None; results=[]
    for run_id in sorted(packets):
        item=packet(api,run_id,packets[run_id],trusted_key)
        if run_id in records:
            raw=api.content(records[run_id]['commit'],CERT_PATH)
            payload=verify_record(raw,item,previous,trusted_key)
        else:
            if private_key is None:
                if finalizer_ref_only:
                    break
                raise Refusal('unfinalized_packet_run_'+str(run_id))
            conclusion=completed_run(api,item)
            payload=record_payload(item,conclusion,previous,trusted_key)
            signed_digest=digest(canonical(payload))
            raw=canonical({'payload':payload,'signature':{'algorithm':'ed25519',
                'signed_digest':signed_digest,'value':base64.b64encode(private_key.sign(bytes.fromhex(signed_digest))).decode()}})+b'\n'
            verify_record(raw,item,previous,trusted_key)
            if payload['conclusion']=='success' and last_success is not None and (
                    payload['epoch']!=last_success['epoch']+1
                    or payload['predecessor_wea_sha256']!=last_success['wea_sha256']):
                raise Refusal('successful_predecessor_chain')
            api.publish(run_id,raw,packets[run_id]['commit'])
        if payload['conclusion']=='success':
            if last_success is not None and (payload['epoch']!=last_success['epoch']+1
                    or payload['predecessor_wea_sha256']!=last_success['wea_sha256']):
                raise Refusal('successful_predecessor_chain')
            last_success=payload
        previous=digest(raw)
        results.append({'record':payload,'record_sha256':previous,'packet':item})
    if last_success is None:
        raise Refusal('no_successful_issuance')
    # Recheck the complete remote set after reads, including finalization races.
    if hasattr(api,'verify_population'):
        api.verify_population(packets)
    elif api.refs(PACKET_PREFIX)!=packets:
        raise Refusal('packet_history_changed_during_resolution')
    return results

def resolve(api,trusted_key,run_id=None):
    rows=scan(api,trusted_key)
    successes=[r for r in rows if r['record']['conclusion']=='success']
    chosen=successes[-1]
    if run_id is not None:
        matches=[r for r in successes if r['record']['run_id']==run_id]
        if len(matches)!=1:
            raise Refusal('requested_success_absent')
        chosen=matches[0]
    p=chosen['record']
    return {'status':'VERIFIED','run_id':p['run_id'],'epoch':p['epoch'],
            'wea_sha256':p['wea_sha256'],'workflow_ref':p['workflow_ref'],
            'workflow_sha':p['workflow_sha'],'packet_tag':p['packet_tag'],
            'packet_commit':p['packet_commit'],'record_sha256':chosen['record_sha256'],
            'history_rows':len(rows)}, chosen['packet']['files']

def successful_rebase_rows(api, trusted_key, *, after_run_id=0):
    """Adapt certified successes to the existing historical chain verifier."""
    return [{'run_id':r['record']['run_id'],'tag':r['record']['packet_tag'],
             'tag_object':r['record']['packet_tag_object'],'commit':r['record']['packet_commit'],
             'wea_raw':r['packet']['files']['write_enforcement_attestation.json'],
             'predecessor_raw':r['packet']['files']['predecessor_write_enforcement_attestation.json']}
            for r in scan(api,trusted_key) if r['record']['conclusion']=='success'
            and r['record']['run_id']>after_run_id]


def export_packet(files,destination):
    if destination.exists():
        raise Refusal('export_destination_exists')
    destination.mkdir(parents=True,mode=0o700)
    try:
        for name,raw in files.items():
            target=destination/name
            target.write_bytes(raw)
            target.chmod(0o755 if name in {'hybrid_capability_provider','runtime_mount.py'} else 0o644)
    except BaseException:
        # A partial staging directory never counts as an installed packet.
        raise

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['resolve','export','finalize','finalizer-ref'])
    parser.add_argument('--trusted-public-key',required=True,type=Path)
    parser.add_argument('--run-id',type=int)
    parser.add_argument('--destination',type=Path)
    parser.add_argument('--private-key',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.trusted_public_key.is_symlink():
            raise Refusal('trusted_key_symlink')
        trusted=args.trusted_public_key.read_bytes()
        if args.action=='finalize':
            if (os.environ.get('GITHUB_ACTIONS')!='true'
                    or os.environ.get('GITHUB_REPOSITORY')!=REPOSITORY
                    or os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch'
                    or GENERATION_REF.fullmatch(os.environ.get('GITHUB_REF','')) is None
                    or args.private_key is None):
                raise Refusal('finalizer_hosted_identity_required')
            private=serialization.load_pem_private_key(args.private_key.read_bytes(),password=None)
            if not isinstance(private,Ed25519PrivateKey) or private.public_key().public_bytes(
                    serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)!=trusted:
                raise Refusal('finalizer_key_mismatch')
            api=GitObjects()
            scan(api,trusted,private)
            api.flush()
        elif args.private_key is not None:
            raise Refusal('private_key_forbidden_on_reader')
        if args.action!='finalize':
            api=GitObjects()
        if args.action=='finalizer-ref':
            rows=scan(api,trusted,finalizer_ref_only=True)
            prior=[r for r in rows if r['record']['conclusion']=='success'][-1]['record']
            print(json.dumps({'status':'FINALIZER_REF','workflow_ref':prior['workflow_ref'],
                              'workflow_sha':prior['workflow_sha']}));return 0
        result,files=resolve(api,trusted,args.run_id)
        if args.action=='export':
            if args.destination is None:
                raise Refusal('destination_required')
            export_packet(files,args.destination)
        print(json.dumps(result,sort_keys=True));return 0
    except (Refusal,OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status':'REFUSED','reason_code':Refusal.reason_code,
                          'detail':str(exc) if isinstance(exc,Refusal) else type(exc).__name__}),file=sys.stderr)
        return 3

if __name__=='__main__':
    raise SystemExit(main())
