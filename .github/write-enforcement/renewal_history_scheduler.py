#!/usr/bin/env python3
"""Finish completed issuer history before permitting renewal scheduling.

A verified certificate prefix may choose a finalizer executable ref, never an
older enforcement head. First deployment/backfill requires the registered release
coach to dispatch history_finalize on the newly reviewed generation ref.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import durable_attestation_history as history

WORKFLOW='issue-write-enforcement-attestation.yml'

def command(argv):
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=60,
                     env=history.transport_environment(github=True))
    if p.returncode:
        raise history.Refusal('scheduler_command_exit_'+str(p.returncode))
    return p.stdout

def prepare(api=None,public=None,sleep=time.sleep):
    api=api or history.GitObjects()
    public=public or Path(__file__).with_name('trusted_wea_public.pem').read_bytes()
    if set(api.refs(history.PACKET_PREFIX))==set(api.refs(history.HISTORY_PREFIX)):
        result,_=history.resolve(api,public)
        return {'status':'VERIFIED','finalizer_run_id':None,'head':result}
    rows=history.scan(api,public,finalizer_ref_only=True)
    prior=[r for r in rows if r['record']['conclusion']=='success'][-1]['record']
    ref=prior['workflow_ref'][len('refs/tags/'):];head=prior['workflow_sha']
    response=api.api('git/ref/tags/'+ref)
    target=response.get('object',{})
    if target.get('type')=='tag':
        target=api.api('git/tags/'+target.get('sha','')).get('object',{})
    if target.get('type')!='commit' or target.get('sha')!=head:
        raise history.Refusal('scheduler_generation_ref_retargeted')
    def runs():
        return json.loads(command(['gh','run','list','--repo',history.REPOSITORY,'--workflow',WORKFLOW,
            '--event','workflow_dispatch','--limit','100','--json','databaseId,headBranch,headSha,displayTitle,status,conclusion']))
    before=max([r['databaseId'] for r in runs()]+[0])
    command(['gh','workflow','run',WORKFLOW,'--repo',history.REPOSITORY,'--ref',ref,'-f','mode=history_finalize'])
    chosen=None
    deadline=time.monotonic()+1800
    while time.monotonic()<deadline:
        matches=[r for r in runs() if r['databaseId']>before and r['headBranch']==ref
                 and r['headSha']==head and r['displayTitle']=='WEA history_finalize']
        if len(matches)>1:
            raise history.Refusal('scheduler_finalizer_run_ambiguous')
        if matches:
            chosen=matches[0]
            if chosen['status']=='completed':
                if chosen['conclusion']!='success':
                    raise history.Refusal('scheduler_finalizer_failed')
                break
        sleep(10)
    else:
        raise history.Refusal('scheduler_finalizer_timeout')
    # Fresh remote bytes, never the cached prefix, must resolve the full history.
    result,_=history.resolve(history.GitObjects(),public)
    return {'status':'VERIFIED','finalizer_run_id':chosen['databaseId'],'head':result}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['prepare']);parser.parse_args()
    try:
        if os.environ.get('GITHUB_REF')!='refs/heads/main':
            raise history.Refusal('scheduler_requires_main')
        print(json.dumps(prepare(),sort_keys=True));return 0
    except (history.Refusal,ValueError,KeyError,OSError,subprocess.TimeoutExpired) as e:
        print(json.dumps({'status':'REFUSED','reason_code':history.Refusal.reason_code,'detail':str(e) if isinstance(e,history.Refusal) else type(e).__name__}));return 3

if __name__=='__main__':
    raise SystemExit(main())
