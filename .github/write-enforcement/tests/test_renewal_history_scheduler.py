"""Real certificate verification surrounding scheduler dispatch and recovery."""
import importlib.util
import json
from pathlib import Path
import sys
import pytest
from test_durable_attestation_history import fixture, h

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('scheduler',ROOT/'renewal_history_scheduler.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);s.history=h


def test_clean_history_needs_no_finalizer_dispatch(fixture,monkeypatch):
    api,key,public=fixture;h.scan(api,public,key)
    monkeypatch.setattr(s,'command',lambda argv: (_ for _ in ()).throw(AssertionError('unexpected dispatch')))
    result=s.prepare(api,public)
    assert result['finalizer_run_id'] is None and result['head']['run_id']==12

@pytest.mark.parametrize('outcome',['success','failure','ambiguous'])
def test_finalizes_unknown_tail_and_never_calls_older_head_current(fixture,monkeypatch,outcome):
    api,key,public=fixture;last=api.packet_refs.pop(12);h.scan(api,public,key);api.packet_refs[12]=last
    original_api=api.api
    def fake_api(path):
        if path.startswith('git/ref/'):
            return {'object':{'type':'commit','sha':'%040x'%11}}
        return original_api(path)
    api.api=fake_api;calls=[];dispatched=[]
    def command(argv):
        calls.append(argv)
        if argv[:3]==['gh','workflow','run']:
            assert argv[-1]=='mode=history_finalize';dispatched.append(True)
            if outcome=='success':h.scan(api,public,key)
            return ''
        if not dispatched:return '[]'
        rows=[{'databaseId':90,'headBranch':'rea-wea-generation-5-123456abcdef','headSha':'%040x'%11,
               'displayTitle':'WEA history_finalize','status':'completed','conclusion':'success' if outcome=='success' else 'failure'}]
        if outcome=='ambiguous':rows.append(dict(rows[0],databaseId=91))
        return json.dumps(rows)
    monkeypatch.setattr(s,'command',command);monkeypatch.setattr(h,'GitObjects',lambda:api)
    if outcome=='success':
        result=s.prepare(api,public,sleep=lambda _:None)
        assert result['head']['run_id']==12 and result['finalizer_run_id']==90
    else:
        with pytest.raises(h.Refusal,match='scheduler_finalizer'):s.prepare(api,public,sleep=lambda _:None)
        with pytest.raises(h.Refusal,match='unfinalized'):h.resolve(api,public)
    assert sum(c[:3]==['gh','workflow','run'] for c in calls)==1


def test_retargeted_finalizer_ref_refuses_before_dispatch(fixture,monkeypatch):
    api,key,public=fixture;last=api.packet_refs.pop(12);h.scan(api,public,key);api.packet_refs[12]=last
    api.api=lambda path:{'object':{'type':'commit','sha':'f'*40}}
    monkeypatch.setattr(s,'command',lambda argv: (_ for _ in ()).throw(AssertionError('dispatch reached')))
    with pytest.raises(h.Refusal,match='ref_retargeted'):s.prepare(api,public)
