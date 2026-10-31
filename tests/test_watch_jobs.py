import json
import threading
import time
import httpx
import pytest
from fastapi.testclient import TestClient
from pkgtruth.analysis import analyze
from pkgtruth.inputs import InputError
from pkgtruth.jobs import JobRunner
from pkgtruth.network import Fetcher
from pkgtruth.storage import ReportStore
from pkgtruth.watch import watch_once
from pkgtruth.web import create_app
from conftest import make_wheel,make_zip


def report():
    return analyze(make_wheel({'demo.py':b'pass\n'}),make_zip({'demo.py':b'pass\n'}))


def wait_job(runner,job_id):
    limit=time.monotonic()+3
    while time.monotonic()<limit:
        state=runner.get(job_id)
        if state['status'] in ('COMPLETE','FAILED','INTERRUPTED'): return state
        time.sleep(.005)
    pytest.fail('Local test job did not finish')


def test_watch_no_duplicates_new_release_changed_artifact_and_rollback(tmp_path):
    store=ReportStore(tmp_path)
    store.add_watch('Demo');store.add_watch('demo')
    assert len(store.watchlist())==1
    metadata={'info':{'name':'demo','version':'1.0'},'urls':[{'filename':'demo.whl','digests':{'sha256':'a'*64}}]}
    with httpx.Client():
        f=Fetcher(transport=httpx.MockTransport(lambda r:httpx.Response(200,json=metadata)),resolver=lambda h:['8.8.8.8'])
        try:
            assert watch_once(store,fetcher=f)[0]['status']=='BASELINE_RECORDED'
            assert watch_once(store,fetcher=f)[0]['status']=='UNCHANGED'
            metadata['info']['version']='2.0'
            assert watch_once(store,fetcher=f)[0]['status']=='NEW_RELEASE'
            metadata['urls'][0]['digests']['sha256']='b'*64
            assert watch_once(store,fetcher=f)[0]['status']=='ARTIFACT_METADATA_CHANGED'
            metadata['info']['version']='1.0'
            assert watch_once(store,fetcher=f)[0]['status']=='LATEST_VERSION_CHANGED'
            assert len(store.watch_events())==4
            store.remove_watch('demo');store.add_watch('demo')
            assert watch_once(store,fetcher=f)[0]['status']=='BASELINE_RECORDED'
            assert len(store.watch_events())==5
        finally: f.close()


def test_watch_failure_is_explicit_and_no_event_is_fabricated(tmp_path):
    store=ReportStore(tmp_path);store.add_watch('demo')
    f=Fetcher(transport=httpx.MockTransport(lambda r:httpx.Response(503)),resolver=lambda h:['8.8.8.8'])
    try:
        result=watch_once(store,fetcher=f)
        assert result[0]['status']=='ERROR' and not store.watch_events()
    finally: f.close()
    with pytest.raises(InputError): store.add_watch('../bad')


def test_job_success_failure_capacity_and_persistence(tmp_path,monkeypatch):
    store=ReportStore(tmp_path)
    gate=threading.Event();entered=threading.Event()
    def scan(*args):
        entered.set();assert gate.wait(2)
        return report()
    monkeypatch.setattr('pkgtruth.pypi.scan_pypi',scan)
    runner=JobRunner(store)
    first=runner.submit('pypi',{'name':'demo','version':'1.0'})
    assert entered.wait(2)
    second=runner.submit('pypi',{'name':'demo','version':'1.1'})
    with pytest.raises(InputError,match='queue'): runner.submit('pypi',{'name':'demo','version':'1.2'})
    gate.set()
    assert wait_job(runner,first)['status']=='COMPLETE'
    assert wait_job(runner,second)['status']=='COMPLETE'
    assert store.get(runner.get(first)['scan_id'])
    monkeypatch.setattr('pkgtruth.pypi.scan_pypi',lambda *args:(_ for _ in ()).throw(InputError('bounded test failure')))
    failed=runner.submit('pypi',{'name':'demo','version':'1.0'})
    assert wait_job(runner,failed)['status']=='FAILED'
    runner.close()
    with store.connect() as db:
        db.execute("INSERT INTO jobs(id,kind,payload,status) VALUES ('restart','pypi','{}','RUNNING')")
    recovered=JobRunner(store)
    assert recovered.get('restart')['status']=='INTERRUPTED'
    recovered.close()


def test_web_queued_pypi_and_policy_configuration(tmp_path,monkeypatch):
    monkeypatch.setattr('pkgtruth.pypi.scan_pypi',lambda *args:report())
    with TestClient(create_app(ReportStore(tmp_path))) as client:
        client.get('/packages')
        assert client.post('/jobs/pypi',data={'csrf':'wrong'}).status_code==403
        response=client.post('/jobs/pypi',data={'csrf':client.cookies['csrf'],'name':'demo','version':'1.0'},follow_redirects=False)
        assert response.status_code==303 and response.headers['location'].startswith('/jobs/')
        url=response.headers['location']
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            state=client.get(url+'/status').json()
            if state['status'] in ('COMPLETE','FAILED'):break
            time.sleep(.005)
        assert state['status']=='COMPLETE'
        assert client.get('/scans/'+state['scan_id']).status_code==200
        assert client.get('/jobs/'+'0'*32+'/status').status_code==404
        for _ in range(19):assert client.get('/packages').status_code==200
        assert client.get('/packages').status_code==429


def test_watch_cli_and_web_use_persistent_store(monkeypatch,tmp_path,capsys):
    from pkgtruth.cli import main
    assert main(['watch','--add','demo','--json'])==0
    assert json.loads(capsys.readouterr().out)[0]['name']=='demo'
    with TestClient(create_app()) as client:
        page=client.get('/watchlist')
        assert 'demo' in page.text
        assert client.post('/watchlist',data={'csrf':'bad','name':'other'}).status_code==403
        response=client.post('/watchlist',data={'csrf':client.cookies['csrf'],'name':'other'},follow_redirects=False)
        assert response.status_code==303
        assert len(ReportStore().watchlist())==2


def test_web_queued_ai_preserves_report_facts(tmp_path,monkeypatch):
    store=ReportStore(tmp_path);original=report();store.save(original)
    def explain(value):
        result=value.model_copy(deep=True);result.model_status='VALIDATED';return result
    monkeypatch.setattr('pkgtruth.investigator.investigate',explain)
    with TestClient(create_app(store)) as client:
        client.get('/scans/'+original.scan_id)
        response=client.post('/jobs/ai',data={'csrf':client.cookies['csrf'],'scan_id':original.scan_id},follow_redirects=False)
        assert response.status_code==303
        limit=time.monotonic()+3
        while time.monotonic()<limit:
            job=client.get(response.headers['location']+'/status').json()
            if job['status'] in ('COMPLETE','FAILED'):break
            time.sleep(.005)
        assert job['status']=='COMPLETE'
        saved=store.get(job['scan_id'])
        assert saved.model_status=='VALIDATED' and saved.artifact_sha256==original.artifact_sha256
        assert saved.policy_decision==original.policy_decision
