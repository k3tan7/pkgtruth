"""Opt-in real-service acceptance: run against a disposable local instance + private Qwen.
Not part of offline CI. Updates synthetic reports, policy/watch state and recorded AI example.
"""
import httpx,time,json,os
from pathlib import Path
base=os.environ.get('PKGTRUTH_VERIFY_URL','http://127.0.0.1:8003')
root=Path(__file__).resolve().parents[1]
c=httpx.Client(base_url=base,headers={'Origin':base},timeout=180)
assert c.get('/health').json()['status']=='ok'
c.get('/scans/new')
def post(path,**data):
    r=c.post(path,data={'csrf':c.cookies['csrf'],**data});assert r.status_code==303,(path,r.status_code,r.text[:200]);return r.headers['location']
def upload(label):
    r=c.post('/scans',data={'csrf':c.cookies['csrf'],'source_prefix':''},files={'wheel':(label+'.whl',(root/'examples'/f'{label}.whl').read_bytes()),'source':('source.zip',(root/'examples/source.zip').read_bytes())});assert r.status_code==303,r.text;return r.headers['location'].split('/')[-1]
def getreport(s):return c.get(f'/scans/{s}/report.json').json()
def job(path,**data):
    location=post(path,**data);assert c.get(location).status_code==200
    for _ in range(180):
        j=c.get(location+'/status').json()
        if j['status'] in ('COMPLETE','FAILED','INTERRUPTED'):
            assert j['status']=='COMPLETE',j;print('job',j,flush=True);return j['scan_id']
        time.sleep(1)
    raise AssertionError('Job timed out')
clean,startup=upload('clean'),upload('startup')
assert getreport(clean)['policy_decision']['decision']=='ALLOW'
post(f'/scans/{startup}/dna',baseline=clean)
before=getreport(startup);assert before['historical_anomalies']
job('/jobs/ai',scan_id=startup)
after=getreport(startup);assert after['model_status']=='VALIDATED',after['model_details']
for k in before:
    if k not in ('ai_assessments','model_details','model_status','schema_version'):assert before[k]==after[k],k
(root/'examples/qwen.actual.json').write_text(json.dumps(after,indent=2)+'\n')
html=c.get(f'/scans/{startup}/report.html');assert html.status_code==200 and after['artifact_sha256'] in html.text
assert 'Release DNA' in c.get(f'/scans/{startup}').text
post('/policy',require_complete='on',review_medium='on')
post('/watchlist',name='idna')
r=c.post('/watchlist/check',data={'csrf':c.cookies['csrf']});assert r.status_code==200,r.text
r=c.post('/watchlist/check',data={'csrf':c.cookies['csrf']});assert r.status_code==200 and 'UNCHANGED' in r.text
assert 'idna' in c.get('/packages?name=idna').text
remote=job('/jobs/pypi',name='idna',version='3.10')
p=getreport(remote);assert p['retrieval']['registry_digest_verified'] and p['package_version']=='3.10'
assert p['artifact_sha256']=='946d195a0d259cbba61165e88e65941f16e9b36ea6ddb97f00452bae8b1287d3'
print(json.dumps({'clean':clean,'startup_dna_ai':startup,'pypi':remote,'ai_status':after['model_status'],'ai_details':after['model_details'],'pypi_status':p['analysis_status'],'dna_changes':len(before['historical_anomalies'])},indent=2))
