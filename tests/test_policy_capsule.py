import json
import pytest
from pkgtruth.analysis import analyze
from pkgtruth.policy import PolicyConfig, apply_policy
from pkgtruth.capsule import capsule_html
from pkgtruth.dna import compare_releases
from conftest import make_wheel, make_zip, wheel_files


def scan(files):
    return analyze(make_wheel(files),make_zip(files))


def test_allow_is_deterministic_scoped_and_references_evidence():
    report=scan({'demo.py':b'pass\n'})
    assert report.policy_decision.decision=='ALLOW'
    again=apply_policy(report)
    assert again==report
    known={e.id for e in report.evidence}
    assert all(set(r.evidence_ids)<=known for r in report.policy_decision.reasons)
    assert 'not proof' in report.policy_decision.reasons[0].explanation


def test_invalid_record_blocks_and_incomplete_reviews():
    files=wheel_files({'demo.py':b'pass\n'});files['demo.py']=b'changed\n'
    report=analyze(make_zip(files),make_zip({'demo.py':b'pass\n'}))
    assert report.policy_decision.decision=='BLOCK'
    incomplete=analyze(make_zip({'demo.py':b'pass\n'}),None)
    assert incomplete.policy_decision.decision=='REVIEW'


def test_historical_new_hook_requires_review_or_block():
    previous=scan({'demo.py':b'pass\n'})
    current=scan({'demo.py':b'pass\n','new.pth':b'import demo\n'})
    assert current.policy_decision.decision=='ALLOW'
    delta=compare_releases(previous,current)
    assert delta.policy_decision.decision=='REVIEW'
    assert apply_policy(delta,PolicyConfig(block_high=True)).policy_decision.decision=='BLOCK'


def test_require_provenance_and_strict_config():
    report=scan({'demo.py':b'pass\n'})
    assert apply_policy(report,PolicyConfig(require_verified_provenance=True)).policy_decision.decision=='REVIEW'
    with pytest.raises(ValueError): PolicyConfig(block_high='false')
    with pytest.raises(ValueError): PolicyConfig(invented=True)


def test_proof_capsule_is_standalone_escaped_real_json():
    report=scan({'demo.py':b'x="<script>alert(1)</script>"\n'})
    html=capsule_html(report)
    assert '<script>alert' not in html and '&lt;script&gt;' in html
    assert report.artifact_sha256 in html and 'Proof Capsule' in html
    assert 'not signed' in html and report.scan_id in html


def test_entrypoint_relationship_is_not_a_runtime_claim():
    report=scan({'demo.py':b'pass\n','new.pth':b'import demo\n',
        'demo-1.0.dist-info/entry_points.txt':b'[console_scripts]\ndemo=demo:main\n'})
    assert any(edge['target']=='demo.py' and 'declares' in edge['relationship'] for edge in report.impact_relationships)
    assert all('established' in edge['relationship'] or 'unverified' in edge['relationship'] or 'conditional' in edge['origin'] for edge in report.impact_relationships)


def test_policy_cli_and_web_settings_exports(tmp_path, capsys):
    from fastapi.testclient import TestClient
    from pkgtruth.cli import main
    from pkgtruth.storage import ReportStore
    from pkgtruth.web import create_app
    report=scan({'demo.py':b'pass\n'})
    path=tmp_path/'report.json';path.write_text(report.model_dump_json())
    assert main(['policy','check','--report',str(path),'--json'])==0
    assert json.loads(capsys.readouterr().out)['decision']=='ALLOW'
    store=ReportStore();store.save(report)
    output=tmp_path/'capsule.html'
    assert main(['report',report.scan_id,'--format','html','--output',str(output)])==0
    assert report.artifact_sha256 in output.read_text()
    with TestClient(create_app(store)) as client:
        client.get('/policy')
        assert client.post('/policy',data={'csrf':'wrong'}).status_code==403
        response=client.post('/policy',data={'csrf':client.cookies['csrf'],'require_complete':'on','block_high':'on','review_medium':'on'},follow_redirects=False)
        assert response.status_code==303 and store.get_policy().block_high
        exported=client.get(f'/scans/{report.scan_id}/report.html')
        assert exported.status_code==200 and 'Proof Capsule' in exported.text
        assert "default-src 'none'" in exported.headers['content-security-policy']


def test_impact_limit_is_visible_and_cli_strips_model_controls(monkeypatch):
    from pkgtruth.cli import render
    monkeypatch.setattr('pkgtruth.impact.MAX_EDGES',1)
    report=scan({'demo.py':b'pass\n','new.pth':b'import demo\n'})
    assert report.impact_truncated and len(report.impact_relationships)==1
    report.ai_assessments=[{'explanation':'untrusted\x1b[31m text'}]
    assert '\x1b' not in render(report)
