import pytest
from pkgtruth.analysis import analyze
from pkgtruth.dna import compare_releases
from pkgtruth.inputs import InputError
from conftest import make_wheel, make_zip


def scan(files):
    return analyze(make_wheel(files), make_zip(files))


def test_historical_first_seen_startup_even_when_present_in_current_source():
    previous = scan({'demo.py': b'pass\n'})
    current = scan({'demo.py': b'import socket\n', 'new.pth': b'import demo\n'})
    assert all(i.relation == 'PRESENT' for i in current.behavior_indicators)
    delta = compare_releases(previous, current)
    assert any(a['kind'] == 'FIRST_OBSERVED_PTH_EXECUTION' and a['severity'] == 'HIGH' for a in delta.historical_anomalies)
    assert any(a['kind'] == 'FIRST_OBSERVED_IMPORT' and a['current'] == 'socket' for a in delta.historical_anomalies)
    evidence = {e.id for e in delta.evidence}
    assert all(set(a['evidence_ids']) <= evidence for a in delta.historical_anomalies)
    assert delta == compare_releases(previous, current)
    assert not current.historical_anomalies


def test_unchanged_dna_is_empty_and_no_first_ever_claim():
    report = scan({'demo.py': b'import socket\n'})
    delta = compare_releases(report, report)
    assert not delta.historical_anomalies
    assert 'not all releases' in delta.dna_baseline['meaning']


def test_dna_removes_files_and_compares_declarations():
    previous = scan({'demo.py': b'pass\n', 'extra.py': b'pass\n'})
    current = scan({'demo.py': b'pass\n', 'demo-1.0.dist-info/entry_points.txt': b'[console_scripts]\ndemo=demo:main\n'})
    delta = compare_releases(previous, current)
    assert any(a['kind'] == 'FILE_REMOVED' and a['path'] == 'extra.py' for a in delta.historical_anomalies)
    assert any(a['kind'] == 'DECLARATION_CHANGED' for a in delta.historical_anomalies)


def test_partial_history_and_missing_fingerprint_are_explicit():
    report = scan({'demo.py': b'pass\n'})
    partial = report.model_copy(deep=True)
    partial.release_fingerprint['coverage_limited'] = True
    assert compare_releases(partial, report).dna_baseline['coverage_limited']
    partial.release_fingerprint = {}
    with pytest.raises(InputError):
        compare_releases(partial, report)


def test_mixed_package_identity_is_rejected():
    previous, current = scan({'demo.py': b'pass\n'}), scan({'demo.py': b'pass\n'})
    previous.package_name, current.package_name = 'one', 'two'
    with pytest.raises(InputError):
        compare_releases(previous, current)


def test_repeated_comparison_does_not_duplicate_evidence():
    previous, current = scan({'demo.py': b'pass\n'}), scan({'demo.py': b'import socket\n'})
    first = compare_releases(previous, current)
    again = compare_releases(previous, first)
    assert first == again
    assert len({e.id for e in again.evidence}) == len(again.evidence)


def test_dna_cli_and_web_share_comparison(tmp_path, monkeypatch, capsys):
    import json
    from fastapi.testclient import TestClient
    from pkgtruth.cli import main
    from pkgtruth.storage import ReportStore
    from pkgtruth.web import create_app
    previous, current = scan({'demo.py': b'pass\n'}), scan({'demo.py': b'pass\n', 'new.pth': b'import demo\n'})
    store=ReportStore(); store.save(previous); store.save(current)
    assert main(['dna','--previous',previous.scan_id,'--current',current.scan_id,'--json']) == 1
    cli=json.loads(capsys.readouterr().out)
    with TestClient(create_app(store)) as client:
        client.get('/scans/'+current.scan_id)
        response=client.post(f'/scans/{current.scan_id}/dna',data={'csrf':client.cookies['csrf'],'baseline':previous.scan_id},follow_redirects=False)
        assert response.status_code==303
        assert client.get(response.headers['location']+'/report.json').json()==cli
        assert 'FIRST_OBSERVED_PTH_EXECUTION' in client.get(response.headers['location']).text


@pytest.mark.parametrize('before,after,direction', [('3.9','3.10','FORWARD'),('3.10','3.9','REVERSE'),('1.0','1.0','SAME_VERSION'),(None,'1.0','UNKNOWN')])
def test_dna_explains_actual_comparison_direction(before, after, direction):
    previous, current = scan({'demo.py':b'pass\n'}), scan({'demo.py':b'pass\n'})
    previous.package_version, current.package_version = before, after
    report = compare_releases(previous, current)
    assert report.dna_baseline['direction'] == direction
    assert report.dna_baseline['direction_explanation']


def test_removed_capabilities_have_self_contained_comparison_evidence():
    previous = scan({'demo.py':b'import socket\n','start.pth':b'import demo\n'})
    current = scan({'demo.py':b'pass\n'})
    report = compare_releases(previous,current)
    assert {'REMOVED_NETWORK_CAPABILITY','REMOVED_PTH_EXECUTION','REMOVED_IMPORT'} <= {a['kind'] for a in report.historical_anomalies}
    known={e.id for e in report.evidence}
    for anomaly in report.historical_anomalies:
        assert set(anomaly['evidence_ids']) <= known
    assert compare_releases(previous,report) == report
