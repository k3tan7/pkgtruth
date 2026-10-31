import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from pkgtruth.cli import main
from pkgtruth.models import Report
from pkgtruth.storage import ReportStore
from pkgtruth.web import create_app, MAX_REQUEST
from conftest import make_zip, make_wheel


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(ReportStore(tmp_path / 'web'))) as client:
        yield client


def upload(client, wheel, source, prefix=''):
    client.get('/scans/new')
    return client.post('/scans', headers={'Origin': str(client.base_url).rstrip('/')}, data={'csrf': client.cookies['csrf'], 'source_prefix': prefix},
        files={'wheel': ('demo.whl', wheel), 'source': ('source.zip', source)}, follow_redirects=False)


@pytest.mark.parametrize('tampered', [False, True])
def test_web_cli_engine_equivalence(client, tmp_path, package_pair, tampered):
    files, _ = package_pair
    wheel = make_wheel(files)
    if tampered:
        wheel = make_wheel({**files, 'demo/__init__.py': b'VALUE = 99\n'})
    wheel_path, source_path = tmp_path / 'demo.whl', tmp_path / 'source.zip'
    wheel_path.write_bytes(wheel)
    source_path.write_bytes(make_zip(files))
    process = subprocess.run([sys.executable, '-m', 'pkgtruth.cli', 'scan', 'local', '--wheel', str(wheel_path),
        '--source', str(source_path), '--json'], capture_output=True, text=True, cwd=tmp_path)
    assert process.returncode == (1 if tampered else 0), process.stderr
    cli_report = Report.model_validate_json(process.stdout)
    response = upload(client, wheel, make_zip(files))
    assert response.status_code == 303
    exported = client.get(response.headers['location'] + '/report.json')
    assert exported.status_code == 200
    assert Report.model_validate(exported.json()) == cli_report
    page = client.get(response.headers['location'])
    assert page.status_code == 200
    assert cli_report.artifact_sha256 in page.text
    assert 'File explorer' in page.text
    assert 'NOT_CHECKED' in page.text
    assert 'demo.whl' in client.get('/').text
    output = tmp_path / 'export.json'
    assert main(['report', cli_report.scan_id, '--output', str(output)]) == 0
    assert Report.model_validate_json(output.read_text()) == cli_report


def test_cli_errors_and_help(tmp_path, capsys):
    assert main(['scan', 'local', '--wheel', str(tmp_path / 'missing'), '--source', str(tmp_path)]) == 2
    assert 'pkgtruth:' in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        main(['scan', 'local'])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(['--help'])
    assert exc.value.code == 0
    assert main(['report', 'missing', '--output', str(tmp_path / 'out')]) == 2


def test_web_rejection_states(client, package_pair):
    _, wheel = package_pair
    response = upload(client, b'not a wheel', wheel)
    assert response.status_code == 422
    assert 'Input rejected' in response.text
    assert 'Malformed' in response.text
    assert client.post('/scans', data={'csrf': 'wrong'}).status_code == 403
    assert client.post('/scans', headers={'Origin': 'https://evil.example'}).status_code == 403
    assert client.post('/scans', headers={'Origin': 'null'}).status_code == 403
    assert client.post('/scans', headers={'Sec-Fetch-Site': 'cross-site'}).status_code == 403
    assert client.get('/scans/' + '0' * 32).status_code == 404
    assert client.get('/scans/invalid/report.json').status_code == 404


def test_headers_and_oversized_upload(client):
    response = client.get('/health')
    assert response.json()['status'] == 'ok'
    assert "script-src 'self'" in response.headers['content-security-policy']
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert client.post('/scans', headers={'Content-Length': str(MAX_REQUEST + 1)}).status_code == 413
    assert client.post('/scans', content=b'x' * (MAX_REQUEST + 1)).status_code == 413
    assert client.get('/', headers={'host': 'evil.example'}).status_code == 400


def test_remote_clients_rejected():
    with TestClient(create_app(), client=('198.51.100.2', 12345)) as remote:
        assert remote.get('/').status_code == 403
        assert remote.get('/scans/' + '0' * 32 + '/report.json').status_code == 403


def test_html_escapes_untrusted_package_text(client):
    payload = b'<script>alert("untrusted")</script>\n'
    wheel = make_zip({'evil.py': payload})
    source = make_zip({'evil.py': b'pass\n'})
    response = upload(client, wheel, source)
    page = client.get(response.headers['location'])
    assert '<script>alert' not in page.text
    assert '&lt;script&gt;' in page.text


def test_web_partial_mapping_state(client, package_pair):
    files, wheel = package_pair
    response = upload(client, wheel, make_zip({'src/' + k: v for k, v in files.items()}))
    page = client.get(response.headers['location'])
    assert 'PARTIAL' in page.text
    assert 'Coverage needs review' in page.text


def test_built_assets_available(client):
    assert client.get('/static/app.css').status_code == 200
    assert client.get('/static/app.js').status_code == 200
    assert 'name="csrf"' in client.get('/scans/new').text


def test_unicode_csrf_is_rejected_without_server_error(client, package_pair):
    _, wheel = package_pair
    client.get('/scans/new')
    response = client.post('/scans', data={'csrf': '\u00e9'}, files={
        'wheel': ('demo.whl', wheel), 'source': ('source.zip', wheel)})
    assert response.status_code == 403


def test_storage_failure_is_an_explicit_error(client, tmp_path, package_pair, monkeypatch, capsys):
    import sqlite3
    _, wheel = package_pair
    def unavailable(*args):
        raise sqlite3.OperationalError('database is locked')
    monkeypatch.setattr(ReportStore, 'save', unavailable)
    response = upload(client, wheel, wheel)
    assert response.status_code == 503
    assert 'unavailable' in response.json()['detail']
    wheel_path = tmp_path / 'demo.whl'
    source_path = tmp_path / 'source.zip'
    wheel_path.write_bytes(wheel)
    source_path.write_bytes(wheel)
    assert main(['scan', 'local', '--wheel', str(wheel_path), '--source', str(source_path)]) == 2
    assert 'database is locked' in capsys.readouterr().err


@pytest.mark.parametrize('tampered', [False, True])
def test_security_findings_match_web_and_cli(client, tmp_path, tampered):
    source = {'demo.py': b'VALUE=1\n'}
    payload = {'demo.py': b'import subprocess as sp\nsp.run([])\n', 'startup.pth': b'import demo\n'} if tampered else source
    wheel = make_wheel(payload)
    wheel_path, source_path = tmp_path / 'demo.whl', tmp_path / 'source.zip'
    wheel_path.write_bytes(wheel)
    source_path.write_bytes(make_zip(source))
    process = subprocess.run([sys.executable, '-m', 'pkgtruth.cli', 'scan', 'local', '--wheel', str(wheel_path),
        '--source', str(source_path), '--json'], capture_output=True, text=True, cwd=tmp_path)
    assert process.returncode == (1 if tampered else 0), process.stderr
    cli_report = Report.model_validate_json(process.stdout)
    response = upload(client, wheel, make_zip(source))
    assert response.status_code == 303
    url = response.headers['location']
    assert Report.model_validate(client.get(url + '/report.json').json()) == cli_report
    assert cli_report.record_status == 'VALID'
    page = client.get(url)
    assert page.status_code == 200
    assert 'Install impact preview' in page.text
    assert 'Entry points &amp; dependencies' in page.text
    if tampered:
        assert 'PTH_EXECUTION' in page.text
        assert 'SUBPROCESS_CAPABILITY' in page.text
        assert any(f.severity == 'HIGH' for f in cli_report.findings)
    else:
        assert not cli_report.behavior_indicators


def test_cli_missing_record_requires_review_and_explains_status(tmp_path, capsys):
    wheel = tmp_path / 'demo.whl'
    source = tmp_path / 'source.zip'
    wheel.write_bytes(make_zip({'demo.py': b'pass\n'}))
    source.write_bytes(wheel.read_bytes())
    assert main(['scan', 'local', '--wheel', str(wheel), '--source', str(source)]) == 1
    text = capsys.readouterr().out
    assert 'RECORD: UNAVAILABLE' in text
    assert 'PARTIAL' in text


def test_web_escapes_security_evidence(client):
    code = b'eval("<script>alert(1)</script>")\n'
    response = upload(client, make_wheel({'demo.py': code}), make_zip({'demo.py': b'pass\n'}))
    page = client.get(response.headers['location'])
    assert page.status_code == 200
    assert '<script>alert' not in page.text
    assert '&lt;script&gt;' in page.text
    assert 'DYNAMIC_EXECUTION' in page.text
