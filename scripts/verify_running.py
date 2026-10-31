"""Verify real loopback HTTP uploads and stored exports against the shared engine.

Run `pkgtruth serve` first. Needs the project's [test] dependencies.
"""
import argparse
from pathlib import Path
import httpx
from pkgtruth.analysis import analyze
from pkgtruth.models import Report

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--port', type=int, default=8000)
args = parser.parse_args()
if not 1 <= args.port <= 65535:
    parser.error('port must be between 1 and 65535')
URL = f'http://127.0.0.1:{args.port}'

with httpx.Client(base_url=URL, timeout=30) as client:
    assert client.get('/health').status_code == 200
    for label in ('clean', 'tampered', 'startup', 'record-mismatch'):
        assert client.get('/scans/new').status_code == 200
        wheel = (ROOT / f'examples/{label}.whl').read_bytes()
        source = (ROOT / 'examples/source.zip').read_bytes()
        response = client.post('/scans', headers={'Origin': URL},
            data={'csrf': client.cookies['csrf'], 'source_prefix': ''},
            files={'wheel': (f'{label}.whl', wheel), 'source': ('source.zip', source)})
        assert response.status_code == 303, response.text
        location = response.headers['location']
        exported = client.get(location + '/report.json')
        assert exported.status_code == 200
        actual = Report.model_validate(exported.json())
        expected = analyze(wheel, source, artifact_name=f'{label}.whl')
        assert actual == expected
        assert actual.record_status == ('INVALID' if label == 'record-mismatch' else 'VALID')
        if label == 'startup':
            assert any(f.rule == 'PTH_EXECUTION' and f.severity == 'HIGH' for f in actual.findings)
            assert 'Install impact preview' in client.get(location).text
        page = client.get(location)
        assert page.status_code == 200
        assert 'File explorer' in page.text
        assert actual.artifact_sha256 in page.text
        print(f'{label}: POST 303, report 200, rendered results 200, engine equality verified: {URL}{location}')
