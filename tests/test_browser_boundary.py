"""Regression for native form POSTs and negotiated browser recovery pages."""
import pytest
from fastapi.testclient import TestClient
from pkgtruth.analysis import analyze
from pkgtruth.storage import ReportStore
from pkgtruth.web import create_app
from pkgtruth.web_security import canonical_origin
from conftest import make_wheel, make_zip


@pytest.mark.parametrize('base,origin', [
    ('http://127.0.0.1:8003', 'http://127.0.0.1:8003'),
    ('http://localhost:8003', 'http://localhost:8003'),
    ('http://localhost', 'http://localhost:80'),
    ('https://localhost', 'https://localhost:443'),
    ('http://[::1]:8003', 'http://[::1]:8003'),
])
def test_native_same_origin_forms_use_compatible_referrer_policy(tmp_path, monkeypatch, base, origin):
    report = analyze(make_wheel({'demo.py': b'pass\n'}), make_zip({'demo.py': b'pass\n'}))
    monkeypatch.setattr('pkgtruth.pypi.scan_pypi', lambda *args: report)
    monkeypatch.setattr('pkgtruth.watch.watch_once', lambda store: [])
    with TestClient(create_app(ReportStore(tmp_path)), base_url=base) as client:
        page = client.get('/policy')
        # Fetch's append-Origin algorithm makes native no-referrer POSTs opaque.
        # same-origin preserves their Origin while withholding cross-origin Referer.
        assert page.headers['referrer-policy'] == 'same-origin'
        headers = {'Origin': origin, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate', 'Accept': 'text/html'}
        token = client.cookies['csrf']
        for path, values, expected in [('/policy', {'require_complete': 'on'}, 303),
                                       ('/watchlist/check', {}, 200),
                                       ('/jobs/pypi', {'name': 'demo', 'version': '1.0'}, 303)]:
            response = client.post(path, data={'csrf': token, **values}, headers=headers, follow_redirects=False)
            assert response.status_code == expected, response.text


@pytest.mark.parametrize('origin', ['null', 'http://evil.example', 'http://localhost:8003',
                                  'http://127.0.0.1:8004', 'https://127.0.0.1:8003',
                                  'http://127.0.0.1:8003/path', 'http://user@127.0.0.1:8003', ''])
@pytest.mark.parametrize('path', ['/policy', '/watchlist/check', '/jobs/pypi'])
def test_opaque_cross_origin_and_malformed_posts_stay_rejected(tmp_path, origin, path):
    with TestClient(create_app(ReportStore(tmp_path)), base_url='http://127.0.0.1:8003') as client:
        client.get('/policy')
        response = client.post(path, data={'csrf': client.cookies['csrf']}, headers={'Origin': origin, 'Accept': 'text/html'})
        assert response.status_code == 403
        assert response.headers['content-type'].startswith('text/html')
        assert 'Reload this form' in response.text
        assert 'Return to the form' in response.text


def test_duplicate_origin_cross_site_and_missing_csrf_stay_rejected(tmp_path):
    with TestClient(create_app(ReportStore(tmp_path)), base_url='http://127.0.0.1:8003') as client:
        client.get('/policy')
        token = client.cookies['csrf']
        for headers in [
            [('Origin', 'http://evil.example'), ('Origin', 'http://127.0.0.1:8003')],
            {'Origin': 'http://127.0.0.1:8003', 'Sec-Fetch-Site': 'cross-site'},
        ]:
            assert client.post('/policy', data={'csrf': token}, headers=headers).status_code == 403
        for token in ('wrong', '', '\u00e9'):
            response = client.post('/policy', data={'csrf': token}, headers={'Origin': 'http://127.0.0.1:8003'})
            assert response.status_code == 403


def test_error_negotiation_preserves_json_and_status_codes(tmp_path, monkeypatch):
    with TestClient(create_app(ReportStore(tmp_path))) as client:
        html = client.get('/missing', headers={'Accept': 'text/html'})
        assert html.status_code == 404 and 'We could not find' in html.text
        api = client.get('/missing', headers={'Accept': 'application/json'})
        assert api.status_code == 404 and api.json()['detail'] == 'Not Found'
        # Machine endpoints remain JSON even with browser navigation Accept.
        api = client.get('/scans/' + '0' * 32 + '/report.json', headers={'Accept': 'text/html'})
        assert api.status_code == 404 and api.json()['detail'] == 'Report not found'
        api = client.get('/jobs/' + '0' * 32 + '/status', headers={'Accept': 'text/html'})
        assert api.status_code == 404 and api.json()['detail'] == 'Job not found'
        oversized = client.post('/policy', headers={'Accept': 'text/html', 'Content-Length': str(40 * 1024 * 1024)})
        assert oversized.status_code == 413 and 'files are too large' in oversized.text


def test_origin_parser_does_not_turn_explicit_zero_port_into_default():
    assert canonical_origin('http://localhost:0') != canonical_origin('http://localhost')
