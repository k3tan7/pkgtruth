import hashlib
import json
import httpx
import pytest
from fastapi.testclient import TestClient
from pkgtruth.inputs import InputError
from pkgtruth.network import Fetcher
from pkgtruth.pypi import scan_pypi, project_versions, claimed_repository, package_name
from pkgtruth.cli import main
from pkgtruth.web import create_app
from conftest import make_wheel, make_zip


@pytest.fixture
def registry():
    wheel = make_wheel({'demo.py': b'VALUE=1\n'})
    source = make_zip({'root/src/demo.py': b'VALUE=1\n'})
    metadata = {'info': {'name': 'demo', 'version': '1.0', 'project_urls': {'Source': 'https://github.com/example/demo'}},
        'urls': [{'packagetype': 'bdist_wheel', 'filename': 'demo-1.0-py3-none-any.whl', 'url': 'https://files.pythonhosted.org/demo.whl',
                  'size': len(wheel), 'digests': {'sha256': hashlib.sha256(wheel).hexdigest()}}], 'releases': {'1.0': []}}
    responses = {'/pypi/demo/1.0/json': metadata, '/pypi/demo/json': metadata,
        '/repos/example/demo/git/ref/tags/1.0': {'ref': 'refs/tags/1.0', 'object': {'type': 'commit', 'sha': 'a' * 40}},
        '/example/demo/zip/' + 'a' * 40: source, '/demo.whl': wheel}
    def handle(request):
        body = responses.get(request.url.path)
        if body is None:
            return httpx.Response(404)
        if isinstance(body, dict):
            return httpx.Response(200, json=body)
        return httpx.Response(200, content=body)
    fetcher = Fetcher(transport=httpx.MockTransport(handle), resolver=lambda host: ['8.8.8.8'])
    yield fetcher, responses, metadata
    fetcher.close()


def test_exact_registry_scan_digest_source_and_shared_engine(registry):
    fetcher, _, _ = registry
    report = scan_pypi('demo', '1.0', fetcher=fetcher)
    assert report.package_name == 'demo' and report.package_version == '1.0'
    assert report.retrieval['registry_digest_verified']
    assert report.source_commit == 'a' * 40
    assert report.source_resolution == 'PYPI_TAG_UNVERIFIED'
    assert report.provenance_status == 'NOT_CHECKED'
    assert report.coverage.identical == 1
    assert report.record_status == 'VALID'


def test_unresolved_source_is_not_fake_comparison(registry):
    fetcher, responses, _ = registry
    del responses['/repos/example/demo/git/ref/tags/1.0']
    report = scan_pypi('demo', '1.0', fetcher=fetcher)
    assert report.analysis_status == 'PARTIAL'
    assert report.source_resolution == 'ARTIFACT_ONLY'
    assert report.coverage.identical == 0 and report.coverage.source_files == 0
    assert not any(i.relation == 'NEW' for i in report.behavior_indicators)
    assert not any(f.rule == 'CONTENT_DIFFERENCE' for f in report.findings)


def test_digest_mismatch_is_rejected(registry):
    fetcher, responses, _ = registry
    responses['/demo.whl'] += b'tampered'
    with pytest.raises(InputError, match='SHA-256 or size'):
        scan_pypi('demo', '1.0', fetcher=fetcher)


def test_sdist_is_never_built(registry):
    fetcher, _, metadata = registry
    metadata['urls'][0]['packagetype'] = 'sdist'
    with pytest.raises(InputError, match='never built'):
        scan_pypi('demo', '1.0', fetcher=fetcher)


def test_registry_response_version_must_match(registry):
    fetcher, _, metadata = registry
    metadata['info']['version'] = '2.0'
    with pytest.raises(InputError, match='does not match'):
        scan_pypi('demo', '1.0', fetcher=fetcher)


@pytest.mark.parametrize('url', ['http://pypi.org/a', 'https://localhost/a', 'https://pypi.org.evil.example/a', 'https://user:pass@pypi.org/a', 'https://pypi.org:8080/a', 'https://127.0.0.1/a', 'https://evil.example/a'])
def test_network_allowlist(url):
    f = Fetcher(resolver=lambda h: ['8.8.8.8'])
    with pytest.raises(InputError):
        f.get(url)
    f.close()


def test_dns_private_and_redirect_are_rejected():
    f = Fetcher(resolver=lambda h: ['127.0.0.1'])
    with pytest.raises(InputError, match='non-public'):
        f.get('https://pypi.org/a')
    f.close()
    f = Fetcher(transport=httpx.MockTransport(lambda r: httpx.Response(302, headers={'location': 'https://evil.example/a'})), resolver=lambda h: ['8.8.8.8'])
    with pytest.raises(InputError, match='approved'):
        f.get('https://pypi.org/a')
    f.close()


def test_download_limit_and_encoding():
    for headers, body in [({}, b'12345'), ({'Content-Length': '999'}, b'x'), ({'Content-Encoding': 'gzip'}, b'fake')]:
        f = Fetcher(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body, headers=headers)), resolver=lambda h: ['8.8.8.8'])
        with pytest.raises(InputError):
            f.get('https://pypi.org/a', limit=4)
        f.close()


def test_claimed_repo_is_conservative():
    assert claimed_repository({'project_urls': {'Source': 'https://github.com/owner/repo/tree/main'}}) == 'owner/repo'
    assert claimed_repository({'project_urls': {'Source': 'https://github.com.evil/owner/repo'}}) is None
    assert claimed_repository({'project_urls': {'A': 'https://github.com/a/b', 'B': 'https://github.com/c/d'}}) is None
    with pytest.raises(InputError):
        package_name('../bad')


def test_package_lookup(registry):
    assert project_versions('demo', registry[0])['versions'] == ['1.0']


def test_pypi_web_cli_equivalence(registry, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr('pkgtruth.pypi.Fetcher', lambda: registry[0])
    monkeypatch.setattr(registry[0], 'close', lambda: None)
    assert main(['scan', 'pypi', '--name', 'demo', '--version', '1.0', '--json']) == 0
    cli = json.loads(capsys.readouterr().out)
    with TestClient(create_app()) as client:
        page = client.get('/packages?name=demo')
        assert page.status_code == 200 and '1.0' in page.text
        result = client.post('/scans/pypi', data={'csrf': client.cookies['csrf'], 'name': 'demo', 'version': '1.0'}, follow_redirects=False)
        assert result.status_code == 303
        assert client.get(result.headers['location'] + '/report.json').json() == cli
        assert client.post('/scans/pypi', data={'csrf': 'wrong'}).status_code == 403


def test_exact_tag_archive_comment_fallback(registry, monkeypatch):
    import io, zipfile
    fetcher, responses, _ = registry
    monkeypatch.setattr('pkgtruth.pypi.resolve_tag', lambda *a: (_ for _ in ()).throw(InputError('HTTP 403')))
    buffer = io.BytesIO(responses['/example/demo/zip/' + 'a' * 40])
    with zipfile.ZipFile(buffer, 'a') as z:
        z.comment = ('a' * 40).encode()
    responses['/example/demo/zip/refs/tags/1.0'] = buffer.getvalue()
    report = scan_pypi('demo', '1.0', fetcher=fetcher)
    assert report.source_commit == 'a' * 40
    assert report.retrieval['source_resolution_method'] == 'GIT_ARCHIVE_COMMENT_UNVERIFIED'
    assert report.provenance_status == 'NOT_CHECKED'


def test_wheel_declared_identity_mismatch_is_not_accepted(registry):
    fetcher,responses,metadata=registry
    wheel=make_wheel({'demo.py':b'pass\n','demo-1.0.dist-info/METADATA':b'Name: other\nVersion: 1.0\n'})
    responses['/demo.whl']=wheel
    metadata['urls'][0]['size']=len(wheel)
    metadata['urls'][0]['digests']['sha256']=hashlib.sha256(wheel).hexdigest()
    with pytest.raises(InputError,match='identity'):
        scan_pypi('demo','1.0',fetcher=fetcher)


def test_source_discovery_trace_and_actual_phases(registry):
    phases = []
    report = scan_pypi('demo', '1.0', fetcher=registry[0], progress=phases.append)
    assert phases == ['LOOKUP', 'DOWNLOAD', 'SOURCE_DISCOVERY', 'ANALYSIS']
    assert report.retrieval['claimed_repository_fields'] == ['project_urls.Source']
    assert report.retrieval['source_retrieved'] is True
    assert report.retrieval['source_comparison_performed'] is True
    assert report.retrieval['source_tag'] == '1.0'
    assert report.provenance_status == 'NOT_CHECKED'


def test_source_retrieval_is_distinct_from_comparison(registry):
    fetcher, responses, _ = registry
    responses['/example/demo/zip/' + 'a' * 40] = make_zip({'root/demo.py': b'pass\n', 'root/src/demo.py': b'pass\n'})
    report = scan_pypi('demo', '1.0', fetcher=fetcher)
    assert report.retrieval['source_retrieved'] is True
    assert report.retrieval['source_comparison_performed'] is False
    assert report.retrieval['source_archive_inspected'] is False
    assert any('ambiguous' in note for note in report.retrieval['source_discovery_notes'])
    assert report.source_resolution == 'ARTIFACT_ONLY'


def test_versions_use_python_version_order_not_string_order(registry):
    fetcher, _, metadata = registry
    metadata['releases'] = {'3.9': [], '3.10': [], '3.11rc1': [], '3.11': [], 'legacy.invalid': []}
    assert project_versions('demo', fetcher)['versions'] == ['3.11', '3.11rc1', '3.10', '3.9', 'legacy.invalid']
