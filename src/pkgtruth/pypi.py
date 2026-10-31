"""Exact-release PyPI adapter. GitHub tags are correspondence claims, not provenance."""
import hashlib
import io
import zipfile
import re
from urllib.parse import quote, urlsplit

from .analysis import analyze
from .inputs import InputError, MAX_ARCHIVE, read_zip
from .network import Fetcher


def package_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?', value):
        raise InputError('Invalid package name')
    return re.sub(r'[-_.]+', '-', value).lower()


def version_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.!+_-]{0,99}', value):
        raise InputError('Invalid exact package version')
    return value


def release_metadata(fetcher, name, version=None):
    name = package_name(name)
    suffix = '/' + quote(version_name(version), safe='') if version else ''
    data = fetcher.json(f'https://pypi.org/pypi/{name}{suffix}/json')
    if not isinstance(data, dict) or not isinstance(data.get('info'), dict):
        raise InputError('Malformed PyPI project metadata')
    if package_name(data['info'].get('name')) != name or (version and data['info'].get('version') != version):
        raise InputError('PyPI response does not match requested package/version')
    return data


def project_versions(name, fetcher=None):
    own = fetcher is None
    fetcher = fetcher or Fetcher()
    try:
        data = release_metadata(fetcher, name)
        releases = data.get('releases', {})
        if not isinstance(releases, dict) or len(releases) > 10000:
            raise InputError('Unsupported release metadata')
        versions = [version for version in releases if isinstance(version, str)]
        # PyPI supplies version strings; require an exact user selection, not guessed ordering.
        return {'name': package_name(name), 'latest': data['info'].get('version'), 'versions': versions[-200:],
                'summary': str(data['info'].get('summary', ''))[:1000]}
    finally:
        if own:
            fetcher.close()


def claimed_repository(info):
    urls = info.get('project_urls') or {}
    if not isinstance(urls, dict):
        return None
    preferred = [value for key, value in urls.items() if str(key).lower() in ('source', 'source code', 'repository', 'code', 'github')]
    candidates = preferred or [*urls.values(), info.get('home_page')]
    repos = set()
    for value in candidates:
        if not isinstance(value, str):
            continue
        try:
            parsed = urlsplit(value)
        except ValueError:
            continue
        if parsed.scheme != 'https' or parsed.netloc != 'github.com':
            continue
        parts = parsed.path.strip('/').split('/')
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1].removesuffix('.git')
            if all(re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}', p) and p not in ('.', '..') for p in (owner, repo)):
                repos.add(f'{owner}/{repo}')
    return next(iter(repos)) if len(repos) == 1 else None


def resolve_tag(fetcher, repo, version):
    for tag in (version, 'v' + version):
        try:
            data = fetcher.json(f'https://api.github.com/repos/{repo}/git/ref/tags/{quote(tag, safe="")}')
        except FileNotFoundError:
            continue
        if not isinstance(data, dict) or data.get('ref') != 'refs/tags/' + tag:
            continue
        obj = data.get('object', {})
        for _ in range(3):
            sha = obj.get('sha') if isinstance(obj, dict) else None
            if not isinstance(sha, str) or not re.fullmatch('[a-f0-9]{40}', sha):
                break
            if obj.get('type') == 'commit':
                return tag, sha
            if obj.get('type') != 'tag':
                break
            annotated = fetcher.json(f'https://api.github.com/repos/{repo}/git/tags/{sha}')
            obj = annotated.get('object', {}) if isinstance(annotated, dict) else {}
    return None, None


def choose_source_prefix(archive, wheel):
    files = read_zip(archive)
    wrappers = {path.split('/')[0] for path in files}
    if len(wrappers) != 1 or any('/' not in path for path in files):
        raise InputError('GitHub archive has no unambiguous wrapper root')
    root = next(iter(wrappers))
    published = read_zip(wheel)
    candidates = []
    for prefix in (root, root + '/src'):
        paths = {path[len(prefix) + 1:] for path in files if path.startswith(prefix + '/')}
        overlap = {path for path in paths & published.keys() if not path.split('/')[0].endswith('.dist-info')}
        if overlap:
            candidates.append(prefix)
    if len(candidates) != 1:
        raise InputError('Source root is ambiguous or has no shared package paths')
    return candidates[0]


def scan_pypi(name, version, *, fetcher=None):
    name, version = package_name(name), version_name(version)
    own = fetcher is None
    fetcher = fetcher or Fetcher()
    try:
        data = release_metadata(fetcher, name, version)
        urls = data.get('urls')
        if not isinstance(urls, list):
            raise InputError('PyPI release has no artifact list')
        wheels = [item for item in urls if isinstance(item, dict) and item.get('packagetype') == 'bdist_wheel' and not item.get('yanked')]
        # Pure Python wheels first; then deterministic filename selection. Never fall back to building an sdist.
        wheels.sort(key=lambda item: (not str(item.get('filename', '')).endswith('none-any.whl'), str(item.get('filename', ''))))
        if not wheels:
            raise InputError('No non-yanked wheel is available; source distributions are never built')
        item = wheels[0]
        filename, url = item.get('filename'), item.get('url')
        digests = item.get('digests')
        expected = digests.get('sha256') if isinstance(digests, dict) else None
        if not isinstance(filename, str) or '/' in filename or '\\' in filename or not re.fullmatch(r'[A-Za-z0-9_.+!-]+\.whl', filename) or not isinstance(url, str) or not url.startswith('https://files.pythonhosted.org/'):
            raise InputError('Invalid PyPI wheel identity or download host')
        if not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{64}', expected):
            raise InputError('PyPI artifact has no valid SHA-256 digest')
        if not isinstance(item.get('size'), int) or not 0 < item['size'] <= MAX_ARCHIVE:
            raise InputError('PyPI wheel size exceeds supported limits')
        wheel = fetcher.get(url)
        if len(wheel) != item['size'] or hashlib.sha256(wheel).hexdigest() != expected:
            raise InputError('Published wheel SHA-256 or size does not match PyPI metadata')
        repo = claimed_repository(data['info'])
        source, prefix, tag, commit = None, '', None, None
        resolution_method = None
        notes = []
        if repo:
            try:
                try:
                    tag, commit = resolve_tag(fetcher, repo, version)
                    resolution_method = 'GITHUB_TAG_API' if commit else None
                except InputError as exc:
                    notes.append(f'Tag API unavailable: {exc}; trying exact-tag archives only.')
                if not commit:
                    for candidate in (version, 'v' + version):
                        try:
                            archive = fetcher.get(f'https://codeload.github.com/{repo}/zip/refs/tags/{quote(candidate, safe="")}')
                            read_zip(archive)
                            with zipfile.ZipFile(io.BytesIO(archive)) as z:
                                comment = z.comment.decode('ascii', errors='replace')
                            if re.fullmatch('[a-f0-9]{40}', comment):
                                tag, commit = candidate, comment
                                resolution_method = 'GIT_ARCHIVE_COMMENT_UNVERIFIED'
                                break
                        except FileNotFoundError:
                            continue
                if commit:
                    source = fetcher.get(f'https://codeload.github.com/{repo}/zip/{commit}')
                    prefix = choose_source_prefix(source, wheel)
                else:
                    notes.append('No exact version/v-version tag resolved; default branches are not substituted.')
            except (InputError, FileNotFoundError) as exc:
                source, prefix = None, ''
                notes.append(f'Claimed source could not be fully inspected: {exc}')
        else:
            notes.append('No unambiguous claimed GitHub repository in package metadata.')
        report = analyze(wheel, source, artifact_name=filename, source_prefix=prefix)
        from packaging.version import Version
        identity_verified = report.package_name is not None and report.package_version is not None
        if identity_verified:
            try:
                if package_name(report.package_name) != name or Version(report.package_version) != Version(version):
                    raise InputError('Wheel metadata identity does not match the requested release')
            except ValueError as exc:
                raise InputError('Wheel metadata identity does not match the requested release') from exc
        else:
            notes.append('Wheel metadata identity could not be independently parsed.')
        report.package_name, report.package_version = name, version
        report.source_commit = commit
        report.source_resolution = 'PYPI_TAG_UNVERIFIED' if source else 'ARTIFACT_ONLY'
        report.retrieval = {'registry': 'https://pypi.org', 'artifact_url': url, 'registry_sha256': expected,
            'registry_digest_verified': True, 'wheel_metadata_identity_verified': identity_verified, 'claimed_repository': f'https://github.com/{repo}' if repo else None,
            'source_tag': tag, 'source_resolution_method': resolution_method, 'source_archive_sha256': hashlib.sha256(source).hexdigest() if source else None, 'source_archive_inspected': source is not None,
            'source_correspondence': 'TAG_MATCH_UNVERIFIED' if commit else 'UNRESOLVED'}
        report.limitations.extend(notes + ['A matching GitHub tag is a claimed correspondence, not authenticated provenance or a reproducible-build guarantee.'])
        report.scan_id = hashlib.sha256(f'pypi:{report.scan_id}:{name}:{version}:{commit}'.encode()).hexdigest()[:32]
        from .policy import apply_policy
        return apply_policy(report)
    finally:
        if own:
            fetcher.close()
