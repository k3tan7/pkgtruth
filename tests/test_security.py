"""Security regressions use inert archives; target code is never executed."""
import base64
import hashlib
import json
from pathlib import Path
import pytest
from pkgtruth.analysis import analyze
from pkgtruth.inputs import InputError
from pkgtruth.models import Report
from pkgtruth.security import features, validate_record
from conftest import make_wheel, make_zip, wheel_files

RECORD = 'demo-1.0.dist-info/RECORD'


def scan(files, source=None):
    return analyze(make_wheel(files), make_zip(source if source is not None else files))


def test_record_valid_is_not_authenticity():
    report = scan({'demo.py': b'VALUE=1\n'})
    assert report.record_status == 'VALID'
    assert report.record_check.checked_files == 3
    assert report.provenance_status == 'NOT_CHECKED'
    assert report.analysis_status == 'COMPLETE'


def test_rewritten_record_does_not_hide_tampering():
    report = scan({'demo.py': b'import subprocess\nsubprocess.run(["echo", "inert fixture"])\n'}, {'demo.py': b'VALUE=1\n'})
    assert report.record_status == 'VALID'
    assert any(d.path == 'demo.py' and d.status == 'modified' for d in report.file_differences)
    assert any(f.rule == 'SUBPROCESS_CAPABILITY' and f.severity == 'MEDIUM' for f in report.findings)
    assert any(i.kind == 'SUBPROCESS_CAPABILITY' and i.relation == 'NEW' for i in report.behavior_indicators)


def test_record_hash_and_size_mismatch():
    files = wheel_files({'demo.py': b'VALUE=1\n'})
    files['demo.py'] = b'VALUE=22222\n'
    result = validate_record(files)
    assert result.status == 'INVALID'
    reasons = [i.reason for i in result.issues]
    assert any('size' in r for r in reasons)
    assert any('hash' in r for r in reasons)
    report = analyze(make_zip(files), make_zip({'demo.py': b'VALUE=1\n'}))
    assert report.analysis_status == 'PARTIAL'
    assert any(f.rule == 'RECORD_INVALID' and f.severity == 'HIGH' for f in report.findings)


@pytest.mark.parametrize('row', [
    'demo.py,,8\n',
    'demo.py,sha256=abc,8\n',
    'demo.py,sha256=abc=,8\n',
    'demo.py,md5=abc,8\n',
    'demo.py,sha1=abc,8\n',
    'demo.py,sha256=abc,-1\n',
    '../demo.py,sha256=abc,8\n',
    'missing.py,sha256=abc,8\n',
    'a,b,c,d\n',
    '"unclosed',
])
def test_invalid_record_rows(row):
    files = wheel_files({'demo.py': b'VALUE=1\n'})
    files[RECORD] = row.encode()
    assert validate_record(files).status == 'INVALID'


def test_record_self_entry_and_unlisted_file():
    files = wheel_files({'demo.py': b'VALUE=1\n'})
    files[RECORD] = files[RECORD].replace((RECORD + ',,').encode(), (RECORD + ',sha256=abc,0').encode())
    files['unlisted.py'] = b'pass\n'
    result = validate_record(files)
    assert result.status == 'INVALID'
    assert any('self-entry' in i.reason for i in result.issues)
    assert any(i.path == 'unlisted.py' for i in result.issues)


def test_record_duplicate_normalized_paths():
    files = wheel_files({'demo.py': b'pass\n'})
    files[RECORD] += b'DEMO.py,sha256=abc,5\n'
    assert any('colliding' in i.reason for i in validate_record(files).issues)


def test_multiple_distribution_roots_are_invalid():
    files = wheel_files({'demo.py': b'pass\n'})
    files['other.dist-info/METADATA'] = b'Name: other\n'
    assert validate_record(files).status == 'INVALID'


def test_absent_and_unsupported_record_are_explicit():
    report = analyze(make_zip({'demo.py': b'pass\n'}), make_zip({'demo.py': b'pass\n'}))
    assert report.record_status == 'UNAVAILABLE'
    assert report.analysis_status == 'PARTIAL'
    files = wheel_files({'demo.py': b'pass\n'})
    files[RECORD] = files[RECORD].replace(b'sha256=', b'unimplemented=')
    result = validate_record(files)
    assert result.status == 'UNRESOLVED'
    assert result.checked_files == 0


@pytest.mark.parametrize('algorithm', ['sha384', 'sha512', 'sha3_256', 'blake2b'])
def test_supported_secure_record_digests(algorithm):
    files = wheel_files({'demo.py': b'pass\n'})
    old = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(b'pass\n').digest()).decode().rstrip('=')
    new = algorithm + '=' + base64.urlsafe_b64encode(hashlib.new(algorithm, b'pass\n').digest()).decode().rstrip('=')
    files[RECORD] = files[RECORD].replace(old.encode(), new.encode())
    assert validate_record(files).status == 'VALID'


def test_legacy_signature_exception_does_not_verify_signature():
    files = wheel_files({'demo.py': b'pass\n'})
    files[RECORD + '.jws'] = b'not a verified signature'
    assert validate_record(files).status == 'VALID'
    report = analyze(make_zip(files), make_zip({'demo.py': b'pass\n'}))
    assert report.provenance_status == 'NOT_CHECKED'


@pytest.mark.parametrize('path', ['start.pth', 'sitecustomize.py', 'usercustomize/__init__.py', 'demo-1.0.data/purelib/start.pth'])
def test_new_startup_surface_is_high_priority(path):
    content = b'import demo\n'
    report = scan({'demo.py': b'pass\n', path: content}, {'demo.py': b'pass\n'})
    assert report.record_status == 'VALID'
    assert any(f.rule in ('PTH_EXECUTION', 'CUSTOMIZE_MODULE') and f.severity == 'HIGH' for f in report.findings)


def test_unchanged_startup_hook_is_informational():
    files = {'demo.py': b'pass\n', 'start.pth': b'import demo\n'}
    report = scan(files)
    hooks = [f for f in report.findings if f.rule == 'PTH_EXECUTION']
    assert hooks and all(f.severity == 'INFORMATIONAL' for f in hooks)
    assert any(i.relation == 'PRESENT' for i in report.behavior_indicators)


def test_pth_comments_paths_whitespace_and_nested_files_are_not_startup_claims():
    report = scan({'demo.py': b'pass\n', 'paths.pth': b'# import socket\nimportable\n import socket\n', 'pkg/nested.pth': b'import socket\n'})
    assert not any(i.kind == 'PTH_EXECUTION' for i in report.behavior_indicators)


def test_changed_pth_directive_is_new_even_when_file_was_present():
    report = scan({'demo.py': b'pass\n', 'start.pth': b'import socket\n'}, {'demo.py': b'pass\n', 'start.pth': b'import demo\n'})
    assert any(i.kind == 'PTH_EXECUTION' and i.relation == 'NEW' for i in report.behavior_indicators)
    assert any(i.kind == 'PTH_EXECUTION' and i.relation == 'SOURCE_ONLY' for i in report.behavior_indicators)


@pytest.mark.parametrize(('content', 'kind'), [
    (b'import requests as r\nr.get("https://example.invalid")\n', 'NETWORK_CAPABILITY'),
    (b'from subprocess import run as launch\nlaunch([])\n', 'SUBPROCESS_CAPABILITY'),
    (b'import os as o\no.system("inert")\n', 'SUBPROCESS_CAPABILITY'),
    (b'eval("1+1")\n', 'DYNAMIC_EXECUTION'),
    (b'import importlib as i\ni.import_module("demo")\n', 'DYNAMIC_IMPORT'),
    (b'__import__("demo")\n', 'DYNAMIC_IMPORT'),
])
def test_ast_indicators_and_aliases(content, kind):
    report = scan({'demo.py': content}, {'demo.py': b'pass\n'})
    assert any(i.kind == kind and i.relation == 'NEW' for i in report.behavior_indicators)
    assert any('execution' in i.explanation for i in report.behavior_indicators)


def test_ast_strings_comments_and_relative_imports_do_not_match():
    code = b'# subprocess.run([])\ntext = "eval import requests socket"\nfrom . import socket\nimport os\nos.path.join("a", "b")\n'
    report = scan({'demo.py': code}, {'demo.py': b'pass\n'})
    assert not report.behavior_indicators


def test_line_moves_do_not_create_new_capability():
    report = scan({'demo.py': b'# new comment\nimport socket\n'}, {'demo.py': b'import socket\n'})
    assert all(i.relation == 'PRESENT' for i in report.behavior_indicators)
    assert all(f.severity == 'INFORMATIONAL' for f in report.findings if f.rule == 'NETWORK_CAPABILITY')


def test_binary_and_bytecode_are_unverified():
    report = scan({'demo.py': b'pass\n', 'extra.so': b'\x7fELFfake', 'cache.pyc': b'fake'}, {'demo.py': b'pass\n'})
    assert {i.kind for i in report.behavior_indicators} == {'NATIVE_BINARY', 'BYTECODE'}


@pytest.mark.parametrize('content', [b'not valid Python !!!', b'x = "unterminated', b''.join(f'x{i}={i}\n'.encode() for i in range(20000))])
def test_unparsed_python_is_partial(content):
    report = scan({'demo.py': content})
    assert report.analysis_status == 'PARTIAL'
    assert report.record_status == 'VALID'
    assert any('parser unavailable' in note for note in report.limitations)


def test_unknown_source_parse_does_not_claim_new_capability():
    report = scan({'demo.py': b'import socket\n'}, {'demo.py': b'invalid syntax !!!'})
    assert report.analysis_status == 'PARTIAL'
    assert all(i.relation == 'UNKNOWN' for i in report.behavior_indicators)


def test_parser_and_global_indicator_limits(monkeypatch):
    monkeypatch.setattr('pkgtruth.security.MAX_NODES', 2)
    assert scan({'demo.py': b'x=1\n'}).analysis_status == 'PARTIAL'
    monkeypatch.setattr('pkgtruth.security.MAX_NODES', 20000)
    monkeypatch.setattr('pkgtruth.security.MAX_INDICATORS', 1)
    report = scan({'a.py': b'import socket\n', 'b.py': b'import subprocess\n'})
    assert report.analysis_status == 'PARTIAL'
    assert len(report.behavior_indicators) == 1
    assert any('Global indicator limit' in note for note in report.limitations)


def test_record_parser_limit(monkeypatch):
    monkeypatch.setattr('pkgtruth.security.MAX_PARSE', 10)
    assert validate_record(wheel_files({'demo.py': b'pass\n'})).status == 'UNRESOLVED'


def test_entrypoint_and_dependency_changes():
    source = {'demo.py': b'pass\n', 'pyproject.toml': b'[project]\nname="demo"\nversion="1.0"\ndependencies=["requests>=2"]\n[project.scripts]\ndemo="demo:old"\n'}
    artifact = {'demo.py': b'pass\n', 'demo-1.0.dist-info/METADATA': b'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nRequires-Dist: httpx>=0.28\n',
                'demo-1.0.dist-info/entry_points.txt': b'[console_scripts]\ndemo = demo:new\n'}
    report = scan(artifact, source)
    assert any(c.field == 'dependencies' and c.relation == 'CHANGED' for c in report.metadata_changes)
    assert any(c.field == 'console_scripts' and c.source_values == ['demo = demo:old'] and c.artifact_values == ['demo = demo:new'] for c in report.metadata_changes)
    assert {'DEPENDENCY_CHANGE', 'ENTRY_POINT_CHANGE'} <= {f.rule for f in report.findings}


def test_removed_entrypoints_and_dependencies():
    source = {'demo.py': b'pass\n', 'pyproject.toml': b'[project]\nname="demo"\nversion="1.0"\ndependencies=["requests"]\n[project.scripts]\ndemo="demo:main"\n'}
    report = scan({'demo.py': b'pass\n'}, source)
    assert any(c.field == 'console_scripts' and c.relation == 'CHANGED' and c.artifact_values == [] for c in report.metadata_changes)
    assert any(c.field == 'dependencies' and c.relation == 'CHANGED' and c.artifact_values == [] for c in report.metadata_changes)


def test_static_metadata_matches_without_building():
    source = {'demo.py': b'pass\n', 'pyproject.toml': b'[project]\nname="demo"\nversion="1.0"\ndependencies=[]\n[project.scripts]\ndemo="demo:main"\n'}
    report = scan({'demo.py': b'pass\n', 'demo-1.0.dist-info/entry_points.txt': b'[console_scripts]\ndemo=demo:main\n'}, source)
    assert all(c.relation == 'PRESENT' for c in report.metadata_changes)
    assert all(f.severity == 'INFORMATIONAL' for f in report.findings)
    assert next(d for d in report.file_differences if d.path == 'pyproject.toml').classification == 'packaging_configuration'
    assert not any(f.rule in ('DEPENDENCY_CHANGE', 'ENTRY_POINT_CHANGE') for f in report.findings)


def test_dynamic_or_legacy_project_metadata_is_unknown():
    for declaration in (b'[build-system]\nrequires=[]\n', b'[project]\ndynamic=["dependencies", "scripts", "gui-scripts"]\n'):
        report = scan({'demo.py': b'pass\n'}, {'demo.py': b'pass\n', 'pyproject.toml': declaration})
        assert all(c.relation == 'UNKNOWN' for c in report.metadata_changes)


def test_malformed_metadata_is_partial():
    report = scan({'demo.py': b'pass\n', 'demo-1.0.dist-info/entry_points.txt': b'[console_scripts]\nx=one\nx=two\n'})
    assert report.analysis_status == 'PARTIAL'
    assert any('metadata parser unavailable' in note for note in report.limitations)


def test_arbitrary_code_in_dist_info_is_not_generated_metadata():
    report = scan({'demo.py': b'pass\n', 'demo-1.0.dist-info/unexpected.py': b'import socket\n'}, {'demo.py': b'pass\n'})
    difference = next(d for d in report.file_differences if d.path.endswith('unexpected.py'))
    assert difference.classification == 'unexplained'
    assert any(i.kind == 'NETWORK_CAPABILITY' for i in report.behavior_indicators)


def test_legacy_report_schema_remains_readable():
    report = scan({'demo.py': b'pass\n'}).model_dump()
    report['schema_version'] = '1.0'
    report['record_status'] = 'NOT_CHECKED'
    for field in ('record_check', 'behavior_indicators', 'metadata_changes'):
        del report[field]
    loaded = Report.model_validate(report)
    assert loaded.record_check.status == 'NOT_CHECKED'
    assert not loaded.behavior_indicators


def test_security_ids_references_and_results_are_deterministic():
    payload = {'demo.py': b'import socket\n', 'start.pth': b'import demo\n'}
    one, two = scan(payload, {'demo.py': b'pass\n'}), scan(payload, {'demo.py': b'pass\n'})
    assert one == two
    evidence = {item.id for item in one.evidence}
    assert len(evidence) == len(one.evidence)
    assert len({f.id for f in one.findings}) == len(one.findings)
    for item in [*one.findings, *one.behavior_indicators, *one.metadata_changes]:
        assert set(item.evidence_ids) <= evidence
    assert Report.model_validate_json(one.model_dump_json()) == one


def test_actual_milestone1_report_exports_without_changing_schema():
    original = json.loads((Path(__file__).parent / 'fixtures/milestone1.report.json').read_text())
    report = Report.model_validate(original)
    assert report.schema_version == '1.0'
    assert report.record_status == 'NOT_CHECKED'
    assert report.model_dump(mode='json') == original
    assert json.loads(report.model_dump_json()) == original


def test_optional_empty_record_size_is_unresolved_not_invalid():
    files = wheel_files({'demo.py': b'pass\n'})
    files[RECORD] = files[RECORD].replace(b',5\n', b',\n')
    result = validate_record(files)
    assert result.status == 'UNRESOLVED'
    assert any('No size declared' in issue.reason for issue in result.issues)


def test_record_row_budget_does_not_allege_unread_rows_are_missing(monkeypatch):
    files = wheel_files({'demo.py': b'pass\n', 'other.py': b'pass\n'})
    monkeypatch.setattr('pkgtruth.security.MAX_FILES', 1)
    result = validate_record(files)
    assert result.status == 'UNRESOLVED'
    assert not any('not listed' in issue.reason for issue in result.issues)


def test_record_self_size_is_checked_when_declared():
    files = wheel_files({'demo.py': b'pass\n'})
    original = files[RECORD]
    size = len(original)
    for _ in range(10):
        candidate = original.replace((RECORD + ',,').encode(), (RECORD + ',,' + str(size)).encode())
        if len(candidate) == size:
            break
        size = len(candidate)
    files[RECORD] = candidate
    assert validate_record(files).status == 'VALID'


def test_added_build_script_does_not_get_a_source_omission_exemption():
    report = scan({'demo.py': b'pass\n', 'setup.py': b'eval("1")\n'}, {'demo.py': b'pass\n'})
    assert next(d for d in report.file_differences if d.path == 'setup.py').classification == 'unexplained'
    assert any(f.rule == 'DYNAMIC_EXECUTION' and f.severity == 'MEDIUM' for f in report.findings)
