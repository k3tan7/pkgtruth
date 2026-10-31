from pathlib import Path
import pytest
from pkgtruth.analysis import analyze
from pkgtruth.inputs import InputError
from pkgtruth.models import Report
from conftest import make_zip


def test_clean_is_reproducible_and_validates(package_pair):
    files, wheel = package_pair
    one = analyze(wheel, make_zip(files), artifact_name='demo.whl')
    two = analyze(wheel, make_zip(files), artifact_name='demo.whl')
    assert one == two
    assert one.analysis_status == 'COMPLETE'
    assert one.coverage.identical == 2
    assert not one.findings
    assert one.provenance_status == 'NOT_CHECKED'
    assert one.record_status == 'NOT_CHECKED'
    assert one.policy_decision is None
    assert Report.model_validate_json(one.model_dump_json()) == one


def test_added_removed_modified_and_binary(package_pair):
    files, _ = package_pair
    wheel = make_zip({'demo/__init__.py': b'VALUE = 2\n', 'demo/new.bin': b'\x00\xff'})
    report = analyze(wheel, make_zip(files))
    by_path = {f.path: f for f in report.file_differences}
    assert by_path['demo/__init__.py'].status == 'modified'
    assert '-VALUE = 1' in by_path['demo/__init__.py'].diff
    assert '+VALUE = 2' in by_path['demo/__init__.py'].diff
    assert by_path['demo/util.py'].status == 'removed'
    assert by_path['demo/new.bin'].binary
    assert by_path['demo/new.bin'].status == 'added'
    evidence = {e.id for e in report.evidence}
    assert len(evidence) == len(report.evidence)
    assert all(set(f.evidence_ids) <= evidence for f in report.findings)
    assert all(f.severity == 'MEDIUM' for f in report.findings)


def test_explicit_src_layout_and_exclusions(package_pair, tmp_path):
    files, wheel = package_pair
    archive = {'release/src/' + path: value for path, value in files.items()}
    archive['release/README.md'] = b'Not part of the compared scope'
    zip_report = analyze(wheel, make_zip(archive), source_prefix='release/src')
    for path, value in archive.items():
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)
    directory_report = analyze(wheel, tmp_path, source_prefix='release/src')
    assert zip_report == directory_report
    assert zip_report.coverage.excluded_source_files == 1
    assert zip_report.coverage.identical == 2
    assert zip_report.file_differences[0].source_path.startswith('release/src/')


def test_no_guessed_ambiguous_mapping(package_pair):
    files, wheel = package_pair
    archive = {prefix + path: value for prefix in ['src/', 'other/'] for path, value in files.items()}
    report = analyze(wheel, make_zip(archive))
    assert report.analysis_status == 'PARTIAL'
    assert report.coverage.identical == 0
    selected = analyze(wheel, make_zip(archive), source_prefix='src')
    assert selected.coverage.identical == 2
    with pytest.raises(InputError, match='matches no files'):
        analyze(wheel, make_zip(archive), source_prefix='missing')


def test_metadata_does_not_create_false_security_claim(package_pair):
    files, _ = package_pair
    wheel = make_zip({**files, 'demo-1.0.dist-info/METADATA': b'Name: demo\nVersion: 1.0\n'})
    report = analyze(wheel, make_zip(files))
    assert len(report.findings) == 1
    assert report.findings[0].severity == 'INFORMATIONAL'
    assert report.findings[0].rule == 'PACKAGING_METADATA'
    assert 'not verified' in report.findings[0].explanation


def test_bounded_previews_cover_full_hashes():
    report = analyze(make_zip({'pkg.txt': b'A' * 3000}), make_zip({'pkg.txt': b'B' * 3000}))
    difference = report.file_differences[0]
    assert difference.excerpt_truncated
    assert len(report.evidence[0].source_excerpt) == 2048
    assert len(difference.diff) <= 8192
    assert difference.artifact_sha256 != difference.source_sha256


def test_wheel_data_relocation_is_partial(package_pair):
    files, _ = package_pair
    report = analyze(make_zip({**files, 'demo-1.0.data/purelib/extra.py': b'x=1'}), make_zip(files))
    assert report.analysis_status == 'PARTIAL'


def test_schema_rejects_unknown_fields(package_pair):
    _, wheel = package_pair
    data = analyze(wheel, wheel).model_dump()
    data['invented_trust_score'] = 100
    with pytest.raises(ValueError):
        Report.model_validate(data)


def test_analysis_deadline_is_explicit(package_pair, monkeypatch):
    _, wheel = package_pair
    ticks = iter([0, 31])
    monkeypatch.setattr('pkgtruth.analysis.monotonic', lambda: next(ticks))
    with pytest.raises(InputError, match='Analysis time limit'):
        analyze(wheel, wheel)
