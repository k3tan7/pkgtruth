"""Regression tests for beginner-friendly CLI presentation and factual correctness."""
import json
from pathlib import Path
import pytest
from conftest import make_wheel, make_zip
from pkgtruth.analysis import analyze
from pkgtruth.cli import main, render
from pkgtruth.models import Report


def test_cli_executive_summary_at_top_and_key_facts(tmp_path, capsys):
    wheel_data = make_wheel({'demo.py': b'pass\n'})
    source_data = make_zip({'demo.py': b'pass\n'})
    wheel = tmp_path / 'demo.whl'
    source = tmp_path / 'source.zip'
    wheel.write_bytes(wheel_data)
    source.write_bytes(source_data)

    ret = main(['scan', 'local', '--wheel', str(wheel), '--source', str(source)])
    assert ret == 0
    out = capsys.readouterr().out

    # 1. Executive Summary is at the top
    assert 'EXECUTIVE SUMMARY' in out
    summary_pos = out.find('EXECUTIVE SUMMARY')
    key_facts_pos = out.find('KEY FACTS')
    findings_pos = out.find('WHAT WE FOUND')
    assert 0 < summary_pos < key_facts_pos < findings_pos

    # 2. Executive summary contents
    assert 'Verdict:' in out
    assert 'checks completed' in out.lower() or 'no anomalous' in out.lower()

    # 3. Key facts below summary
    assert '• Inspection Status:' in out
    assert 'COMPLETE' in out
    assert '• Matched Files:' in out
    assert '1 identical' in out
    assert '• Wheel Integrity:       RECORD: VALID' in out
    assert '• Policy Recommendation: ALLOW' in out

    # 4. Ordinary packaging differences consolidated
    assert 'ORDINARY PACKAGING DIFFERENCES' in out
    assert 'Unchanged code files: 1 file(s)' in out

    # 5. Next steps and tips
    assert 'RECOMMENDED NEXT STEPS' in out
    assert '--verbose or --details' in out


def test_cli_distinguishes_suspicious_changes_from_ordinary_omissions(tmp_path, capsys):
    # Wheel with startup.pth, plus multiple source files omitted (tests, docs, ci)
    wheel_files = {
        'demo.py': b'pass\n',
        'startup.pth': b'import demo\n',
    }
    source_files = {
        'demo.py': b'pass\n',
        'README.md': b'Documentation',
        'docs/index.md': b'Docs',
        'tests/test_demo.py': b'pass\n',
        '.github/workflows/ci.yml': b'name: ci\n',
        'setup.py': b'pass\n',
    }
    wheel = tmp_path / 'demo.whl'
    source = tmp_path / 'source.zip'
    wheel.write_bytes(make_wheel(wheel_files))
    source.write_bytes(make_zip(source_files))

    ret = main(['scan', 'local', '--wheel', str(wheel), '--source', str(source)])
    assert ret == 1
    out = capsys.readouterr().out

    # Potentially suspicious changes clearly separated
    assert 'POTENTIALLY CONCERNING CHANGES & CAPABILITIES' in out
    assert '[HIGH] Automatic Startup Directive (.pth script)' in out
    assert 'startup file containing executable import statements' in out
    assert 'Why it matters: When installed' in out
    assert 'What to check:' in out

    # Repetitive omissions grouped together instead of dozens of lines
    assert 'ORDINARY PACKAGING DIFFERENCES (CONSOLIDATED)' in out
    assert 'Source-only files omitted: 5 file(s)' in out
    assert 'typical for wheels' in out


def test_zero_modified_files_never_presented_as_content_modifications(tmp_path, capsys):
    """Exact idna 3.10 scenario: 0 modified files, 18 removed files."""
    wheel_files = {'demo.py': b'pass\n'}
    source_files = {'demo.py': b'pass\n'}
    for i in range(18):
        source_files[f'tests/test_{i}.py'] = b'import pytest\n'

    wheel = tmp_path / 'demo.whl'
    source = tmp_path / 'source.zip'
    wheel.write_bytes(make_wheel(wheel_files))
    source.write_bytes(make_zip(source_files))

    ret = main(['scan', 'local', '--wheel', str(wheel), '--source', str(source)])
    assert ret == 1
    out = capsys.readouterr().out

    # 1. Key facts must accurately state 0 modified, 18 removed
    assert '0 modified, 3 added, 18 removed' in out

    # 2. Must NEVER present omitted source files as modified content
    assert 'MODIFIED FILE CONTENT' not in out
    assert 'File Content Differs from Source' not in out
    assert 'Check the modified files' not in out
    assert 'lines were modified' not in out

    # 3. Must correctly describe 18 source-only files omitted
    assert 'Source-only files omitted: 18 file(s)' in out
    assert 'zero modified files' in out

    # 4. Reconciles with actual report coverage
    rep = analyze(make_wheel(wheel_files), make_zip(source_files))
    assert rep.coverage.modified == 0
    assert rep.coverage.removed == 18


def test_cli_verbose_and_details_flags(tmp_path, capsys):
    wheel_data = make_wheel({'demo.py': b'import subprocess\nsubprocess.run([])\n'})
    source_data = make_zip({'demo.py': b'pass\n'})
    wheel = tmp_path / 'demo.whl'
    source = tmp_path / 'source.zip'
    wheel.write_bytes(wheel_data)
    source.write_bytes(source_data)

    # 1. Default (non-verbose): summary format, points to --verbose
    main(['scan', 'local', '--wheel', str(wheel), '--source', str(source)])
    out_default = capsys.readouterr().out
    assert 'COMPLETE TECHNICAL EVIDENCE (--verbose / --details)' not in out_default
    assert '--verbose or --details' in out_default

    # 2. With --verbose flag
    main(['scan', 'local', '--wheel', str(wheel), '--source', str(source), '--verbose'])
    out_verbose = capsys.readouterr().out
    assert 'COMPLETE TECHNICAL EVIDENCE (--verbose / --details)' in out_verbose
    assert 'All Recorded Findings' in out_verbose
    assert 'File Differences Breakdown' in out_verbose
    assert 'Static Behavior Indicators' in out_verbose

    # 3. With --details flag
    main(['scan', 'local', '--wheel', str(wheel), '--source', str(source), '--details'])
    out_details = capsys.readouterr().out
    assert 'COMPLETE TECHNICAL EVIDENCE (--verbose / --details)' in out_details
    assert 'All Recorded Findings' in out_details

    # 4. Short flag -v
    main(['scan', 'local', '--wheel', str(wheel), '--source', str(source), '-v'])
    out_short = capsys.readouterr().out
    assert 'COMPLETE TECHNICAL EVIDENCE (--verbose / --details)' in out_short


def test_cli_partial_scan_explains_specific_reason(tmp_path, capsys):
    # Missing RECORD manifest triggers PARTIAL inspection status
    wheel = tmp_path / 'demo.whl'
    source = tmp_path / 'source.zip'
    wheel.write_bytes(make_zip({'demo.py': b'pass\n'}))
    source.write_bytes(wheel.read_bytes())

    ret = main(['scan', 'local', '--wheel', str(wheel), '--source', str(source)])
    assert ret == 1
    out = capsys.readouterr().out

    # Status must be PARTIAL and clearly explain the specific grounded reason
    assert 'Inspection Status:     PARTIAL' in out
    assert 'Wheel RECORD manifest is absent' in out
    assert 'RECORD: UNAVAILABLE' in out
    assert 'Static inspection covers the selected scope only. Matching content does not prove safety.' in out


def test_cli_json_output_preserves_backward_compatibility(tmp_path, capsys):
    wheel_data = make_wheel({'demo.py': b'pass\n'})
    source_data = make_zip({'demo.py': b'pass\n'})
    wheel = tmp_path / 'demo.whl'
    source = tmp_path / 'source.zip'
    wheel.write_bytes(wheel_data)
    source.write_bytes(source_data)

    ret = main(['scan', 'local', '--wheel', str(wheel), '--source', str(source), '--json'])
    assert ret == 0
    raw_json = capsys.readouterr().out
    data = json.loads(raw_json)
    report = Report.model_validate(data)
    assert report.package_name or report.input_artifact
    assert report.record_status == 'VALID'
    assert report.analysis_status == 'COMPLETE'
