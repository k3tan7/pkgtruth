import html
import json
from pkgtruth.analysis import analyze
from pkgtruth.capsule import capsule_html
from pkgtruth.presentation import present_report
from conftest import make_wheel, make_zip


def test_grouped_omissions_preserve_every_finding_policy_and_evidence():
    source = {'demo.py': b'pass\n', 'README.md': b'Documentation', 'docs/guide.rst': b'Guide',
              'tests/test_demo.py': b'pass\n', '.github/workflows/ci.yml': b'name: checks\n', 'setup.py': b'pass\n'}
    report = analyze(make_wheel({'demo.py': b'pass\n'}), make_zip(source))
    original = report.model_dump_json()
    view = present_report(report)
    omissions = next(group for group in view['file_groups'] if group['id'] == 'source_only')
    assert len(omissions['files']) == 5
    assert 'commonly omitted' in omissions['description'] and 'original finding severities' in omissions['description']
    all_files = [file for group in view['file_groups'] for file in group['files']]
    all_findings = [finding for group in view['finding_groups'] for finding in group['findings']]
    assert sorted(f.path for f in all_files) == sorted(f.path for f in report.file_differences)
    assert sorted(f.id for f in all_findings) == sorted(f.id for f in report.findings)
    assert all(f in report.findings for f in all_findings)
    assert report.model_dump_json() == original
    assert view['decision_code'] == report.policy_decision.decision == 'REVIEW'
    assert view['counts']['medium'] == sum(f.severity == 'MEDIUM' for f in report.findings)


def test_added_executable_content_cannot_hide_in_documentation_or_metadata():
    files = {'demo.py': b'pass\n', '.github/eval.py': b'import subprocess\n',
             'docs/readme.py': b'import socket\n', 'README.py': b'pass\n',
             'demo-1.0.dist-info/extra.py': b'pass\n'}
    report = analyze(make_wheel(files), make_zip({'demo.py': b'pass\n'}))
    view = present_report(report)
    executable = next(group for group in view['file_groups'] if group['id'] == 'executable')
    assert {f.path for f in executable['files']} == set(files) - {'demo.py'}
    omissions = next(group for group in view['file_groups'] if group['id'] == 'source_only')
    assert not omissions['files']
    assert any(f.rule == 'NETWORK_CAPABILITY' for f in report.findings)


def test_artifact_only_has_no_implied_source_difference_and_ai_states_are_distinct():
    report = analyze(make_wheel({'demo.py': b'pass\n'}), None)
    view = present_report(report)
    assert len(next(g for g in view['file_groups'] if g['id'] == 'unresolved')['files']) == len(report.file_differences)
    assert view['coverage_label'] == 'Some checks could not be completed'
    assert view['ai_label'] == 'AI has not been run for this report'
    report.model_status = 'UNAVAILABLE'
    assert present_report(report)['ai_label'] == 'AI was unavailable at the last attempt'


def test_capsule_sections_and_full_json_are_escaped_and_complete():
    report = analyze(make_wheel({'demo.py': b'x = "<img src=x onerror=alert(1)>"\n'}), make_zip({'demo.py': b'pass\n'}))
    report.retrieval = {'claimed_repository': 'javascript:alert(1)', 'claimed_repository_fields': ['project_urls.Source'],
                        'source_tag': '<svg/onload=alert(1)>', 'source_retrieved': True, 'source_comparison_performed': False}
    report.ai_assessments = [{'explanation': '<script>alert(1)</script>', 'legitimate_explanation': 'test',
                             'security_concern': 'test', 'uncertainty': 'unknown', 'next_checks': ['Review'],
                             'evidence_ids': [report.evidence[0].id]}]
    document = capsule_html(report)
    assert '<script>' not in document and '<img src=x' not in document and '<svg/onload' not in document
    assert 'href="javascript:' not in document
    assert '&lt;script&gt;' in document
    for title in ('Investigation overview', 'Source discovery', 'What changed?', 'Security findings',
                  'AI explanation', 'Release DNA', 'Install Impact Preview', 'Release Gate recommendation',
                  'Technical evidence', 'Coverage and limitations', 'Complete structured report'):
        assert title in document
    encoded = html.escape(json.dumps(report.model_dump(mode='json'), ensure_ascii=True, indent=2))
    assert encoded in document
    assert report.artifact_sha256 in document
    assert all(f'id="evidence-{e.id}"' in document for e in report.evidence)
    assert 'project_urls.Source' in document and 'Source comparison' in document


def test_executive_summary_and_three_layer_presentation():
    clean = analyze(make_wheel({'demo.py': b'pass\n'}), make_zip({'demo.py': b'pass\n'}))
    view_clean = present_report(clean)
    assert 'executive_summary' in view_clean
    assert view_clean['executive_summary']['tone'] in ('success', 'neutral')
    assert 'completed' in view_clean['executive_summary']['headline'].lower()
    assert len(view_clean['executive_summary']['facts']) == 4

    tampered = analyze(make_wheel({'demo.py': b'pass\n', 'startup.pth': b'import demo\n'}), make_zip({'demo.py': b'pass\n'}))
    view_tampered = present_report(tampered)
    assert view_tampered['executive_summary']['tone'] in ('danger', 'warn')
    assert any(f['rule'] == 'PTH_EXECUTION' for f in view_tampered['translated_findings'])
    pth_finding = next(f for f in view_tampered['translated_findings'] if f['rule'] == 'PTH_EXECUTION')
    assert 'Startup Directive' in pth_finding['title']
    assert pth_finding['what_happened'] and pth_finding['why_it_matters'] and pth_finding['what_to_check']
