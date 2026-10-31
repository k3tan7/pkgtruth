"""Readable standalone Proof Capsules; every untrusted value is HTML-escaped."""
import html
import json

from .presentation import present_report

_STYLE = '''
:root{color-scheme:light;--ink:#162a2a;--muted:#4c6263;--line:#dbe5e3;--brand:#08796d}
*{box-sizing:border-box}body{margin:0;background:#edf3f1;color:var(--ink);font:16px/1.65 system-ui,sans-serif}
main{max-width:1000px;margin:40px auto;background:white;border:1px solid var(--line);border-radius:18px;overflow:hidden}
header{padding:40px;background:#102f2d;color:#f1fcf8}header p{color:#c1d9d1}.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase}
h1{font-size:38px;line-height:1.2;margin:12px 0}h2{font-size:23px;margin:0 0 15px}h3{font-size:17px;margin:14px 0 7px}
section{padding:28px 40px;border-bottom:1px solid var(--line)}p{margin:8px 0 14px}a{color:var(--brand);text-underline-offset:3px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.stat{padding:16px;background:#f3f7f5;border:1px solid var(--line);border-radius:10px}
.stat span,dt{display:block;color:var(--muted);font-size:13px}.stat strong{display:block;font-size:17px}code{font:13px/1.6 ui-monospace,monospace;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7f6;padding:16px;border-radius:8px;font:12px/1.6 ui-monospace,monospace;max-width:100%}
.badge{display:inline-block;padding:3px 10px;border:1px solid #a5bdb6;border-radius:5px;font-size:12px;font-weight:650}.note{border-left:3px solid #b47c24;padding:8px 16px;background:#fff9ef}
details{margin:10px 0;border:1px solid var(--line);border-radius:8px;padding:12px 16px}summary{cursor:pointer;font-weight:600;overflow-wrap:anywhere}summary:focus-visible,a:focus-visible{outline:3px solid #09877a;outline-offset:4px}
ul,ol{padding-left:24px}li{margin:8px 0}dl{display:grid;grid-template-columns:minmax(120px,1fr) minmax(0,3fr);gap:8px 16px}dd{margin:0;overflow-wrap:anywhere}
.finding{padding:12px 0;border-bottom:1px solid var(--line)}small{color:var(--muted)}.edge{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;margin:12px 0}.node{padding:12px;background:#f3f7f5;border:1px solid var(--line);border-radius:8px;overflow-wrap:anywhere}
footer{padding:24px 40px;color:var(--muted);font-size:13px}@media(max-width:600px){main{margin:0;border:0;border-radius:0}header,section,footer{padding:24px}.grid{grid-template-columns:1fr}h1{font-size:28px}dl{grid-template-columns:1fr}.edge{grid-template-columns:1fr}.arrow{transform:rotate(90deg);justify-self:center}}
@media print{body{background:white}main{margin:0;border:0}header{background:white;color:var(--ink)}header p{color:var(--muted)}section{break-inside:avoid}details{break-inside:auto}a{color:inherit}pre{font-size:10px}.raw{break-before:page}}
'''


def _e(value):
    return html.escape(str(value), quote=True)


def _json(value):
    return _e(json.dumps(value, ensure_ascii=True, indent=2))


def _references(ids):
    return ' '.join(f'<a href="#evidence-{_e(eid)}"><code>{_e(eid)}</code></a>' for eid in ids)


def _section(title, body):
    return f'<section><h2>{_e(title)}</h2>{body}</section>'


def capsule_html(report):
    """Export readable evidence, plus the unchanged machine report for full fidelity."""
    view = present_report(report)
    data = report.model_dump(mode='json')
    chunks = [f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>pkgtruth Proof Capsule · {_e(view['title'])}</title><style>{_STYLE}</style></head><body><main><header><div class="eyebrow">pkgtruth / Proof Capsule</div><h1>{_e(view['title'])}</h1><p>{_e(view['decision_label'])}</p><span class="badge">{_e(view['decision_code'])}</span><p>What you review isn't always what you install.</p></header>''']
    cards = ''.join(f'<div class="stat"><span>{_e(label)}</span><strong>{_e(value)}</strong></div>' for label, value in (
        ('Analysis coverage', view['coverage_label']), ('Wheel integrity', view['record_label']),
        ('Source comparison', view['source_label']), ('Local AI', view['ai_label'])))
    chunks.append(_section('Investigation overview', f'<div class="grid">{cards}</div><p>{_e(view["summary"])}</p><div class="note">Supported checks, matching source and a consistent file list do not prove safety or execution. This report is not signed or tamper-proof. Provenance status: {_e(report.provenance_status)}.</div><h3>Recommended next steps</h3><ol>' + ''.join(f'<li>{_e(step)}</li>' for step in view['next_steps']) + '</ol>'))
    retrieval = report.retrieval
    source = f'<dl><dt>Claimed repository</dt><dd><code>{_e(retrieval.get("claimed_repository") or "No repository identified")}</code></dd><dt>Resolved commit</dt><dd><code>{_e(report.source_commit or "Not resolved")}</code></dd><dt>Source selection</dt><dd>{_e(report.source_resolution)}</dd><dt>Provenance</dt><dd>{_e(report.provenance_status)}</dd></dl>'
    if retrieval:
        source += '<dl>' + ''.join(f'<dt>{_e(label)}</dt><dd>{_e(value)}</dd>' for label, value in (
            ('Metadata field', ', '.join(retrieval.get('claimed_repository_fields', [])) or 'Not recorded'),
            ('Selected release tag', retrieval.get('source_tag') or 'Not resolved'),
            ('Source retrieved', 'Yes' if retrieval.get('source_retrieved') else 'No / not recorded'),
            ('Source comparison', 'Performed within the reported coverage' if retrieval.get('source_comparison_performed') else 'Not completed / not recorded'),
        )) + '</dl>'
        source += ''.join(f'<p>{_e(note)}</p>' for note in retrieval.get('source_discovery_notes', []))
    source += '<p>A publisher-supplied repository or matching release tag helps compare code; it does not independently prove that the repository produced this package.</p>'
    if retrieval:
        source += f'<details><summary>Source discovery and retrieval details</summary><pre>{_json(retrieval)}</pre></details>'
    chunks.append(_section('Source discovery', source))
    changes = ''
    for group in view['file_groups']:
        if not group['count']:
            continue
        files = ''
        for file in group['files']:
            files += f'<details><summary>{_e(file.path)} · {_e(file.status)}</summary><p>{_references([file.evidence_id])}</p><dl><dt>Source SHA-256</dt><dd><code>{_e(file.source_sha256 or "Absent")}</code></dd><dt>Artifact SHA-256</dt><dd><code>{_e(file.artifact_sha256 or "Absent")}</code></dd></dl>'
            if file.diff:
                files += f'<pre>{_e(file.diff)}</pre>'
            elif file.binary:
                files += '<p>Binary content; compare hashes. No text preview is available.</p>'
            elif file.status == 'identical':
                files += '<p>Inspected bytes are identical.</p>'
            if file.excerpt_truncated:
                files += '<p>Text preview truncated; hashes cover full inspected bytes.</p>'
            files += '</details>'
        changes += f'<h3>{_e(group["title"])} · {group["count"]}</h3><p>{_e(group["description"])}</p>{files}'
    chunks.append(_section('What changed?', changes or '<p>No file comparisons were recorded.</p>'))
    findings = ''
    for group in view['finding_groups']:
        items = ''.join(f'<article class="finding"><span class="badge">{_e(f.severity)}</span><p>{_e(f.explanation)}</p><small>Rule: {_e(f.rule)} · {_e(f.id)}</small><p>{_references(f.evidence_ids)}</p></article>' for f in group['findings'])
        findings += f'<details><summary>{_e(group["title"])} · {group["count"]} findings</summary><p>{_e(group["description"])}</p>{items}</details>'
    chunks.append(_section('Security findings', findings or '<p>No supported findings recorded. This does not establish safety.</p>'))
    ai = f'<p>{_e(view["ai_label"])}. AI interprets selected evidence; it cannot alter deterministic findings or policy. Its statements remain unverified.</p>'
    for item in report.ai_assessments:
        ai += f'<h3>{_e(item.get("explanation", ""))}</h3><dl>'
        for key, label in (('legitimate_explanation', 'Legitimate alternative'), ('security_concern', 'Security concern'), ('uncertainty', 'Uncertainty')):
            ai += f'<dt>{label}</dt><dd>{_e(item.get(key, ""))}</dd>'
        ai += '</dl><h3>Suggested checks</h3><ul>' + ''.join(f'<li>{_e(check)}</li>' for check in item.get('next_checks', [])) + '</ul>' + _references(item.get('evidence_ids', []))
    if report.model_details:
        ai += f'<details><summary>Model, runtime and validation details</summary><pre>{_json(report.model_details)}</pre></details>'
    chunks.append(_section('AI explanation', ai))
    dna = '<p>First observed means relative to the selected baseline. This is deterministic comparison, not trained machine learning or a runtime trace.</p>'
    if report.dna_baseline:
        dna += f'<div class="grid"><div class="stat"><span>Selected baseline</span><strong>{_e(report.dna_baseline.get("package_version") or report.dna_baseline.get("scan_id", "Unknown"))}</strong></div><div class="stat"><span>Current artifact</span><strong>{_e(report.package_version or report.scan_id)}</strong></div></div>'
        dna += f'<p>{_e(report.dna_baseline.get("direction_explanation", "Comparison direction follows the selected baseline and current artifact."))}</p><p>{len(report.historical_anomalies)} recorded historical changes.</p><details><summary>Exact comparison identities and coverage</summary><pre>{_json(report.dna_baseline)}</pre></details>'
        for item in report.historical_anomalies:
            dna += f'<details><summary>{_e(item.get("kind", "Change"))} · {_e(item.get("path", ""))}</summary><p>{_e(item.get("explanation", ""))}</p><pre>{_json({"baseline": item.get("previous"), "current": item.get("current")})}</pre>{_references(item.get("evidence_ids", []))}</details>'
        if not report.historical_anomalies:
            dna += '<p>No supported historical changes were observed in this comparison.</p>'
    else:
        dna += '<p>No historical comparison has been run for this report.</p>'
    chunks.append(_section('Release DNA', dna))
    impact = '<p>Conditional static relationships do not establish actual execution. Each relationship comes from recorded evidence.</p>'
    for edge in report.impact_relationships:
        impact += f'<div class="edge"><div class="node">{_e(edge.get("origin", ""))}</div><span class="arrow" aria-hidden="true">→</span><div class="node">{_e(edge.get("target", ""))}</div></div><p>{_e(edge.get("relationship", ""))}</p><p>{_references(edge.get("evidence_ids", []))}</p>'
    if not report.impact_relationships:
        impact += '<p>No supported relationships were identified.</p>'
    if report.impact_truncated:
        impact += '<p>The relationship preview reached its edge limit.</p>'
    chunks.append(_section('Install Impact Preview', impact))
    policy = f'<p>{_e(view["decision_label"])}. ALLOW describes configured checks only and never guarantees safety.</p>'
    if report.policy_decision:
        for reason in report.policy_decision.reasons:
            policy += f'<h3>{_e(reason.rule.replace("_", " ").capitalize())}</h3><p>{_e(reason.explanation)}</p>{_references(reason.evidence_ids)}'
        policy += f'<details><summary>Exact rules used</summary><pre>{_json(report.policy_decision.config)}</pre></details><p>{_e(report.policy_decision.limitation)}</p>'
    chunks.append(_section('Release Gate recommendation', policy))
    evidence = f'<dl><dt>Scan ID</dt><dd><code>{_e(report.scan_id)}</code></dd><dt>Artifact SHA-256</dt><dd><code>{_e(report.artifact_sha256)}</code></dd><dt>Source tree SHA-256</dt><dd><code>{_e(report.source_tree_sha256)}</code></dd><dt>Tool / rules / schema</dt><dd>{_e(report.tool_version)} / {_e(report.rule_version)} / {_e(report.schema_version)}</dd></dl>'
    for item in report.evidence:
        evidence += f'<details id="evidence-{_e(item.id)}"><summary>{_e(item.id)} · {_e(item.path)}</summary><p>{_e(item.description)}</p>'
        if item.source_excerpt is not None:
            evidence += f'<h3>Source or baseline excerpt</h3><pre>{_e(item.source_excerpt)}</pre>'
        if item.artifact_excerpt is not None:
            evidence += f'<h3>Artifact or current excerpt</h3><pre>{_e(item.artifact_excerpt)}</pre>'
        evidence += '</details>'
    chunks.append(_section('Technical evidence', evidence))
    chunks.append(_section('Coverage and limitations', f'<pre>{_json(report.coverage.model_dump())}</pre><ul>' + ''.join(f'<li>{_e(note)}</li>' for note in report.limitations) + '</ul>'))
    chunks.append(f'<section class="raw"><h2>Complete structured report</h2><details><summary>Versioned JSON with all recorded evidence</summary><pre>{_json(data)}</pre></details></section><footer>pkgtruth · Evidence for a human decision. Source correspondence, static inspection and AI do not establish package safety.</footer></main></body></html>')
    return ''.join(chunks)
