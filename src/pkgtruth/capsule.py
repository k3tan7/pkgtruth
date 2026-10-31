"""Standalone, escaped JSON/HTML Proof Capsules generated from actual reports."""
import html
import json


def capsule_html(report):
    data = report.model_dump(mode='json')
    payload = html.escape(json.dumps(data, ensure_ascii=True, indent=2))
    title = html.escape((report.package_name + ' ' + (report.package_version or '')) if report.package_name else report.input_artifact)
    decision = html.escape(report.policy_decision.decision if report.policy_decision else 'NOT_EVALUATED')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>pkgtruth Proof Capsule · {title}</title><style>body{{font:16px system-ui;margin:3rem auto;padding:0 1rem;max-width:1000px;background:#111817;color:#e4eee6}}code,pre{{overflow-wrap:anywhere;white-space:pre-wrap}}h1{{color:#b8ed85}}details{{border:1px solid #4b5f50;padding:1rem}}p{{line-height:1.7}}</style></head><body><h1>pkgtruth Proof Capsule</h1><h2>{title}</h2><p>Artifact SHA-256: <code>{report.artifact_sha256}</code></p><p>Coverage: {report.analysis_status} · RECORD: {report.record_status} · Provenance: {report.provenance_status} · Release Gate: {decision}</p><p>This evidence report is not signed or tamper-proof. Configured checks, static indicators and AI explanations do not prove safety or execution. Source correspondence may be unverified.</p><h2>Findings</h2><ul>''' + ''.join(f'<li><strong>{html.escape(f.severity)}</strong> {html.escape(f.explanation)} <code>{html.escape(", ".join(f.evidence_ids))}</code></li>' for f in report.findings) + f'''</ul><h2>Coverage limitations</h2><ul>{''.join('<li>'+html.escape(note)+'</li>' for note in report.limitations)}</ul><details open><summary>Complete versioned evidence, DNA, AI and policy JSON</summary><pre>{payload}</pre></details></body></html>'''
