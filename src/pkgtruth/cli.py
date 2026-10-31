"""Non-interactive CLI. Exit 0: no unexplained differences, 1: review, 2: error."""
import argparse
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze
from .inputs import InputError, read_bounded_file
from .models import Report
from .storage import ReportStore


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog='pkgtruth', description='Compare a local wheel with explicitly selected source. Target code is never executed.')
    root.add_argument('--version', action='version', version=__version__)
    commands = root.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('scan', help='Run a static integrity investigation')
    modes = scan.add_subparsers(dest='mode', required=True)
    local = modes.add_parser('local', help='Compare a wheel and source directory or ZIP')
    local.add_argument('--wheel', type=Path, required=True)
    local.add_argument('--source', type=Path, required=True)
    local.add_argument('--source-prefix', default='', help='Exact relative source root, e.g. src or release/src; default: archive/directory root')
    local.add_argument('--json', action='store_true', help='Emit the versioned report JSON to stdout')
    local.add_argument('--ai', action='store_true', help='Request validated local Qwen investigation')
    local.add_argument('--output', type=Path, help='Also save JSON to this file')
    remote = modes.add_parser('pypi', help='Investigate one exact PyPI release; never build source distributions')
    remote.add_argument('--name', required=True)
    remote.add_argument('--version', required=True)
    remote.add_argument('--json', action='store_true')
    remote.add_argument('--ai', action='store_true')
    remote.add_argument('--output', type=Path)
    watch = commands.add_parser('watch', help='Manually check latest-release registry metadata')
    watch.add_argument('--add', metavar='PACKAGE')
    watch.add_argument('--remove', metavar='PACKAGE')
    watch.add_argument('--once', action='store_true')
    watch.add_argument('--scan-new', action='store_true')
    watch.add_argument('--json', action='store_true')
    dna = commands.add_parser('dna', help='Compare two stored scans or two exact PyPI releases')
    dna.add_argument('package', nargs='?')
    dna.add_argument('--previous', required=True, help='Previous scan ID, or exact version with a package name')
    dna.add_argument('--current', required=True, help='Current scan ID, or exact version with a package name')
    dna.add_argument('--json', action='store_true')
    ai = commands.add_parser('investigate', help='Explain a stored scan using pinned local Qwen')
    ai.add_argument('scan_id')
    ai.add_argument('--json', action='store_true')
    report = commands.add_parser('report', help='Export a locally stored report')
    report.add_argument('scan_id')
    report.add_argument('--output', type=Path, required=True)
    report.add_argument('--format', choices=['json','html'], default='json')
    policy = commands.add_parser('policy', help='Evaluate deterministic release adoption checks')
    check = policy.add_subparsers(dest='policy_mode', required=True).add_parser('check')
    check.add_argument('--report', type=Path, required=True)
    check.add_argument('--config', type=Path)
    check.add_argument('--json', action='store_true')
    serve = commands.add_parser('serve', help='Start the single-user loopback web application')
    serve.add_argument('--port', type=int, default=8000)
    return root


def render(report: Report) -> str:
    c = report.coverage
    text = '\n'.join([
        f'pkgtruth · {report.analysis_status} · {report.scan_id}',
        f'Artifact SHA-256: {report.artifact_sha256}',
        f'Files: {c.identical} identical / {c.modified} modified / {c.added} added / {c.removed} removed',
        *[f'[{f.severity}] {f.id} {f.explanation}' for f in report.findings],
        f'RECORD: {report.record_status} (consistency only). Provenance: NOT_CHECKED. AI: {report.model_status}. Policy: {report.policy_decision.decision if report.policy_decision else "NOT_EVALUATED"}.',
        f'Static indicators: {len(report.behavior_indicators)} / metadata comparisons: {len(report.metadata_changes)}',
        *[f'AI (unverified explanation): {a["explanation"]}' for a in report.ai_assessments],
        'Static inspection covers the selected scope only. Matching content does not prove safety.',
    ])
    return ''.join(ch for ch in text if (ord(ch) >= 32 and ord(ch) != 127) or ch in '\n\t')


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'serve':
            if not 1 <= args.port <= 65535:
                raise InputError('Port must be between 1 and 65535')
            import uvicorn
            uvicorn.run('pkgtruth.web:app', host='127.0.0.1', port=args.port)
            return 0
        store = ReportStore()
        if args.command == 'watch':
            from .watch import watch_once
            if args.add: store.add_watch(args.add)
            if args.remove: store.remove_watch(args.remove)
            results=watch_once(store,scan_new=args.scan_new) if args.once else store.watchlist()
            import json
            print(json.dumps(results,indent=2) if args.json else '\n'.join(f"{r['name']}: {r.get('status','WATCHING')}" for r in results) or 'Watchlist is empty.')
            return 1 if any(r.get('status')=='ERROR' or 'scan_error' in r for r in results) else 0
        if args.command == 'policy':
            from .policy import apply_policy, PolicyConfig
            original = Report.model_validate_json(read_bounded_file(args.report))
            config = PolicyConfig.model_validate_json(read_bounded_file(args.config)) if args.config else PolicyConfig()
            result = apply_policy(original, config).policy_decision
            print(result.model_dump_json(indent=2) if args.json else result.decision + '\n' + '\n'.join(r.explanation for r in result.reasons))
            return {'ALLOW':0,'REVIEW':1,'BLOCK':2}[result.decision]
        if args.command == 'dna':
            from .dna import compare_releases
            if args.package:
                from .pypi import scan_pypi
                previous, current = scan_pypi(args.package, args.previous), scan_pypi(args.package, args.current)
                store.save(previous)
            else:
                previous, current = store.get(args.previous), store.get(args.current)
            if previous is None or current is None:
                raise InputError('Both baseline and current reports must exist')
            from .policy import apply_policy
            report = apply_policy(compare_releases(previous, current), store.get_policy())
            store.save(report)
            print(report.model_dump_json(indent=2) if args.json else render(report) + '\n' + '\n'.join(f"DNA {a['severity']}: {a['kind']} {a['path']}" for a in report.historical_anomalies))
            return 1 if report.policy_decision.decision != 'ALLOW' or report.analysis_status != 'COMPLETE' else 0
        if args.command == 'investigate':
            from .investigator import investigate
            original = store.get(args.scan_id)
            if original is None:
                raise InputError('Report not found')
            report = investigate(original)
            store.save(report)
            print(report.model_dump_json(indent=2) if args.json else render(report))
            return 0 if report.model_status == 'VALIDATED' else 1
        if args.command == 'report':
            report = store.get(args.scan_id)
            if report is None:
                raise InputError('Report not found')
            from .capsule import capsule_html
            args.output.write_text(capsule_html(report) if args.format == 'html' else report.model_dump_json(indent=2) + '\n')
            return 0
        if args.mode == 'pypi':
            from .pypi import scan_pypi
            report = scan_pypi(args.name, args.version)
        else:
            source = args.source if args.source.is_dir() else read_bounded_file(args.source)
            report = analyze(read_bounded_file(args.wheel), source, artifact_name=args.wheel.name, source_prefix=args.source_prefix)
        from .policy import apply_policy
        report = apply_policy(report, store.get_policy())
        if args.ai:
            from .investigator import investigate
            report = investigate(report)
        store.save(report)
        serialized = report.model_dump_json(indent=2)
        if args.output:
            args.output.write_text(serialized + '\n')
        print(serialized if args.json else render(report))
        if args.ai and report.model_status != 'VALIDATED':
            return 1
        return 1 if report.analysis_status != 'COMPLETE' or report.policy_decision.decision != 'ALLOW' else 0
    except (InputError, OSError, ValueError, sqlite3.Error) as exc:
        print(f'pkgtruth: {exc}', file=sys.stderr)
        return 3 if args.command == 'policy' else 2


if __name__ == '__main__':
    sys.exit(main())
