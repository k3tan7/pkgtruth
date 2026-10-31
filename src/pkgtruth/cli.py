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
    local.add_argument('--output', type=Path, help='Also save JSON to this file')
    report = commands.add_parser('report', help='Export a locally stored report')
    report.add_argument('scan_id')
    report.add_argument('--output', type=Path, required=True)
    serve = commands.add_parser('serve', help='Start the single-user loopback web application')
    serve.add_argument('--port', type=int, default=8000)
    return root


def render(report: Report) -> str:
    c = report.coverage
    return '\n'.join([
        f'pkgtruth · {report.analysis_status} · {report.scan_id}',
        f'Artifact SHA-256: {report.artifact_sha256}',
        f'Files: {c.identical} identical / {c.modified} modified / {c.added} added / {c.removed} removed',
        *[f'[{f.severity}] {f.id} {f.explanation}' for f in report.findings],
        'Provenance / RECORD: NOT_CHECKED. AI: NOT_CONFIGURED. Policy: not evaluated.',
        'Byte comparison covers the selected scope only. Matching content does not prove safety.',
    ])


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
        if args.command == 'report':
            report = store.get(args.scan_id)
            if report is None:
                raise InputError('Report not found')
            args.output.write_text(report.model_dump_json(indent=2) + '\n')
            return 0
        source = args.source if args.source.is_dir() else read_bounded_file(args.source)
        report = analyze(read_bounded_file(args.wheel), source, artifact_name=args.wheel.name, source_prefix=args.source_prefix)
        store.save(report)
        serialized = report.model_dump_json(indent=2)
        if args.output:
            args.output.write_text(serialized + '\n')
        print(serialized if args.json else render(report))
        return 1 if report.analysis_status != 'COMPLETE' or any(f.severity != 'INFORMATIONAL' for f in report.findings) else 0
    except (InputError, OSError, ValueError, sqlite3.Error) as exc:
        print(f'pkgtruth: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
