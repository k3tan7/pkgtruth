"""Non-interactive CLI. Exit 0: no unexplained differences, 1: review, 2: error."""

import argparse
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze
from .inputs import InputError, read_bounded_file
from .models import Report
from .presentation import partial_coverage_reason, present_report
from .storage import ReportStore


def parser() -> argparse.ArgumentParser:
    common_options = argparse.ArgumentParser(add_help=False)
    common_options.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed technical findings and per-file evidence",
    )
    common_options.add_argument(
        "--details",
        action="store_true",
        help="Show detailed technical findings and per-file evidence",
    )

    root = argparse.ArgumentParser(
        prog="pkgtruth",
        description="Compare a local wheel with explicitly selected source. Target code is never executed.",
        parents=[common_options],
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)

    scan = commands.add_parser(
        "scan", help="Run a static integrity investigation", parents=[common_options]
    )
    modes = scan.add_subparsers(dest="mode", required=True)

    local = modes.add_parser(
        "local",
        help="Compare a wheel and source directory or ZIP",
        parents=[common_options],
    )
    local.add_argument("--wheel", type=Path, required=True)
    local.add_argument("--source", type=Path, required=True)
    local.add_argument(
        "--source-prefix",
        default="",
        help="Exact relative source root, e.g. src or release/src; default: archive/directory root",
    )
    local.add_argument(
        "--json", action="store_true", help="Emit the versioned report JSON to stdout"
    )
    local.add_argument(
        "--ai", action="store_true", help="Request validated local Qwen investigation"
    )
    local.add_argument("--output", type=Path, help="Also save JSON to this file")

    remote = modes.add_parser(
        "pypi",
        help="Investigate one exact PyPI release; never build source distributions",
        parents=[common_options],
    )
    remote.add_argument("--name", required=True)
    remote.add_argument("--version", required=True)
    remote.add_argument("--json", action="store_true")
    remote.add_argument("--ai", action="store_true")
    remote.add_argument("--output", type=Path)

    watch = commands.add_parser(
        "watch", help="Manually check latest-release registry metadata"
    )
    watch.add_argument("--add", metavar="PACKAGE")
    watch.add_argument("--remove", metavar="PACKAGE")
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--scan-new", action="store_true")
    watch.add_argument("--json", action="store_true")

    dna = commands.add_parser(
        "dna",
        help="Compare two stored scans or two exact PyPI releases",
        parents=[common_options],
    )
    dna.add_argument("package", nargs="?")
    dna.add_argument(
        "--previous",
        required=True,
        help="Previous scan ID, or exact version with a package name",
    )
    dna.add_argument(
        "--current",
        required=True,
        help="Current scan ID, or exact version with a package name",
    )
    dna.add_argument("--json", action="store_true")

    ai = commands.add_parser(
        "investigate",
        help="Explain a stored scan using pinned local Qwen",
        parents=[common_options],
    )
    ai.add_argument("scan_id")
    ai.add_argument("--json", action="store_true")

    report = commands.add_parser("report", help="Export a locally stored report")
    report.add_argument("scan_id")
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--format", choices=["json", "html"], default="json")

    policy = commands.add_parser(
        "policy", help="Evaluate deterministic release adoption checks"
    )
    check = policy.add_subparsers(dest="policy_mode", required=True).add_parser("check")
    check.add_argument("--report", type=Path, required=True)
    check.add_argument("--config", type=Path)
    check.add_argument("--json", action="store_true")

    serve = commands.add_parser(
        "serve", help="Start the single-user loopback web application"
    )
    serve.add_argument("--port", type=int, default=8000)

    return root


def render(report: Report, verbose: bool = False) -> str:
    """Render plain-language CLI report.

    Layer 1: 5-second executive summary at top.
    Layer 2: Key facts and consolidated findings distinguishing suspicious vs ordinary.
    Layer 3: Full technical details when --verbose or --details is requested.
    """
    view = present_report(report)
    ex = view["executive_summary"]
    c = report.coverage

    if report.analysis_status == "PARTIAL":
        status_str = "PARTIAL (Some files could not be fully analyzed)"
    else:
        status_str = f"{report.analysis_status} ({view['coverage_label']})"
    lines = [
        "=" * 80,
        "pkgtruth · PACKAGE ANALYSIS REPORT",
        f"Target: {view['title']}",
        f"Scan ID: {report.scan_id} · Artifact SHA-256: {report.artifact_sha256}",
        "=" * 80,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 80,
        f"Verdict: {ex['headline']} [{view['decision_code']}]",
        "",
        ex["explanation"],
        "",
        "KEY FACTS",
        "-" * 80,
        f"• Inspection Status:     {status_str}",
        f"• Matched Files:         {c.identical} identical / {c.compared_files} compared ({c.artifact_files} in package)",
        f"• File Differences:      {c.modified} modified, {c.added} added, {c.removed} removed",
        f"• Wheel Integrity:       RECORD: {report.record_status} ({view['record_label']})",
        f"• Source Verification:   {view['source_label']}",
        f"• Provenance:            {report.provenance_status or 'NOT_CHECKED'}",
                f'• Policy Recommendation: {view["decision_code"]} ({view["decision_label"]})',
        '',
    ]

    # Preserve the exact reason without cluttering the executive summary.
    if report.analysis_status == 'PARTIAL':
        reason = partial_coverage_reason(report)
        lines.extend([
            'INSPECTION LIMITATIONS',
            '-' * 80,
            reason or 'Some inspection checks could not be completed',
            '',
        ])

    lines.extend([
        'WHAT WE FOUND',
        '-' * 80,
    ])

    all_translated = view.get("translated_findings", [])

    # Differentiate 5 categories based on actual structured data
    security_items = [
        tf
        for tf in all_translated
        if tf.get("category") in ("security_indicator", "integrity")
    ]
    modified_items = [tf for tf in all_translated if tf.get("category") == "modified"]
    artifact_items = [
        tf for tf in all_translated if tf.get("category") == "artifact_only"
    ]
    metadata_items = [
        tf for tf in all_translated if tf.get("category") == "metadata_change"
    ]

    has_notable = False

    # 1. True Security Indicators
    if security_items:
        has_notable = True
        lines.append("POTENTIALLY CONCERNING CHANGES & CAPABILITIES")
        for item in security_items:
            lines.append(f"  • [{item['severity']}] {item['title']} ({item['rule']})")
            lines.append(f"    - What happened: {item['what_happened']}")
            lines.append(f"    - Why it matters: {item['why_it_matters']}")
            lines.append(f"    - What to check:  {item['what_to_check']}")
            lines.append(f"    - Reference ID:   {item['id']}")
        lines.append("")

    # 2. Modified Content (strictly when c.modified > 0)
    if modified_items and c.modified > 0:
        has_notable = True
        lines.append("MODIFIED FILE CONTENT")
        lines.append(
            f"  • {len(modified_items)} file(s) differ in byte content between source and package:"
        )
        for item in modified_items:
            lines.append(f"    - [{item['severity']}] {item['path']}")
            lines.append(f"      What happened: {item['what_happened']}")
            lines.append(f"      Action:        {item['what_to_check']}")
        lines.append("")

    # 3. Artifact-Only Additions (strictly when c.added > 0 and not metadata)
    if artifact_items and c.added > 0:
        has_notable = True
        lines.append("ARTIFACT-ONLY ADDITIONS (PRESENT IN WHEEL, ABSENT IN SOURCE)")
        lines.append(
            f"  • {len(artifact_items)} file(s) added to published package that were not in compared source:"
        )
        for item in artifact_items:
            lines.append(f"    - [{item['severity']}] {item['path']}")
            lines.append(f"      What happened: {item['what_happened']}")
            lines.append(f"      Action:        {item['what_to_check']}")
        lines.append("")

    # 4. Declared Metadata & Configuration Changes
    if metadata_items:
        has_notable = True
        lines.append("DECLARED METADATA & CONFIGURATION CHANGES")
        for item in metadata_items:
            lines.append(f"  • [{item['severity']}] {item['title']}")
            lines.append(f"    - Details: {item['original_explanation']}")
        lines.append("")

    # 5. Consolidated Ordinary Packaging Differences (Reconciled with report counts)
    lines.append("ORDINARY PACKAGING DIFFERENCES (CONSOLIDATED)")
    ordinary_count = 0
    if c.removed > 0:
        lines.append(
            f"  • Source-only files omitted: {c.removed} file(s) (documentation, tests, or CI files omitted from package wheel — typical for wheels)"
        )
        ordinary_count += 1

    generated_count = sum(
        1 for d in report.file_differences if d.classification == "packaging_metadata"
    )
    if generated_count > 0:
        lines.append(
            f"  • Generated packaging metadata: {generated_count} file(s) (.dist-info metadata synthesized during build)"
        )
        ordinary_count += 1

    config_count = sum(
        1
        for d in report.file_differences
        if d.classification == "packaging_configuration"
    )
    if config_count > 0:
        lines.append(
            f"  • Packaging configuration declarations: {config_count} file(s) differ from source"
        )
        ordinary_count += 1

    if c.identical > 0:
        lines.append(
            f"  • Unchanged code files: {c.identical} file(s) match source baseline byte-for-byte"
        )
        ordinary_count += 1

    if ordinary_count == 0 and not has_notable:
        lines.append(
            "  • No file differences or anomalous indicators detected in the compared scope."
        )

    lines.append("")
    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("-" * 80)
    for idx, step in enumerate(view["next_steps"], 1):
        lines.append(f"{idx}. {step}")

    if report.ai_assessments:
        lines.append("")
        lines.append("LOCAL AI INVESTIGATOR (UNVERIFIED)")
        lines.append("-" * 80)
        for a in report.ai_assessments:
            lines.append(f"• AI (unverified explanation): {a.get('explanation', '')}")
            if a.get("legitimate_explanation"):
                lines.append(
                    f"  Legitimate alternative: {a.get('legitimate_explanation')}"
                )
            if a.get("security_concern"):
                lines.append(f"  Security concern:       {a.get('security_concern')}")
            if a.get("next_checks"):
                lines.append(f"  Suggested checks:       {', '.join(a['next_checks'])}")

    if verbose:
        lines.append("")
        lines.append("=" * 80)
        lines.append("COMPLETE TECHNICAL EVIDENCE (--verbose / --details)")
        lines.append("=" * 80)

        lines.append(f"All Recorded Findings ({len(report.findings)} total):")
        for f in report.findings:
            lines.append(f"• [{f.severity}] {f.id} {f.rule}: {f.explanation}")
            if f.evidence_ids:
                lines.append(f"  Evidence IDs: {', '.join(f.evidence_ids)}")
        lines.append("")

        lines.append(
            f"File Differences Breakdown ({len(report.file_differences)} total):"
        )
        for fd in report.file_differences:
            lines.append(
                f"• [{fd.status.upper()}] {fd.path} (Classification: {fd.classification})"
            )
            lines.append(
                f"  Source SHA-256:   {fd.source_sha256 or 'Absent (not in source)'}"
            )
            lines.append(
                f"  Artifact SHA-256: {fd.artifact_sha256 or 'Absent (not in wheel)'}"
            )
            if fd.diff:
                snippet = "\n    ".join(fd.diff.strip().splitlines()[:12])
                lines.append(f"  Diff excerpt:\n    {snippet}")
        lines.append("")

        lines.append(
            f"Static Behavior Indicators ({len(report.behavior_indicators)} total):"
        )
        for ind in report.behavior_indicators:
            lines.append(
                f"• [{ind.relation}] {ind.kind} at {ind.path}:{ind.line}: {ind.symbol}"
            )
            lines.append(f"  {ind.explanation}")
        lines.append("")

        lines.append(
            f"Distribution Metadata Declarations ({len(report.metadata_changes)} total):"
        )
        for mc in report.metadata_changes:
            lines.append(f"• [{mc.relation}] {mc.field} in {mc.path}")
            if mc.source_values is not None:
                lines.append(f"  Source values:   {mc.source_values}")
            lines.append(f"  Artifact values: {mc.artifact_values}")
        lines.append("")

        if report.record_check.issues:
            lines.append(
                f"Wheel RECORD Issues ({len(report.record_check.issues)} total):"
            )
            for iss in report.record_check.issues:
                lines.append(f"• {iss.path or '(wheel)'}: {iss.reason}")
            lines.append("")

        if report.limitations:
            lines.append("Inspection Boundaries & Limitations:")
            for lim in report.limitations:
                lines.append(f"• {lim}")
            lines.append("")
    else:
        lines.append("")
        lines.append("-" * 80)
        lines.append(
            "Tip: Run with --verbose or --details to view complete technical evidence, individual finding IDs, diffs, and exact SHA-256 hashes."
        )

    lines.append("=" * 80)
    lines.append(
        "Static inspection covers the selected scope only. Matching content does not prove safety."
    )

    text = "\n".join(lines)
    return "".join(
        ch for ch in text if (ord(ch) >= 32 and ord(ch) != 127) or ch in "\n\t"
    )


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    args = parser().parse_args(args_list)
    verbose = bool(
        getattr(args, "verbose", False)
        or getattr(args, "details", False)
        or any(a in args_list for a in ("--verbose", "-v", "--details"))
    )

    try:
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise InputError("Port must be between 1 and 65535")
            import uvicorn

            uvicorn.run("pkgtruth.web:app", host="127.0.0.1", port=args.port)
            return 0

        store = ReportStore()

        if args.command == "watch":
            from .watch import watch_once

            if args.add:
                store.add_watch(args.add)
            if args.remove:
                store.remove_watch(args.remove)
            results = (
                watch_once(store, scan_new=args.scan_new)
                if args.once
                else store.watchlist()
            )
            import json

            print(
                json.dumps(results, indent=2)
                if args.json
                else "\n".join(
                    f"{r['name']}: {r.get('status', 'WATCHING')}" for r in results
                )
                or "Watchlist is empty."
            )
            return (
                1
                if any(r.get("status") == "ERROR" or "scan_error" in r for r in results)
                else 0
            )

        if args.command == "policy":
            from .policy import PolicyConfig, apply_policy

            original = Report.model_validate_json(read_bounded_file(args.report))
            config = (
                PolicyConfig.model_validate_json(read_bounded_file(args.config))
                if args.config
                else PolicyConfig()
            )
            result = apply_policy(original, config).policy_decision
            print(
                result.model_dump_json(indent=2)
                if args.json
                else result.decision
                + "\n"
                + "\n".join(r.explanation for r in result.reasons)
            )
            return {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}[result.decision]

        if args.command == "dna":
            from .dna import compare_releases

            if args.package:
                from .pypi import scan_pypi

                previous, current = (
                    scan_pypi(args.package, args.previous),
                    scan_pypi(args.package, args.current),
                )
                store.save(previous)
            else:
                previous, current = store.get(args.previous), store.get(args.current)
            if previous is None or current is None:
                raise InputError("Both baseline and current reports must exist")
            from .policy import apply_policy

            report = apply_policy(
                compare_releases(previous, current), store.get_policy()
            )
            store.save(report)
            print(
                report.model_dump_json(indent=2)
                if args.json
                else render(report, verbose=verbose)
                + "\n"
                + "\n".join(
                    f"DNA {a['severity']}: {a['kind']} {a['path']}"
                    for a in report.historical_anomalies
                )
            )
            return (
                1
                if report.policy_decision.decision != "ALLOW"
                or report.analysis_status != "COMPLETE"
                else 0
            )

        if args.command == "investigate":
            from .investigator import investigate

            original = store.get(args.scan_id)
            if original is None:
                raise InputError("Report not found")
            report = investigate(original)
            store.save(report)
            print(
                report.model_dump_json(indent=2)
                if args.json
                else render(report, verbose=verbose)
            )
            return 0 if report.model_status == "VALIDATED" else 1

        if args.command == "report":
            report = store.get(args.scan_id)
            if report is None:
                raise InputError("Report not found")
            from .capsule import capsule_html

            args.output.write_text(
                capsule_html(report)
                if args.format == "html"
                else report.model_dump_json(indent=2) + "\n"
            )
            return 0

        if args.mode == "pypi":
            from .pypi import scan_pypi

            report = scan_pypi(args.name, args.version)
        else:
            source = (
                args.source if args.source.is_dir() else read_bounded_file(args.source)
            )
            report = analyze(
                read_bounded_file(args.wheel),
                source,
                artifact_name=args.wheel.name,
                source_prefix=args.source_prefix,
            )

        from .policy import apply_policy

        report = apply_policy(report, store.get_policy())
        if args.ai:
            from .investigator import investigate

            report = investigate(report)
        store.save(report)
        serialized = report.model_dump_json(indent=2)
        if args.output:
            args.output.write_text(serialized + "\n")
        print(serialized if args.json else render(report, verbose=verbose))
        if args.ai and report.model_status != "VALIDATED":
            return 1
        return (
            1
            if report.analysis_status != "COMPLETE"
            or report.policy_decision.decision != "ALLOW"
            else 0
        )
    except (InputError, OSError, ValueError, sqlite3.Error) as exc:
        print(f"pkgtruth: {exc}", file=sys.stderr)
        return 3 if args.command == "policy" else 2


if __name__ == "__main__":
    sys.exit(main())
