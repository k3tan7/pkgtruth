"""Plain-language report views. Presentation grouping never changes analysis or policy."""

from pathlib import PurePosixPath

DECISION_LABELS = {
    "ALLOW": "Allowed under your configured rules",
    "REVIEW": "Needs human review",
    "BLOCK": "Blocked by your configured rules",
    "NOT_EVALUATED": "Rules have not been evaluated",
}
COVERAGE_LABELS = {
    "COMPLETE": "Supported checks completed",
    "PARTIAL": "Some checks could not be completed",
    "REJECTED": "Input could not be inspected",
}
RECORD_LABELS = {
    "VALID": "Package file list is internally consistent",
    "INVALID": "Package files do not match their declared file list",
    "UNAVAILABLE": "Package file list is unavailable",
    "UNRESOLVED": "Package file list could not be fully checked",
    "NOT_CHECKED": "Package file list was not checked",
}
AI_LABELS = {
    "NOT_CONFIGURED": "AI has not been run for this report",
    "VALIDATED": "AI explanation available",
    "UNAVAILABLE": "AI was unavailable at the last attempt",
    "REJECTED": "The last AI response could not be validated",
}
GROUPS = (
    (
        "code",
        "Published code changes",
        "Changed code and unchanged comparison files. Open a file to see exact hashes and differences.",
    ),
    (
        "executable",
        "Unexpected potentially executable content",
        "Added scripts, startup files or native code deserve inspection. Presence does not prove execution or malicious intent.",
    ),
    (
        "configuration",
        "Dependencies and configuration",
        "Declared package dependencies, entry points and build configuration. No dependency or build tool was executed.",
    ),
    (
        "generated",
        "Common generated packaging files",
        "These paths commonly contain generated package metadata. Their legitimacy is not independently verified.",
    ),
    (
        "source_only",
        "Source-only documentation, tests and build files",
        "These source paths are commonly omitted from published wheels. Still review the evidence; original finding severities and policy decisions are preserved.",
    ),
    (
        "unresolved",
        "Other or unresolved differences",
        "Content that needs context, or unmatched artifact files when source could not be compared.",
    ),
)
_EXECUTABLE = {
    ".py",
    ".pyw",
    ".pyc",
    ".pyo",
    ".pth",
    ".so",
    ".pyd",
    ".dll",
    ".dylib",
    ".exe",
    ".sh",
    ".bat",
    ".cmd",
    ".ps1",
}
_CONFIGURATION = {
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "tox.ini",
    "manifest.in",
    ".coveragerc",
    ".readthedocs.yaml",
    ".readthedocs.yml",
    "makefile",
}
_SOURCE_DIRS = {"docs", "doc", "tests", "test", ".github", ".gitlab", "examples"}

RULE_TRANSLATIONS = {
    "PTH_EXECUTION": {
        "title": "Automatic Startup Directive (.pth script)",
        "what_happened": "A `.pth` startup file containing executable import statements was found in the wheel.",
        "why_it_matters": "When installed in Python site-packages, `.pth` files run code immediately during Python interpreter startup, before any module is explicitly imported by user code.",
        "what_to_check": "Inspect the exact lines in the `.pth` file to verify why startup execution is required, and confirm with the publisher if this behavior is expected.",
    },
    "CUSTOMIZE_MODULE": {
        "title": "Startup Customization Module",
        "what_happened": "A `sitecustomize.py` or `usercustomize.py` module was packaged in the distribution.",
        "why_it_matters": "These modules are automatically imported by Python during site initialization if present in the import path.",
        "what_to_check": "Check the module contents to ensure it does not run unintended initialization hooks.",
    },
    "SUBPROCESS_CAPABILITY": {
        "title": "External Command / Subprocess Execution",
        "what_happened": "Code references system execution functions (such as `subprocess`, `os.system`, or `os.execv`).",
        "why_it_matters": "Invoking external system commands allows Python packages to run shell scripts or binaries outside the Python runtime.",
        "what_to_check": "Review the invoked commands, arguments, and whether inputs to the command are sanitized.",
    },
    "DYNAMIC_EXECUTION": {
        "title": "Dynamic Code Execution (eval / exec)",
        "what_happened": "Code calls dynamic evaluation functions like `eval()`, `exec()`, or `compile()`.",
        "why_it_matters": "Dynamic execution parses and runs code strings at runtime, which can obscure program logic from static review and create injection risks.",
        "what_to_check": "Examine the code string being evaluated to confirm it originates from a trusted internal source and not untrusted input.",
    },
    "DYNAMIC_IMPORT": {
        "title": "Dynamic Module Import",
        "what_happened": "Code uses `__import__()` or `importlib.import_module()` to load modules dynamically.",
        "why_it_matters": "Dynamic imports can be used for optional plugin loading, but can also be used to bypass static dependency scanners.",
        "what_to_check": "Verify which module names can be imported dynamically and ensure they are bounded.",
    },
    "NETWORK_CAPABILITY": {
        "title": "Network Socket / Outbound Connection",
        "what_happened": "Code references networking libraries such as `socket`, `urllib`, `requests`, `httpx`, or `aiohttp`.",
        "why_it_matters": "Outbound network access enables data transmission over the internet, which may be standard for an API client but unexpected for a purely local utility.",
        "what_to_check": "Verify destination URLs, network ports, and when network calls trigger in the package.",
    },
    "NATIVE_BINARY": {
        "title": "Compiled Native Binary or Shared Library",
        "what_happened": "The package contains compiled binaries (such as `.so`, `.dll`, `.dylib`, or ELF/Mach-O headers).",
        "why_it_matters": "Compiled native code cannot be inspected with Python AST scanners and executes directly on the operating system.",
        "what_to_check": "Verify whether binary extensions are expected for this package (e.g. C extensions or accelerators) and check binary build provenance.",
    },
    "BYTECODE": {
        "title": "Precompiled Python Bytecode (.pyc)",
        "what_happened": "Precompiled `.pyc` files are included directly in the distribution.",
        "why_it_matters": "Standard wheel packaging normally ships `.py` source files and lets Python compile `.pyc` locally upon install. Direct `.pyc` files might differ from source.",
        "what_to_check": "Confirm if corresponding `.py` files exist in the wheel and compare their contents.",
    },
    "RECORD_INVALID": {
        "title": "Package Integrity Mismatch (RECORD file)",
        "what_happened": "Files inside the wheel do not match the cryptographic digests or sizes listed in `.dist-info/RECORD`.",
        "why_it_matters": "The RECORD file is the wheel package inventory. A mismatch indicates the package was altered or corrupted after its RECORD manifest was generated.",
        "what_to_check": "Inspect the specific files flagged with hash or size mismatches under Wheel RECORD verification.",
    },
    "RECORD_UNAVAILABLE": {
        "title": "Wheel Integrity Record Absent",
        "what_happened": "No `.dist-info/RECORD` manifest was found in the package.",
        "why_it_matters": "Without a RECORD file, the installer cannot verify that files were delivered intact.",
        "what_to_check": "Check how this wheel was built. Standard build tools (flit, hatch, setuptools, wheel) always generate RECORD.",
    },
    "RECORD_UNRESOLVED": {
        "title": "Wheel Integrity Record Could Not Be Fully Validated",
        "what_happened": "The RECORD file contains unusual structures, unsupported digests, or exceeded parser bounds.",
        "why_it_matters": "Package integrity could not be conclusively verified.",
        "what_to_check": "Review the RECORD verification issues section for details.",
    },
    "ENTRY_POINT_CHANGE": {
        "title": "Entry Point Declaration Change",
        "what_happened": "The command-line tools or plugin hooks declared by this package have changed.",
        "why_it_matters": "Entry points create executable commands in your environment path when installed with pip.",
        "what_to_check": "Inspect the declared script names and the Python functions they point to.",
    },
    "DEPENDENCY_CHANGE": {
        "title": "Package Dependencies Changed",
        "what_happened": "The declared prerequisites in `pyproject.toml` or `METADATA` differ between source and package.",
        "why_it_matters": "Changes in dependencies affect what additional packages pip will download and install.",
        "what_to_check": "Check the added or modified requirements listed under Entry points & dependencies.",
    },
    "CONTENT_DIFFERENCE": {
        "title": "File Content Differs from Source",
        "what_happened": "A published file differs in content from the matching source file in the repository.",
        "why_it_matters": "Published code should match the reviewed source code in git. An unexplained difference could be a packaging artifact or an unauthorized alteration.",
        "what_to_check": "Inspect the unified diff in the File Explorer to understand what lines were modified.",
    },
    "SOURCE_PACKAGING_CONFIGURATION": {
        "title": "Build / Packaging Configuration Difference",
        "what_happened": "Files related to package build configuration differ or were omitted.",
        "why_it_matters": "Build scripts dictate how artifacts are created. Changes may reflect differing build environments.",
        "what_to_check": "Review the configuration diffs in the File Explorer.",
    },
    "PACKAGING_METADATA": {
        "title": "Distribution Metadata File",
        "what_happened": "Generated packaging metadata files (in `.dist-info`) differ from source repository files.",
        "why_it_matters": "Metadata files are normally synthesized by build backends during the packaging process.",
        "what_to_check": "Confirm the metadata matches expected project description, version, and author info.",
    },
}


def translate_rule(rule_name):
    """Translate technical rule identifier to clear plain-language explanation."""
    if rule_name in RULE_TRANSLATIONS:
        return RULE_TRANSLATIONS[rule_name]
    cleaned = rule_name.replace("FIRST_OBSERVED_", "").replace("_", " ").capitalize()
    return {
        "title": cleaned,
        "what_happened": f"A {cleaned.lower()} pattern was detected during static inspection.",
        "why_it_matters": "This syntactic pattern may introduce an unexpected capability or activation surface.",
        "what_to_check": "Review the associated code excerpt and verify with the release publisher.",
    }


def translate_finding(finding, diff=None):
    """Differentiate modified contents, source-only files, artifact-only additions, metadata, and security rules."""
    rule = finding.rule
    severity = finding.severity
    path = diff.path if diff else None

    # 1. True Security Indicators & Integrity checks
    if rule in RULE_TRANSLATIONS and rule not in {
        "CONTENT_DIFFERENCE",
        "SOURCE_PACKAGING_CONFIGURATION",
        "PACKAGING_METADATA",
    }:
        tr = RULE_TRANSLATIONS[rule]
        category = (
            "integrity"
            if rule.startswith("RECORD_")
            else "metadata_change"
            if rule in {"ENTRY_POINT_CHANGE", "DEPENDENCY_CHANGE"}
            else "security_indicator"
        )
        return {
            "id": finding.id,
            "rule": rule,
            "severity": severity,
            "category": category,
            "title": tr["title"],
            "what_happened": tr["what_happened"],
            "why_it_matters": tr["why_it_matters"],
            "what_to_check": tr["what_to_check"],
            "original_explanation": finding.explanation,
            "evidence_ids": finding.evidence_ids,
            "path": path,
            "file_status": diff.status if diff else None,
        }

    # 2. File differences based on actual structured Difference data
    if diff is not None:
        if diff.status == "removed":
            return {
                "id": finding.id,
                "rule": rule,
                "severity": severity,
                "category": "source_only",
                "title": f"Source-Only File Omitted: {diff.path}",
                "what_happened": f"The file {diff.path} is present in the source repository but omitted from the published wheel.",
                "why_it_matters": "Source repositories commonly contain documentation, tests, CI files, and build configurations that are intentionally omitted from wheels to reduce package size.",
                "what_to_check": "Confirm whether this path is documentation, a test suite, or code that should have been packaged.",
                "original_explanation": finding.explanation,
                "evidence_ids": finding.evidence_ids,
                "path": diff.path,
                "file_status": "removed",
            }
        elif diff.status == "added":
            is_meta = diff.classification == "packaging_metadata"
            return {
                "id": finding.id,
                "rule": rule,
                "severity": severity,
                "category": "packaging_metadata" if is_meta else "artifact_only",
                "title": f"Packaging Metadata Generated: {diff.path}"
                if is_meta
                else f"Artifact-Only File Present in Package: {diff.path}",
                "what_happened": f"The metadata file {diff.path} was generated during package build and is present in the wheel."
                if is_meta
                else f"The file {diff.path} is present in the published wheel but was not found in the compared source repository.",
                "why_it_matters": "Distribution metadata files (.dist-info) are standard build outputs synthesized by package tools."
                if is_meta
                else "Artifact-only files may be legitimately compiled assets or generated metadata, but unexpected code files in this category warrant verification.",
                "what_to_check": "Confirm metadata matches expected project details."
                if is_meta
                else "Inspect the added file contents and verify why it was not present in the source repository.",
                "original_explanation": finding.explanation,
                "evidence_ids": finding.evidence_ids,
                "path": diff.path,
                "file_status": "added",
            }
        elif diff.status == "modified":
            return {
                "id": finding.id,
                "rule": rule,
                "severity": severity,
                "category": "modified",
                "title": f"File Content Modified: {diff.path}",
                "what_happened": f"The published file {diff.path} differs in byte content from the matching source file in the repository.",
                "why_it_matters": "Published code should match reviewed source code in git. An unexplained content difference could be a packaging artifact or an unauthorized modification.",
                "what_to_check": "Inspect the unified diff between the source file and published file to review what lines were modified.",
                "original_explanation": finding.explanation,
                "evidence_ids": finding.evidence_ids,
                "path": diff.path,
                "file_status": "modified",
            }

    # Fallback when diff object is not mapped
    tr = translate_rule(rule)
    return {
        "id": finding.id,
        "rule": rule,
        "severity": severity,
        "category": "unresolved",
        "title": tr["title"],
        "what_happened": tr["what_happened"],
        "why_it_matters": tr["why_it_matters"],
        "what_to_check": tr["what_to_check"],
        "original_explanation": finding.explanation,
        "evidence_ids": finding.evidence_ids,
        "path": path,
        "file_status": None,
    }


def partial_coverage_reason(report) -> str | None:
    """Extract specific grounded reasons for PARTIAL inspection status without fabricating explanations."""
    if report.analysis_status != "PARTIAL":
        return None
    reasons = []
    if report.source_resolution == "ARTIFACT_ONLY":
        reasons.append("Source repository could not be compared (ARTIFACT_ONLY)")
    if report.record_status == "UNAVAILABLE":
        reasons.append("Wheel RECORD manifest is absent")
    elif report.record_status == "INVALID":
        issue = (
            report.record_check.issues[0].reason
            if (report.record_check and report.record_check.issues)
            else "digest mismatch"
        )
        reasons.append(f"Wheel RECORD is INVALID ({issue})")
    elif report.record_status == "UNRESOLVED":
        reasons.append("Wheel RECORD could not be fully checked")

    for lim in getattr(report, "limitations", []):
        if (
            "PARTIAL" in lim
            or "limit reached" in lim
            or "parser unavailable" in lim
            or "No in-scope source metadata" in lim
            or "No shared file paths" in lim
        ):
            cleaned = lim.removesuffix(" Investigation is PARTIAL.").removesuffix(
                " Unparsed files make analysis PARTIAL."
            )
            if cleaned not in reasons and not any(r in cleaned for r in reasons):
                reasons.append(cleaned)

    if reasons:
        return "; ".join(reasons)
    return "Some inspection checks could not be completed"


def file_group(file, *, source_available=True):
    """Use path conventions only to organize evidence, never to relabel severity."""
    path = PurePosixPath(file.path)
    parts, name = path.parts or ("",), path.name.lower()
    if not source_available:
        return "unresolved"
    if file.status == "identical":
        return "code"
    if file.status == "added" and path.suffix.lower() in _EXECUTABLE:
        return "executable"
    if file.status == "removed" and (
        parts[0].lower() in _SOURCE_DIRS
        or (
            len(parts) == 1
            and (
                name in _CONFIGURATION
                or name.split(".")[0]
                in {
                    "readme",
                    "license",
                    "licence",
                    "changelog",
                    "changes",
                    "authors",
                    "contributing",
                    "notice",
                }
            )
        )
    ):
        return "source_only"
    if (
        file.classification == "packaging_configuration"
        or (len(parts) == 1 and name in _CONFIGURATION)
        or (
            len(parts) == 2
            and parts[0].endswith(".dist-info")
            and name in {"metadata", "entry_points.txt"}
        )
    ):
        return "configuration"
    if file.classification == "packaging_metadata":
        return "generated"
    if path.suffix.lower() in {".py", ".pyi", ".pyw"}:
        return "code"
    return "unresolved"


def build_executive_summary(report, counts, decision, source_label):
    """Generate Layer 1 5-second plain English executive summary using actual structured finding data."""
    high = counts["high"]
    medium = counts["medium"]
    changed = counts["changed"]
    status = report.analysis_status
    record = report.record_status
    c = report.coverage

    if decision == "BLOCK":
        headline = "Blocked by your configured security rules"
        tone = "danger"
        explanation = f"Your configured security rules blocked this release due to {high} high-priority finding(s) or integrity violations. While static findings do not prove an attack, this release violates your safety threshold. Do not install this package until you have inspected the flagged code below."
    elif record == "INVALID":
        headline = "Wheel integrity record mismatch detected"
        tone = "danger"
        explanation = "The package files do not match the cryptographic digests declared in its internal RECORD inventory. This suggests the artifact was altered, corrupted, or assembled improperly after manifest creation. Review the specific file mismatches before adopting this artifact."
    elif high > 0:
        headline = "Review recommended — high-priority findings detected"
        tone = "danger"
        explanation = f"We identified {high} high-priority finding(s) including unusual execution capabilities or startup hooks. They are not necessarily malicious, but they introduce activation surfaces that warrant careful review. Inspect the code additions below and compare them against an earlier release."
    elif status == "PARTIAL":
        headline = "Review recommended — inspection incomplete"
        tone = "warn"

        reason = partial_coverage_reason(report) or ""

        if "parser byte limit" in reason:
            cause = "One or more Python files were too large to analyze completely."
        elif "parser unavailable" in reason:
            cause = "One or more files could not be fully analyzed."
        elif report.source_resolution == "ARTIFACT_ONLY":
            cause = "The package could not be compared with its source code."
        elif record in ("UNAVAILABLE", "UNRESOLVED"):
            cause = "The package integrity record could not be fully checked."
        else:
            cause = "Some inspection checks could not be completed."

        explanation = (
            f"{cause} Some security indicators may therefore have been missed. "
            "Review the inspection limitations before adopting this release."
        )
    elif medium > 0:
        headline = "Review recommended — differences require inspection"
        tone = "warn"
        if c.modified > 0:
            diff_str = f"{c.modified} modified file(s)"
            if c.added > 0:
                diff_str += f" and {c.added} artifact-only addition(s)"
            if c.removed > 0:
                diff_str += f" ({c.removed} source-only files omitted)"
            explanation = f"We found {diff_str} between the published package and the source used for comparison. Review the modified content diffs before installing this release."
        elif c.added > 0 and c.removed > 0:
            explanation = f"We found {c.added} added file(s) and {c.removed} source-only file(s) omitted from the wheel, with zero modified files. Review the additions and omissions before adopting this release."
        elif c.added > 0:
            explanation = f"We found {c.added} artifact-only file(s) present in the wheel that were not in the compared source, with zero modified files. Review the added files before installing this release."
        elif c.removed > 0:
            explanation = f"We found {c.removed} source-only file(s) omitted from the published package, but zero modified files. Omissions like tests and documentation are standard for wheels; review the omitted paths before adopting this release."
        else:
            explanation = f"We found {medium} difference(s) between the published package and the source used for comparison. They are not necessarily dangerous, but you should review them before installing this release."
    elif report.source_resolution == "ARTIFACT_ONLY":
        headline = "Source comparison unavailable — inspect artifact files directly"
        tone = "info"
        explanation = "No matching source repository could be authenticated from package metadata, so source-to-wheel diffs could not be computed. The wheel passed internal inventory checks, but its contents could not be compared against git. Review the published files directly in the File Explorer."
    else:
        headline = "Supported checks completed — no anomalous additions"
        tone = "success"
        explanation = f"All {report.coverage.compared_files} compared paths match their source baseline without unexpected executable additions or record mismatches. Deterministic static checks passed, though static analysis cannot guarantee absolute safety. You can proceed with installation or archive this report for audit compliance."

    facts = [
        {
            "label": "Findings",
            "value": f"{high + medium} requiring review"
            if (high or medium)
            else "0 requiring review",
            "detail": f"{high} high, {medium} medium · {counts.get('informational', 0)} informational",
            "tone": "danger" if high else "warn" if medium else "neutral",
        },
        {
            "label": "Inspection Coverage",
            "value": "Complete"
            if status == "COMPLETE"
            else "Coverage needs review (PARTIAL)"
            if status == "PARTIAL"
            else status,
            "detail": f"{report.coverage.compared_files} paths compared, {report.coverage.artifact_files} artifact files",
            "tone": "success" if status == "COMPLETE" else "warn",
        },
        {
            "label": "Source Comparison",
            "value": "Matching source found"
            if report.source_resolution == "PYPI_TAG_UNVERIFIED"
            else "Explicit source compared"
            if report.source_resolution == "EXPLICIT_SRC"
            else "Source not compared"
            if report.source_resolution == "ARTIFACT_ONLY"
            else report.source_resolution,
            "detail": source_label,
            "tone": "neutral"
            if report.source_resolution == "ARTIFACT_ONLY"
            else "success",
        },
        {
            "label": "Release Gate",
            "value": decision,
            "detail": DECISION_LABELS.get(decision, decision)
            if report.policy_decision
            else "No policy configured",
            "tone": "danger"
            if decision == "BLOCK"
            else "warn"
            if decision == "REVIEW"
            else "success"
            if decision == "ALLOW"
            else "neutral",
        },
    ]

    return {
        "headline": headline,
        "tone": tone,
        "explanation": explanation,
        "facts": facts,
    }


def present_report(report):
    """Return derived display data and original objects without mutating the report."""
    groups = {
        key: {"id": key, "title": title, "description": description, "files": []}
        for key, title, description in GROUPS
    }
    by_evidence = {}
    for file in report.file_differences:
        key = file_group(
            file, source_available=report.source_resolution != "ARTIFACT_ONLY"
        )
        groups[key]["files"].append(file)
        by_evidence[file.evidence_id] = key
    for group in groups.values():
        group["count"] = len(group["files"])
        group["changed_count"] = sum(
            file.status != "identical" for file in group["files"]
        )
    counts = {
        level.lower(): sum(f.severity == level for f in report.findings)
        for level in ("HIGH", "MEDIUM", "INFORMATIONAL")
    }
    counts.update(
        changed=sum(f.status != "identical" for f in report.file_differences),
        identical=report.coverage.identical,
        packaging_omissions=groups["source_only"]["count"],
        modified=report.coverage.modified,
        added=report.coverage.added,
        removed=report.coverage.removed,
    )
    finding_groups = {}
    for finding in report.findings:
        file_kind = (
            by_evidence.get(finding.evidence_ids[0])
            if len(finding.evidence_ids) == 1
            else None
        )
        if (
            finding.rule
            in {
                "CONTENT_DIFFERENCE",
                "SOURCE_PACKAGING_CONFIGURATION",
                "PACKAGING_METADATA",
            }
            and file_kind
        ):
            key = file_kind
            title, description = groups[key]["title"], groups[key]["description"]
        else:
            key = finding.rule
            title = finding.rule.replace("_", " ").capitalize()
            description = "Static findings from the shared analysis engine. Original severity and supporting evidence are preserved."
        if key not in finding_groups:
            finding_groups[key] = {
                "id": key,
                "title": title,
                "description": description,
                "findings": [],
                "priority": 0,
            }
        item = finding_groups[key]
        item["findings"].append(finding)
        item["priority"] = max(
            item["priority"],
            {"HIGH": 2, "MEDIUM": 1, "INFORMATIONAL": 0}[finding.severity],
        )
    for item in finding_groups.values():
        item["count"] = len(item["findings"])
    # Repetitive omission findings are consolidated, not hidden or downgraded.
    ordered = sorted(
        finding_groups.values(),
        key=lambda item: (
            item["id"] in {"source_only", "generated"},
            -item["priority"],
            item["title"],
        ),
    )
    decision = (
        report.policy_decision.decision if report.policy_decision else "NOT_EVALUATED"
    )
    next_steps = []
    if report.record_status == "INVALID":
        next_steps.append(
            "Review the file-list mismatches before adopting this artifact."
        )
    if counts["high"]:
        next_steps.append(
            "Inspect high-priority findings and the files they reference."
        )
    if report.analysis_status != "COMPLETE":
        next_steps.append(
            "Read the coverage limitations to understand which checks are missing."
        )
    if counts["packaging_omissions"]:
        next_steps.append(
            "Check grouped source-only files; documentation and tests may be intentionally absent from a wheel."
        )
    next_steps.append(
        "Compare an earlier release and verify unexplained changes with the publisher."
    )
    if report.source_resolution == "PYPI_TAG_UNVERIFIED":
        source_label = (
            "Matching source version found; origin not independently verified"
        )
    elif report.source_resolution == "ARTIFACT_ONLY":
        source_label = "Source could not be compared"
    else:
        source_label = "Compared with the source you selected"
    summary = f"{counts['high']} high-priority findings and {counts['medium']} findings requiring review across {counts['changed']} non-identical paths."
    if counts["packaging_omissions"]:
        summary += f" {counts['packaging_omissions']} paths are source-only documentation, tests or build files, grouped for context."
    notable = [
        f
        for item in ordered
        if item["id"] not in {"source_only", "generated"}
        for f in item["findings"]
    ]
    notable.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "INFORMATIONAL": 2}[f.severity])

    # Layer 1: Executive Summary
    executive_summary = build_executive_summary(report, counts, decision, source_label)

    # Layer 2: Understandable Translated Findings with actual structured file difference data
    evidence_to_diff = {d.evidence_id: d for d in report.file_differences}
    translated_findings = []
    for f in report.findings:
        first_ev = f.evidence_ids[0] if f.evidence_ids else None
        diff = evidence_to_diff.get(first_ev)
        translated_findings.append(translate_finding(f, diff))

    return {
        "title": f"{report.package_name} {report.package_version or ''}".strip()
        if report.package_name
        else report.input_artifact,
        "decision_code": decision,
        "decision_label": DECISION_LABELS[decision],
        "coverage_label": COVERAGE_LABELS[report.analysis_status],
        "record_label": RECORD_LABELS[report.record_status],
        "ai_label": AI_LABELS[report.model_status],
        "source_label": source_label,
        "summary": summary,
        "next_steps": next_steps,
        "counts": counts,
        "file_groups": list(groups.values()),
        "finding_groups": ordered,
        "notable_findings": notable[:4],
        "executive_summary": executive_summary,
        "translated_findings": translated_findings,
    }
