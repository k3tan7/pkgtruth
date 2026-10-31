"""The sole deterministic analysis service used by web and CLI."""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from time import monotonic

from .inputs import InputError, MAX_FILE, read_directory, read_zip, safe_path
from .models import Coverage, Difference, Evidence, Finding, Mapping, Report


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_sha(files: dict[str, bytes]) -> str:
    return sha(json.dumps([(name, sha(content)) for name, content in sorted(files.items())], separators=(',', ':')).encode())


def decode(content: bytes | None) -> str | None:
    if content is None or b'\x00' in content:
        return None
    try:
        return content.decode('utf-8')
    except UnicodeDecodeError:
        return None


def analyze(wheel: bytes, source: bytes | Path, *, artifact_name: str = 'local.whl', source_prefix: str = '') -> Report:
    """Compare a wheel against a ZIP or directory; no heuristically guessed mapping."""
    started = monotonic()
    artifact = read_zip(wheel)
    original = read_directory(source) if isinstance(source, Path) else read_zip(source)
    if source_prefix:
        safe_path(source_prefix)
    prefix = source_prefix + '/' if source_prefix else ''
    mapped = {name[len(prefix):]: value for name, value in original.items() if name.startswith(prefix)}
    if not mapped:
        raise InputError('Source prefix matches no files; choose an explicit source root')
    wheel_sha = sha(wheel)
    source_sha = tree_sha(original)
    scan_id = sha(f'local-comparison-1:{wheel_sha}:{source_sha}:{source_prefix}'.encode())[:32]
    differences, evidence, findings = [], [], []
    for path in sorted(artifact.keys() | mapped.keys()):
        if monotonic() - started > 30:
            raise InputError('Analysis time limit exceeded')
        published, reviewed = artifact.get(path), mapped.get(path)
        artifact_hash = sha(published) if published is not None else None
        source_hash = sha(reviewed) if reviewed is not None else None
        status = ('removed' if published is None else 'added' if reviewed is None else
                  'identical' if published == reviewed else 'modified')
        metadata = len(path.split('/')) > 1 and path.split('/')[0].endswith('.dist-info')
        classification = 'identical' if status == 'identical' else 'packaging_metadata' if metadata else 'unexplained'
        evidence_id = 'E-' + sha(f'{path}:{artifact_hash}:{source_hash}'.encode())[:16]
        atext, stext = decode(published), decode(reviewed)
        binary = (published is not None and atext is None) or (reviewed is not None and stext is None)
        # Bound excerpts BEFORE difflib to avoid pathological CPU/memory input.
        truncated = any(text is not None and len(text) > 2048 for text in (atext, stext))
        patch = ''
        if status != 'identical' and not binary:
            patch = ''.join(difflib.unified_diff((stext or '')[:2048].splitlines(True), (atext or '')[:2048].splitlines(True), fromfile='source/' + path, tofile='wheel/' + path))
            if len(patch) > 8192:
                patch = patch[:8192]
                truncated = True
        differences.append(Difference(path=path, source_path=prefix + path if reviewed is not None else None,
            status=status, artifact_sha256=artifact_hash, source_sha256=source_hash,
            classification=classification, evidence_id=evidence_id, binary=binary,
            diff=patch, excerpt_truncated=truncated))
        evidence.append(Evidence(id=evidence_id, path=path,
            description=f'{status}: SHA-256 comparison against the explicitly mapped source',
            source_excerpt=stext[:2048] if stext is not None else None,
            artifact_excerpt=atext[:2048] if atext is not None else None))
        if status != 'identical':
            findings.append(Finding(id='F-' + evidence_id[2:], rule='PACKAGING_METADATA' if metadata else 'CONTENT_DIFFERENCE',
                severity='INFORMATIONAL' if metadata else 'MEDIUM', evidence_ids=[evidence_id],
                explanation=(f'{path}: {status}. Wheel packaging metadata can be generated; its legitimacy is not verified.' if metadata else
                             f'{path}: {status} relative to the selected source root. Review the difference; it does not establish malicious behavior.')))
    overlap = sum(d.status in ('modified', 'identical') for d in differences)
    partial = not overlap or any(name.split('/')[0].endswith('.data') for name in artifact)
    limitations = [
        'Local user-selected source is not authenticated and is not tied to a repository commit.',
        'Static byte comparison only: no target code was executed. Matching files do not prove safety.',
        'RECORD, provenance, startup hooks, AST capabilities, AI, history and release policies are not checked in milestone 1.',
        'Packaging metadata is identified by path only; generated content is not verified.',
        'Source-prefix selection defines scope. Files outside that prefix are counted but excluded.',
        'Text excerpts and diffs are bounded previews; SHA-256 hashes cover full inspected contents.',
    ]
    if not overlap:
        limitations.append('No shared file paths: mapping could be wrong. Investigation is PARTIAL.')
    if any(name.split('/')[0].endswith('.data') for name in artifact):
        limitations.append('Wheel .data installation relocation is not mapped. Investigation is PARTIAL.')
    counts = {kind: sum(d.status == kind for d in differences) for kind in ('added', 'removed', 'modified', 'identical')}
    return Report(scan_id=scan_id, analysis_status='PARTIAL' if partial else 'COMPLETE',
        input_artifact=Path(artifact_name).name[:256], artifact_sha256=wheel_sha, source_tree_sha256=source_sha,
        mappings=[Mapping(source_prefix=source_prefix)], file_differences=differences,
        coverage=Coverage(artifact_files=len(artifact), source_files=len(mapped), compared_files=len(differences),
            excluded_source_files=len(original)-len(mapped), byte_limit_per_file=MAX_FILE, **counts),
        findings=findings, evidence=evidence, limitations=limitations)
